//! `cynet show`: the daemon's status, as text, over a Unix socket or a Windows named pipe.
//! A client can't ask for anything but the status, so the socket can't change anything.
//!
//! The text has the colors of `wg show`. Only the client knows whether it writes to a terminal, so
//! the daemon always includes them, and the client removes them otherwise, as `wg` does.

#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    fmt::Write as _,
    fs,
    io::{self, ErrorKind, IsTerminal},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use eyre::{Context, ContextCompat, bail};
use gotatun::{
    device::{Device, DeviceTransports, configure::PeerStats},
    x25519::PublicKey,
};
use ipnet::IpNet;
use parking_lot::Mutex;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, timeout},
};

use crate::{
    babel::{
        COST_INFINITY,
        driver::{self, Input},
        snapshot::{NeighbourSnapshot, PrefixStatus, RouteSnapshot, Snapshot},
    },
    config::encode_key,
    conflicts::{ConflictLog, Ongoing},
};

/// The directory of the sockets, one per interface.
#[cfg(unix)]
const SOCKET_DIR: &str = "/run/cynet";
#[cfg(windows)]
const SOCKET_DIR: &str = r"\\.\pipe\";

/// How long to wait for a daemon to reply, and for a client to ask.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// The most that is read of what a client sends, which is ignored, as there is only one status to
/// give. Older clients send `verbose\n`, to ask for what that status now is.
const MAX_REQUEST: u64 = 64;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";

fn socket_path(name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        Path::new(SOCKET_DIR).join(format!("{name}.sock"))
    }
    #[cfg(windows)]
    {
        Path::new(SOCKET_DIR).join(format!("cynet-{name}.sock"))
    }
}

/// Returns the first few characters of a public key, enough to tell peers apart.
pub fn short_key(key: &PublicKey) -> String {
    let mut key = encode_key(key.as_bytes());
    key.truncate(5);
    key.push('…');
    key
}

/// A handle for getting a node's status.
pub struct Status<T: DeviceTransports> {
    pub(crate) device: Arc<Device<T>>,
    pub(crate) inputs: mpsc::Sender<Input<PublicKey>>,
    pub(crate) public_key: PublicKey,
    pub(crate) started: Instant,
    pub(crate) conflicts: Arc<Mutex<ConflictLog>>,
}

impl<T: DeviceTransports> Status<T> {
    /// Returns the status as text, with colors.
    pub async fn text(&self, name: &str) -> eyre::Result<String> {
        let snapshot = driver::snapshot(&self.inputs)
            .await
            .wrap_err("the Babel driver has stopped")?;

        let listen_port = self.device.read(async |device| device.listen_port()).await;
        let peers = self.device.peers().await;

        let now = driver::now();
        let conflicts = self.conflicts.lock().ongoing(now);
        let conflicted: HashSet<_> = conflicts.iter().map(|ongoing| ongoing.key.prefix).collect();

        let mut text = format_status(
            name,
            &self.public_key,
            listen_port,
            self.started.elapsed(),
            &peers,
            &snapshot,
            &conflicted,
        );
        text.push_str(&format_conflicts(&conflicts, now));
        Ok(text)
    }
}

/// Formats a node's peers and routes, with what Babel bases its choice of routes on, marking the
/// prefixes in `conflicted`, which have conflicts that go on (see [`format_conflicts`]).
fn format_status(
    name: &str,
    public_key: &PublicKey,
    listen_port: u16,
    uptime: Duration,
    peers: &[PeerStats],
    snapshot: &Snapshot<PublicKey>,
    conflicted: &HashSet<IpNet>,
) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "{GREEN}{BOLD}interface{RESET}: {GREEN}{name}{RESET}");
    let _ = writeln!(
        out,
        "  {BOLD}public key{RESET}: {}",
        encode_key(public_key.as_bytes())
    );
    let _ = writeln!(out, "  {BOLD}listening port{RESET}: {listen_port}");
    let _ = writeln!(
        out,
        "  {BOLD}router-id{RESET}: {:016x}, {BOLD}seqno{RESET}: {}",
        snapshot.router_id.get(),
        snapshot.seqno.get()
    );
    let _ = writeln!(out, "  {BOLD}uptime{RESET}: {}", format_age(uptime));

    let mut peers: Vec<_> = peers.iter().collect();
    peers.sort_unstable_by_key(|peer| encode_key(peer.peer.public_key.as_bytes()));

    for peer in peers {
        let key = &peer.peer.public_key;
        let _ = writeln!(
            out,
            "\n{YELLOW}{BOLD}peer{RESET}: {YELLOW}{}{RESET}",
            encode_key(key.as_bytes())
        );
        if let Some(endpoint) = peer.peer.endpoint {
            let _ = writeln!(out, "  {BOLD}endpoint{RESET}: {endpoint}");
        }
        match peer.stats.last_handshake {
            Some(age) => {
                let _ = writeln!(
                    out,
                    "  {BOLD}latest handshake{RESET}: {} ago",
                    format_age(age)
                );
            }
            None => {
                let _ = writeln!(out, "  {BOLD}latest handshake{RESET}: none");
            }
        }
        let _ = writeln!(
            out,
            "  {BOLD}transfer{RESET}: {} received, {} sent",
            format_bytes(peer.stats.rx_bytes),
            format_bytes(peer.stats.tx_bytes)
        );
        if let Some(neighbour) = snapshot.neighbours.iter().find(|n| n.key == *key) {
            format_neighbour(&mut out, neighbour);
        }
    }

    let _ = writeln!(out, "\n{CYAN}{BOLD}routes{RESET}:");
    let width = (snapshot.prefixes.iter())
        .map(|entry| entry.prefix.to_string().len())
        .max()
        .unwrap_or(0);
    for entry in &snapshot.prefixes {
        let prefix = format_prefix(entry.prefix);
        // Colors take up no space, so they can't count towards the width of the column.
        let prefix_padding = width - entry.prefix.to_string().len();
        // Beside the prefix go its status, if it has one other than a selected route, whether it is
        // nonexclusive, which a prefix that this node originates as nonexclusive, or whose routes
        // are all nonexclusive, says, and whether it has conflicts that go on, last.
        let mut beside = Vec::new();
        let selected = match entry.status {
            PrefixStatus::Injected { .. } => {
                beside.push(format!("{GREEN}injected{RESET}"));
                None
            }
            PrefixStatus::Selected(key) => Some(key),
            PrefixStatus::Held => {
                beside.push(format!("{RED}unreachable (held){RESET}"));
                None
            }
            PrefixStatus::None => {
                beside.push(format!("{RED}no route selected{RESET}"));
                None
            }
        };
        let nonexclusive = match entry.status {
            PrefixStatus::Injected { nonexclusive } => nonexclusive,
            _ => !entry.routes.is_empty() && entry.routes.iter().all(|route| route.nonexclusive),
        };
        if nonexclusive {
            beside.push(format!("{MAGENTA}nonexclusive{RESET}"));
        }
        if conflicted.contains(&entry.prefix) {
            beside.push(format!("{RED}conflicted{RESET}"));
        }

        // That goes in a column beside the prefix, and the routes below it, each on a line of its
        // own, two spaces further in.
        if beside.is_empty() {
            let _ = writeln!(out, "  {prefix}");
        } else {
            let beside = beside.join(", ");
            let _ = writeln!(out, "  {prefix}{:prefix_padding$}  {beside}", "");
        }

        // The selected route first, then the others.
        for route in entry.routes.iter().filter(|r| Some(r.via) == selected) {
            let _ = writeln!(
                out,
                "    {BOLD}via{RESET} {YELLOW}{}{RESET}, {BOLD}metric{RESET} {}{}",
                short_key(&route.via),
                format_cost_metric(route.metric),
                route_details(route, BOLD, RESET),
            );
        }
        for route in entry.routes.iter().filter(|r| Some(r.via) != selected) {
            let feasibility = if route.feasible {
                ", feasible"
            } else {
                ", unfeasible"
            };
            let _ = writeln!(
                out,
                "    {DIM}not via {}, metric {}{}{feasibility}{RESET}",
                short_key(&route.via),
                format_cost_metric(route.metric),
                route_details(route, "", ""),
            );
        }
    }

    out
}

/// Formats the conflicts over prefixes that go on, each with how many hops away the routes meet
/// and how long it has gone on, for the end of the status. With none, there is nothing to show. A
/// line for each prefix heads its conflicts, which go on lines of their own, two spaces further in,
/// as routes do.
///
/// Each names the neighbour that the rejected updates or the alerts come from, which is the next
/// node to look at when tracing a conflict (see
/// [Duplicate addresses](crate::babel::State#duplicate-addresses)).
fn format_conflicts(conflicts: &[Ongoing], now: std::time::Instant) -> String {
    let mut out = String::new();
    if conflicts.is_empty() {
        return out;
    }

    let _ = writeln!(out, "\n{RED}{BOLD}conflicts{RESET}:");
    let mut last = None;
    for Ongoing { key, hops, since } in conflicts {
        // Conflicts come in order of prefix, which is shown once for those that share it.
        if last != Some(key.prefix) {
            let _ = writeln!(out, "  {}", format_prefix(key.prefix));
            last = Some(key.prefix);
        }

        let from = format!("{YELLOW}{}{RESET}", short_key(&key.from));
        let age = now.saturating_duration_since(*since);
        let _ = writeln!(
            out,
            "    {}, for {}",
            key.describe(*hops, &from),
            format_age(age)
        );
    }
    out
}

/// Formats a prefix, with its slash in color.
fn format_prefix(prefix: IpNet) -> String {
    format!("{}{CYAN}/{RESET}{}", prefix.addr(), prefix.prefix_len())
}

/// Writes what Babel knows of a peer's link.
fn format_neighbour(out: &mut String, neighbour: &NeighbourSnapshot<PublicKey>) {
    let cost = if neighbour.cost == COST_INFINITY {
        format!("{RED}infinity{RESET}")
    } else {
        neighbour.cost.to_string()
    };
    let _ = write!(out, "  {BOLD}link cost{RESET}: {cost}");
    if let Some(rtt) = neighbour.rtt {
        let _ = write!(
            out,
            ", {BOLD}rtt{RESET}: {:.1} {CYAN}ms{RESET}",
            rtt.as_secs_f64() * 1000.0
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "  {BOLD}rxcost{RESET}: {}, {BOLD}txcost{RESET}: {}, {BOLD}rtt penalty{RESET}: {}",
        format_cost_metric(neighbour.rxcost),
        format_cost_metric(neighbour.txcost),
        neighbour.rtt_penalty
    );
    let _ = writeln!(
        out,
        "  {BOLD}hello history{RESET}: {:016b} (latest last)",
        neighbour.hello_history
    );
    if neighbour.in_startup {
        let _ = writeln!(
            out,
            "  {BOLD}startup{RESET}: waiting for an acknowledgement"
        );
    }
}

/// Returns the part of a route's line after its metric: the smoothed metric and the source. `bold`
/// and `reset` set off its labels, and are empty in dimmed text, which a reset would end early.
fn route_details(route: &RouteSnapshot<PublicKey>, bold: &str, reset: &str) -> String {
    format!(
        " ({}), {bold}rid{reset} {:016x}, {bold}seqno{reset} {}",
        route.smoothed_metric,
        route.router_id.get(),
        route.seqno.get()
    )
}

fn format_cost_metric(value: u16) -> String {
    if value == u16::MAX {
        "infinity".to_owned()
    } else {
        value.to_string()
    }
}

/// Returns an age as `wg` writes it, in every unit that isn't zero (`pretty_time` in its `show.c`),
/// but for an age of zero, which is 0 seconds here rather than `wg`'s `Now`.
fn format_age(age: Duration) -> String {
    const UNITS: [(&str, u64); 5] = [
        ("year", 365 * 86_400),
        ("day", 86_400),
        ("hour", 3_600),
        ("minute", 60),
        ("second", 1),
    ];

    let mut left = age.as_secs();
    let mut parts = Vec::new();
    for (unit, size) in UNITS {
        let n = left / size;
        left %= size;
        if n > 0 {
            let plural = if n == 1 { "" } else { "s" };
            parts.push(format!("{n} {CYAN}{unit}{plural}{RESET}"));
        }
    }
    if parts.is_empty() {
        return format!("0 {CYAN}seconds{RESET}");
    }
    parts.join(", ")
}

fn format_bytes(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {CYAN}B{RESET}")
    } else {
        format!("{value:.2} {CYAN}{}{RESET}", UNITS[unit])
    }
}

/// Removes the colors from a status.
pub fn strip_colors(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once("\x1b[") {
        out.push_str(before);
        // A sequence ends with a letter.
        rest = match after.find(|c: char| c.is_ascii_alphabetic()) {
            Some(end) => &after[end + 1..],
            None => "",
        };
    }
    out.push_str(rest);
    out
}

/// Serves a node's status for as long as it lives.
pub struct ShowServer {
    #[cfg(unix)]
    path: PathBuf,
    task: JoinHandle<()>,
}

impl ShowServer {
    /// Starts serving on the interface's local status endpoint.
    #[cfg(unix)]
    pub fn start<T: DeviceTransports>(name: &str, status: Status<T>) -> eyre::Result<Self> {
        fs::create_dir_all(SOCKET_DIR)
            .wrap_err_with(|| format!("failed to create {SOCKET_DIR}"))?;

        let path = socket_path(name);
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path)
            .wrap_err_with(|| format!("failed to bind {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .wrap_err_with(|| format!("failed to restrict {}", path.display()))?;

        let name = name.to_owned();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                read_request(&mut stream).await;
                let text = match status.text(&name).await {
                    Ok(text) => text,
                    Err(error) => format!("error: {error:#}\n"),
                };
                // A client that doesn't read gets nothing more than this one try.
                let write = async {
                    let _ = stream.write_all(text.as_bytes()).await;
                    let _ = stream.shutdown().await;
                };
                let _ = timeout(REPLY_TIMEOUT, write).await;
            }
        });

        Ok(Self { path, task })
    }

    /// Starts a local-only Windows named pipe, refusing another server for the same interface.
    #[cfg(windows)]
    pub fn start<T: DeviceTransports>(name: &str, status: Status<T>) -> eyre::Result<Self> {
        let path = socket_path(name);
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&path)
            .wrap_err_with(|| format!("failed to create {}", path.display()))?;
        let name = name.to_owned();
        let task = tokio::spawn(async move {
            loop {
                if let Err(error) = server.connect().await {
                    tracing::warn!("status pipe connection failed: {error}");
                    break;
                }
                // Keep a listening instance alive while the connected client reads its reply.
                let next = match ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&path)
                {
                    Ok(next) => next,
                    Err(error) => {
                        tracing::warn!("failed to create the next status pipe: {error}");
                        break;
                    }
                };
                let exchange = async {
                    read_request(&mut server).await;
                    let text = match status.text(&name).await {
                        Ok(text) => text,
                        Err(error) => format!("error: {error:#}\n"),
                    };
                    // Named pipes have no half-close: frame the reply and await acknowledgement
                    // before closing so Windows cannot discard data the client hasn't read yet.
                    let size = u32::try_from(text.len()).map_err(io::Error::other)?;
                    server.write_u32_le(size).await?;
                    server.write_all(text.as_bytes()).await?;
                    server.read_u8().await?;
                    Ok::<_, io::Error>(())
                };
                let _ = timeout(REPLY_TIMEOUT, exchange).await;
                server = next;
            }
        });
        Ok(Self { task })
    }
}

impl Drop for ShowServer {
    fn drop(&mut self) {
        self.task.abort();
        #[cfg(unix)]
        let _ = fs::remove_file(&self.path);
    }
}

/// Waits for a client to close its side, which it does once it has asked, or to say too much, or
/// for too long, and ignores what it says (see [`MAX_REQUEST`]). Reading it first saves an older
/// client from losing the status: closing a socket with what the peer sent still unread can make
/// the peer's next read fail with a reset. Windows named pipes have no half-close, so a newline
/// also ends their request.
async fn read_request(stream: &mut (impl AsyncRead + Unpin)) {
    let read = async {
        let mut request = [0; MAX_REQUEST as usize];
        let mut received = 0;
        while received < request.len() {
            let count = stream.read(&mut request[received..]).await?;
            if count == 0 {
                break;
            }
            received += count;
            #[cfg(windows)]
            if request[..received].contains(&b'\n') {
                break;
            }
        }
        Ok::<_, io::Error>(())
    };
    let _ = timeout(REPLY_TIMEOUT, read).await;
}

/// Reads one daemon's status, or returns `None` if it is not running: nothing is listening on a
/// socket that a crash left behind, and a socket can be gone by the time it is read.
#[cfg(unix)]
async fn read_status(path: &Path) -> eyre::Result<Option<String>> {
    let exchange = async {
        let mut stream = match UnixStream::connect(path).await {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::NotFound
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        // This tells the daemon that there is nothing more to wait for.
        stream.shutdown().await?;

        let mut text = String::new();
        stream.read_to_string(&mut text).await?;
        Ok(Some(text))
    };
    timeout(REPLY_TIMEOUT, exchange)
        .await
        .wrap_err_with(|| format!("timed out reading {}", path.display()))?
        .wrap_err_with(|| format!("failed to read {}", path.display()))
}

#[cfg(windows)]
async fn read_status(path: &Path) -> eyre::Result<Option<String>> {
    use ::windows::Win32::Foundation::ERROR_PIPE_BUSY;
    let exchange = async {
        let mut stream = loop {
            match ClientOptions::new().open(path) {
                Ok(stream) => break stream,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        };
        stream.write_all(b"\n").await?;
        let size = stream.read_u32_le().await?;
        let mut text = String::new();
        let read = (&mut stream)
            .take(u64::from(size))
            .read_to_string(&mut text)
            .await?;
        if read != size as usize {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "incomplete status reply",
            ));
        }
        stream.write_u8(0).await?;
        Ok(Some(text))
    };
    timeout(REPLY_TIMEOUT, exchange)
        .await
        .wrap_err_with(|| format!("timed out reading {}", path.display()))?
        .wrap_err_with(|| format!("failed to read {}", path.display()))
}

/// Returns the sockets of the running daemons, in order of name.
fn socket_paths() -> eyre::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(SOCKET_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).wrap_err_with(|| format!("failed to read {SOCKET_DIR}"));
        }
    };
    let mut paths: Vec<_> = (entries.flatten())
        .map(|entry| entry.path())
        .filter(|path| {
            let socket = path.extension().is_some_and(|ext| ext == "sock");
            #[cfg(windows)]
            let socket = socket
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("cynet-"));
            socket
        })
        .collect();
    paths.sort_unstable();
    Ok(paths)
}

/// Prints the status of the named interface, or of every running one.
pub async fn show(name: Option<&str>) -> eyre::Result<()> {
    if let Some(name) = name {
        eyre::ensure!(
            crate::config::valid_interface_name(name),
            "invalid interface name {name:?}"
        );
    }
    let paths = match name {
        Some(name) => vec![socket_path(name)],
        None => socket_paths()?,
    };

    let colors = io::stdout().is_terminal();
    let mut first = true;
    for path in paths {
        let Some(text) = read_status(&path).await? else {
            if let Some(name) = name {
                bail!("{name} is not running");
            }
            continue;
        };
        if !first {
            println!();
        }
        first = false;
        if colors {
            print!("{text}");
        } else {
            print!("{}", strip_colors(&text));
        }
    }
    Ok(())
}
