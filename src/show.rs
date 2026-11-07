//! `cynet show`: read-only status over a Unix socket or a Windows named pipe.
//!
//! The text has the colors of `wg show`. Only the client knows whether it writes to a terminal, so
//! the daemon always includes them, and the client removes them otherwise, as `wg` does.

#[cfg(test)]
mod tests;

use std::{
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
        COST_INFINITY, METRIC_INFINITY,
        driver::{self, Input},
        snapshot::{NeighbourSnapshot, PrefixStatus, RouteSnapshot, Snapshot},
    },
    config::encode_key,
};

/// The directory of the sockets, one per interface.
#[cfg(unix)]
const SOCKET_DIR: &str = "/run/cynet";
#[cfg(windows)]
const SOCKET_DIR: &str = r"\\.\pipe\";

/// How long to wait for a daemon to reply, and for a client to ask.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// What a client sends for verbose status. Plain status uses EOF on Unix or a newline on Windows.
const VERBOSE_REQUEST: &[u8] = b"verbose\n";

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
fn short_key(key: &PublicKey) -> String {
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
}

impl<T: DeviceTransports> Status<T> {
    /// Returns the status as text, with colors.
    pub async fn text(&self, name: &str, verbose: bool) -> eyre::Result<String> {
        let snapshot = driver::snapshot(&self.inputs)
            .await
            .wrap_err("the Babel driver has stopped")?;

        let listen_port = self.device.read(async |device| device.listen_port()).await;
        let peers = self.device.peers().await;

        Ok(format_status(
            name,
            &self.public_key,
            listen_port,
            self.started.elapsed(),
            &peers,
            &snapshot,
            verbose,
        ))
    }
}

/// Formats a node's peers and routes. With `verbose`, this includes what Babel bases its choice of
/// routes on.
fn format_status(
    name: &str,
    public_key: &PublicKey,
    listen_port: u16,
    uptime: Duration,
    peers: &[PeerStats],
    snapshot: &Snapshot<PublicKey>,
    verbose: bool,
) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "{GREEN}{BOLD}interface{RESET}: {GREEN}{name}{RESET}");
    let _ = writeln!(
        out,
        "  {BOLD}public key{RESET}: {}",
        encode_key(public_key.as_bytes())
    );
    let _ = writeln!(out, "  {BOLD}listening port{RESET}: {listen_port}");
    if verbose {
        let _ = writeln!(
            out,
            "  {BOLD}router-id{RESET}: {:016x}, {BOLD}seqno{RESET}: {}",
            snapshot.router_id.get(),
            snapshot.seqno.get()
        );
    }
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
            format_neighbour(&mut out, neighbour, verbose);
        }
    }

    let _ = writeln!(out, "\n{MAGENTA}{BOLD}routes{RESET}:");
    let width = (snapshot.prefixes.iter())
        .map(|entry| entry.prefix.to_string().len())
        .max()
        .unwrap_or(0);
    for entry in &snapshot.prefixes {
        let (addr, prefix_len) = (entry.prefix.addr(), entry.prefix.prefix_len());
        let prefix = format!("{addr}{CYAN}/{RESET}{prefix_len}");
        // Colors take up no space, so they can't count towards the width of the column.
        let prefix_padding = width - entry.prefix.to_string().len();
        // A line goes in the column beside the prefix, or `below` it, indented from it.
        let mut first = true;
        let mut line = |out: &mut String, below: bool, text: String| {
            if below {
                if first {
                    let _ = writeln!(out, "  {prefix}");
                }
                let _ = writeln!(out, "    {text}");
            } else {
                let (label, padding) = if first {
                    (prefix.as_str(), prefix_padding)
                } else {
                    ("", width)
                };
                let _ = writeln!(out, "  {label}{:padding$}  {text}", "");
            }
            first = false;
        };

        let selected = match entry.status {
            PrefixStatus::Injected => {
                line(&mut out, false, format!("{GREEN}injected{RESET}"));
                None
            }
            PrefixStatus::Selected(key) => Some(key),
            PrefixStatus::Held => {
                line(&mut out, false, format!("{RED}unreachable (held){RESET}"));
                None
            }
            PrefixStatus::None => {
                line(&mut out, false, format!("{RED}no route selected{RESET}"));
                None
            }
        };

        // The selected route first, then the others.
        for route in entry.routes.iter().filter(|r| Some(r.via) == selected) {
            let mut text = format!(
                "{BOLD}via{RESET} {YELLOW}{}{RESET}, {BOLD}metric{RESET} {}",
                short_key(&route.via),
                format_metric(route.metric),
            );
            if verbose {
                text.push_str(&route_details(route, BOLD, RESET));
            }
            line(&mut out, verbose, text);
        }
        for route in entry.routes.iter().filter(|r| Some(r.via) != selected) {
            let mut text = format!(
                "{DIM}not via {}, metric {}",
                short_key(&route.via),
                format_metric(route.metric),
            );
            if verbose {
                text.push_str(&route_details(route, "", ""));
                if route.metric != METRIC_INFINITY {
                    text.push_str(if route.feasible {
                        ", feasible"
                    } else {
                        ", unfeasible"
                    });
                }
            }
            text.push_str(RESET);
            line(&mut out, verbose, text);
        }
    }

    out
}

/// Writes what Babel knows of a peer's link.
fn format_neighbour(out: &mut String, neighbour: &NeighbourSnapshot<PublicKey>, verbose: bool) {
    let cost = if neighbour.cost == COST_INFINITY {
        format!("{RED}infinite{RESET}")
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

    if verbose {
        let _ = writeln!(
            out,
            "  {BOLD}rxcost{RESET}: {}, {BOLD}txcost{RESET}: {}, {BOLD}rtt penalty{RESET}: {}",
            format_metric(neighbour.rxcost),
            format_metric(neighbour.txcost),
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
}

/// Returns the part of a route's line, after its metric, that only the verbose status has: the
/// smoothed metric and the source. `bold` and `reset` set off its labels, and are empty in dimmed
/// text, which a reset would end early.
fn route_details(route: &RouteSnapshot<PublicKey>, bold: &str, reset: &str) -> String {
    format!(
        " ({}), {bold}rid{reset} {:016x}, {bold}seqno{reset} {}",
        format_metric(route.smoothed_metric),
        route.router_id.get(),
        route.seqno.get()
    )
}

fn format_metric(metric: u16) -> String {
    if metric == METRIC_INFINITY {
        "infinite".to_owned()
    } else {
        metric.to_string()
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
                let verbose = read_request(&mut stream).await;
                let text = match status.text(&name, verbose).await {
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
                    let verbose = read_request(&mut server).await;
                    let text = match status.text(&name, verbose).await {
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

/// Reads whether a client asks for the verbose status. One that says anything else, or nothing for
/// too long, gets the plain one.
async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> bool {
    let mut request = Vec::with_capacity(VERBOSE_REQUEST.len());
    let read = async {
        while request.len() < VERBOSE_REQUEST.len() {
            match stream.read_u8().await {
                Ok(byte) => {
                    request.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error),
            }
        }
        Ok::<_, io::Error>(())
    };
    matches!(timeout(REPLY_TIMEOUT, read).await, Ok(Ok(_))) && request == VERBOSE_REQUEST
}

/// Reads one daemon's status, or returns `None` if it is not running: nothing is listening on a
/// socket that a crash left behind, and a socket can be gone by the time it is read.
#[cfg(unix)]
async fn read_status(path: &Path, verbose: bool) -> eyre::Result<Option<String>> {
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
        if verbose {
            stream.write_all(VERBOSE_REQUEST).await?;
        }
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
async fn read_status(path: &Path, verbose: bool) -> eyre::Result<Option<String>> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    let exchange = async {
        let mut stream = loop {
            match ClientOptions::new().open(path) {
                Ok(stream) => break stream,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        };
        stream
            .write_all(if verbose { VERBOSE_REQUEST } else { b"\n" })
            .await?;
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

/// Prints the status of the named interface, or of every running one, with `verbose` adding what
/// Babel bases its choice of routes on.
pub async fn show(name: Option<&str>, verbose: bool) -> eyre::Result<()> {
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
        let Some(text) = read_status(&path, verbose).await? else {
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
