//! The configuration file, in TOML. Its keys are grouped by what they act on: the kernel's
//! interface, the WireGuard tunnels, and the routing that cynet adds. A key that means the same as
//! in `wg` or `wg-quick` has the same name.
//!
//! ```toml
//! [interface]                # optional, as is each key in it
//! name = "cyn0"              # default: the file's stem, as wg-quick does
//! mtu = 1400                 # default: 1400
//! addresses = ["10.42.0.1", "fd42::1", "nonexclusive,10.42.0.9"]
//!
//! [wireguard]
//! private_key = "base64"     # or private_key_file = "/etc/cynet/key"
//! listen_port = 51820        # default: random
//! reresolve_secs = 60        # seconds between endpoint lookups, default 60, at least 15; 0 disables
//!
//! [routing]
//! mesh = ["10.42.0.0/16", "fd42::/48", "192.168.0.0/16"]
//! attached = ["192.168.7.0/24", "nonexclusive,0.0.0.0/0"]   # directly attached networks
//! kernel_routes = true       # default: true; main-table routes for mesh, see below
//!
//! [[peer]]
//! public_key = "base64"
//! preshared_key = "base64"            # optional
//! endpoint = "vpn.example.com:51820"  # optional
//! peer_name = "peer1"                 # optional
//! ```
//!
//! A prefix of `mesh` only gets a kernel route if this node has an address or an attached network
//! of its family (see [`Config::kernel_route_prefixes`]).
//!
//! A `nonexclusive,` prefix on an entry of `addresses` or `attached` lets other nodes originate it,
//! or prefixes inside it, too
//! (see [`Config::nonexclusive`]).

#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    fmt::Display,
    fs, io,
    net::{IpAddr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use base64::{Engine, prelude::BASE64_STANDARD};
use eyre::{Context, bail, ensure, eyre};
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de};

use crate::{
    babel::{Params, martian_prefix},
    router::local_prefixes,
};

/// The seconds between endpoint lookups, unless configured.
const DEFAULT_RERESOLVE_SECS: u64 = 60;

/// The fewest seconds allowed between endpoint lookups. A peer that sent nothing since the last
/// lookup counts as quiet, which can replace its endpoint, so a live peer must always have been
/// heard from by then. Its Hellos come every 4 s, and 15 s without a reply is when WireGuard itself
/// starts another handshake.
const MIN_RERESOLVE_SECS: u64 = 15;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    interface: RawInterface,
    wireguard: RawWireguard,
    routing: RawRouting,
    #[serde(default, rename = "peer")]
    peers: Vec<RawPeer>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterface {
    name: Option<String>,
    mtu: Option<u16>,
    #[serde(default)]
    addresses: Vec<Marked<IpAddr>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWireguard {
    private_key: Option<String>,
    private_key_file: Option<PathBuf>,
    listen_port: Option<u16>,
    reresolve_secs: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouting {
    mesh: Vec<IpNet>,
    #[serde(default)]
    attached: Vec<Marked<IpNet>>,
    kernel_routes: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: Option<String>,
    peer_name: Option<String>,
}

/// An entry of `addresses` or `attached`, which a `nonexclusive,` prefix marks as nonexclusive.
struct Marked<T> {
    value: T,
    nonexclusive: bool,
}

impl<T: Copy> Marked<T> {
    /// Splits entries into the values of all of them, and those of the ones marked nonexclusive.
    fn split(entries: Vec<Self>) -> (Vec<T>, Vec<T>) {
        let marked = (entries.iter().filter(|e| e.nonexclusive))
            .map(|e| e.value)
            .collect();
        (entries.into_iter().map(|e| e.value).collect(), marked)
    }
}

impl<'de, T> Deserialize<'de> for Marked<T>
where
    T: FromStr,
    T::Err: Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let (text, nonexclusive) = match text.strip_prefix("nonexclusive,") {
            Some(rest) => (rest, true),
            None => (text.as_str(), false),
        };
        let value = text.parse().map_err(de::Error::custom)?;
        Ok(Self {
            value,
            nonexclusive,
        })
    }
}

/// Where a peer is reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// A fixed address.
    Address(SocketAddr),
    /// A hostname, looked up now and then.
    Host {
        /// The hostname.
        host: String,
        /// The port.
        port: u16,
    },
}

/// A peer in the configuration.
pub struct PeerConfig {
    /// Its public key.
    pub public_key: PublicKey,
    /// A preshared key, if any.
    pub preshared_key: Option<[u8; 32]>,
    /// Where it is reached, if known.
    pub endpoint: Option<Endpoint>,
    /// The name used to identify this peer.
    pub peer_name: Option<String>,
}

/// A validated configuration.
pub struct Config {
    /// The name of the interface.
    pub name: String,
    /// The MTU of the interface, in octets.
    pub mtu: u16,
    /// The addresses of the interface, each assigned and advertised as a host route.
    pub addresses: Vec<IpAddr>,
    /// The private key of this node.
    pub private_key: StaticSecret,
    /// The UDP port to listen on, or 0 for a random one.
    pub listen_port: u16,
    /// The interval between endpoint lookups, if any.
    pub reresolve_interval: Option<Duration>,
    /// The sources from which this host accepts packets, and the destinations routed to the
    /// interface. This does not limit what the node learns, advertises, or forwards.
    pub mesh: Vec<IpNet>,
    /// The directly attached networks, which are advertised.
    pub attached: Vec<IpNet>,
    /// The prefixes of `addresses` and `attached` that other nodes may originate too, as may they
    /// prefixes inside them, for example a default route at each of several exit nodes. Every other
    /// prefix that this node originates is exclusive to it: an update from another router for it,
    /// or for a prefix inside it, conflicts with it.
    pub nonexclusive: Vec<IpNet>,
    /// Whether to add kernel routes for `mesh` (see [`Self::kernel_route_prefixes`]).
    pub kernel_routes: bool,
    /// The peers.
    pub peers: Vec<PeerConfig>,
}

impl Config {
    /// Loads a configuration from a file, whose stem names the interface unless the file does.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        warn_if_world_accessible(path);

        let text = fs::read_to_string(path)
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        let stem = path.file_stem().and_then(|stem| stem.to_str());

        Self::parse(&text, stem).wrap_err_with(|| format!("invalid config {}", path.display()))
    }

    /// Parses and validates a configuration. The interface is named `default_name` unless
    /// `text` names it.
    pub fn parse(text: &str, default_name: Option<&str>) -> eyre::Result<Self> {
        // Only the message, as the error's own display quotes the line, which can hold a key.
        let raw: RawConfig = toml::from_str(text).map_err(|e| match e.span() {
            Some(span) => {
                let line = text[..span.start].matches('\n').count() + 1;
                eyre!("line {line}: {}", e.message())
            }
            None => eyre!("{}", e.message()),
        })?;

        let RawInterface {
            name,
            mtu,
            addresses,
        } = raw.interface;
        let RawWireguard {
            private_key,
            private_key_file,
            listen_port,
            reresolve_secs,
        } = raw.wireguard;
        let RawRouting {
            mesh,
            attached,
            kernel_routes,
        } = raw.routing;
        let kernel_routes = kernel_routes.unwrap_or(true);

        let (addresses, nonexclusive_addresses) = Marked::split(addresses);
        let (attached, nonexclusive_attached) = Marked::split(attached);
        let nonexclusive =
            local_prefixes(&nonexclusive_addresses, &nonexclusive_attached).collect();

        let name = name
            .as_deref()
            .or(default_name)
            .ok_or_else(|| eyre!("interface.name is required"))?
            .to_owned();
        ensure!(
            valid_interface_name(&name),
            "invalid interface name {name:?}: it should be 1 to 15 of the characters a-z, A-Z, 0-9, \
             and _=+.-, as wg-quick requires"
        );

        let private_key = match (private_key, private_key_file) {
            (Some(key), None) => decode_key(&key).wrap_err("invalid wireguard.private_key")?,
            (None, Some(path)) => {
                warn_if_world_accessible(&path);
                let key = fs::read_to_string(&path)
                    .wrap_err_with(|| format!("failed to read {}", path.display()))?;
                decode_key(key.trim())
                    .wrap_err_with(|| format!("invalid private key in {}", path.display()))?
            }
            (None, None) => {
                bail!("one of wireguard.private_key and wireguard.private_key_file is required")
            }
            (Some(_), Some(_)) => {
                bail!("only one of wireguard.private_key and wireguard.private_key_file is allowed")
            }
        };
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);

        let mtu = mtu.unwrap_or(Params::DEFAULT_MTU);
        ensure!(
            mtu >= Params::MIN_MTU,
            "interface.mtu should be at least {}",
            Params::MIN_MTU
        );

        for address in &addresses {
            ensure!(
                !martian_prefix(IpNet::from(*address)),
                "interface.addresses cannot include {address}"
            );
        }
        for prefix in &attached {
            ensure!(
                !martian_prefix(*prefix),
                "routing.attached cannot include {prefix}"
            );
        }
        for prefix in &mesh {
            ensure!(
                !martian_prefix(*prefix),
                "routing.mesh cannot include {prefix}"
            );
            ensure!(
                !kernel_routes || prefix.prefix_len() != 0,
                "routing.mesh cannot include {prefix} unless routing.kernel_routes is false"
            );
        }

        ensure!(!raw.peers.is_empty(), "at least one [[peer]] is required");
        let mut seen = HashSet::new();
        let peers = (raw.peers.into_iter())
            .map(|peer| {
                let peer_key = decode_key(&peer.public_key)
                    .map(PublicKey::from)
                    .wrap_err_with(|| format!("invalid peer public key {:?}", peer.public_key))?;
                ensure!(
                    peer_key != public_key,
                    "peer {} is this node's own key",
                    peer.public_key
                );
                ensure!(
                    seen.insert(peer_key),
                    "peer {} is listed twice",
                    peer.public_key
                );

                let preshared_key = peer
                    .preshared_key
                    .as_deref()
                    .map(decode_key)
                    .transpose()
                    .wrap_err_with(|| {
                        format!("invalid preshared key of peer {}", peer.public_key)
                    })?;
                let endpoint = peer
                    .endpoint
                    .as_deref()
                    .map(parse_endpoint)
                    .transpose()
                    .wrap_err_with(|| format!("invalid endpoint of peer {}", peer.public_key))?;
                let peer_name = peer
                    .peer_name
                    .as_deref()
                    .map(parse_peer_name)
                    .transpose()
                    .wrap_err_with(|| format!("invalid name of peer {}", peer.public_key))?;
                    
                Ok(PeerConfig {
                    public_key: peer_key,
                    preshared_key,
                    endpoint,
                    peer_name,
                })
            })
            .collect::<eyre::Result<_>>()?;

        let reresolve_secs = reresolve_secs.unwrap_or(DEFAULT_RERESOLVE_SECS);
        ensure!(
            reresolve_secs == 0 || reresolve_secs >= MIN_RERESOLVE_SECS,
            "wireguard.reresolve_secs should be 0 or at least {MIN_RERESOLVE_SECS}"
        );

        Ok(Self {
            name,
            mtu,
            addresses,
            private_key,
            listen_port: listen_port.unwrap_or(0),
            reresolve_interval: (reresolve_secs != 0).then(|| Duration::from_secs(reresolve_secs)),
            mesh: mesh.iter().map(IpNet::trunc).collect(),
            attached: attached.iter().map(IpNet::trunc).collect(),
            nonexclusive,
            kernel_routes,
            peers,
        })
    }

    /// Splits the prefixes of `mesh` into those to add kernel routes for, and those skipped for
    /// having no local prefix of their family. Only a local prefix can make use of such a route,
    /// as it holds the host's address, or a network that the kernel forwards for. Without one, the
    /// route could only take traffic from the path it would otherwise follow.
    pub fn kernel_route_prefixes(&self) -> (Vec<IpNet>, Vec<IpNet>) {
        if !self.kernel_routes {
            return (Vec::new(), Vec::new());
        }
        let has_local_prefix = |prefix: &IpNet| {
            local_prefixes(&self.addresses, &self.attached)
                .any(|local| local.addr().is_ipv4() == prefix.addr().is_ipv4())
        };
        self.mesh.iter().copied().partition(has_local_prefix)
    }
}

/// Decodes a key in base64, as `wg` writes them.
pub fn decode_key(key: &str) -> eyre::Result<[u8; 32]> {
    let bytes = BASE64_STANDARD
        .decode(key)
        .map_err(|_| eyre!("not valid base64"))?;
    bytes.try_into().map_err(|_| eyre!("not 32 octets long"))
}

/// Encodes a key in base64, as `wg` writes them.
pub fn encode_key(key: &[u8; 32]) -> String {
    BASE64_STANDARD.encode(key)
}

/// Checks a name against the rule of `wg-quick`, which also keeps it safe in a file path.
fn valid_interface_name(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name != "."
        && name != ".."
        && (name.bytes()).all(|b| b.is_ascii_alphanumeric() || b"_=+.-".contains(&b))
}

/// Parses `host:port`, `address:port` or `[address]:port`.
fn parse_endpoint(endpoint: &str) -> eyre::Result<Endpoint> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(Endpoint::Address(addr));
    }

    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| eyre!("{endpoint:?} should be host:port"))?;
    let port = port
        .parse()
        .map_err(|_| eyre!("{endpoint:?} has an invalid port"))?;
    ensure!(
        !host.is_empty() && !host.contains(':') && !host.contains('['),
        "{endpoint:?} should be host:port"
    );

    Ok(Endpoint::Host {
        host: host.to_owned(),
        port,
    })
}

/// Parses peer name [A-Z][a-z]_-
fn parse_peer_name(peer_name: &str) -> eyre::Result<String>{
    ensure!(!peer_name.is_empty() && peer_name.chars().all(|c| {c.is_ascii_alphanumeric() || c == '_' || c == '-'}),
        "Peer name only support letters, digits, hyphens, and underscores"
    );
    Ok(peer_name.to_owned())
}

/// Warns if others can get at a file that may hold a private key.
fn warn_if_world_accessible(path: &Path) {
    if world_accessible(path).unwrap_or(false) {
        tracing::warn!("{} is world accessible", path.display());
    }
}

/// Checks whether users with no special claim on a file can read or write it, going by the
/// permissions of the file itself and of each directory above where it really is.
fn world_accessible(path: &Path) -> io::Result<bool> {
    let path = fs::canonicalize(path)?;
    let mode = |path: &Path| Ok::<_, io::Error>(fs::metadata(path)?.permissions().mode());

    let directories = (path.ancestors().skip(1))
        .map(mode)
        .collect::<io::Result<Vec<_>>>()?;
    Ok(modes_allow_others(mode(&path)?, &directories))
}

/// Checks whether modes let others read or write a file: they need that permission on the file,
/// and search permission on every directory above it.
fn modes_allow_others(file: u32, directories: &[u32]) -> bool {
    file & 0o006 != 0 && directories.iter().all(|mode| mode & 0o001 != 0)
}
