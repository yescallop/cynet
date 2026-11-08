//! Whole nodes in one process: real Babel drivers and WireGuard devices over UDP on the loopback
//! interface, with channels in place of TUN devices, so that this runs without privileges.

use std::{
    io, iter,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    time::Duration,
};

use cynet::{
    babel::{
        Interval, Params,
        snapshot::{PrefixSnapshot, PrefixStatus},
    },
    config::{Config, encode_key},
    daemon::Node,
    router::link_local_address,
    show::{short_key, strip_colors},
    udp::UdpSocketFactory,
};
use gotatun::{
    device::DeviceBuilder,
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    x25519::{PublicKey, StaticSecret},
};
use ipnet::IpNet;
use tokio::{
    sync::mpsc,
    time::{sleep, timeout},
};
use zerocopy::IntoBytes;

const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const DF: u16 = 0x4000;

/// Exercises the public server and the real CLI, without needing a TUN driver or elevation.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_show_reads_a_live_node_and_releases_the_pipe() {
    use cynet::show::ShowServer;
    use std::process::Command;

    let node = TestNode::start(&NodeSpec::new(21, 0, vec!["10.42.0.21"], vec![(22, None)])).await;
    let name = format!("test{}", std::process::id());
    let server = ShowServer::start(&name, node.node.status()).unwrap();
    assert!(ShowServer::start(&name, node.node.status()).is_err());
    let cli = env!("CARGO_BIN_EXE_cynet");

    let mut command = Command::new(cli);
    command.args(["show", &name]);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(&format!("interface: {name}")), "{text}");
    assert!(text.contains("10.42.0.21/32"), "{text}");
    assert!(text.contains("router-id:"), "{text}");
    assert!(!text.contains('\x1b'));
    let output = Command::new(cli).arg("show").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("interface: {name}")));

    drop(server);
    // Aborting a task closes its pipe when the runtime next polls it.
    sleep(Duration::from_millis(50)).await;
    let output = Command::new(cli).args(["show", &name]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not running"));
    node.node.stop().await;
}

/// How long anything in these tests may take, which is far longer than it should.
const PATIENCE: Duration = Duration::from_secs(20);

/// The kernel's side of a mock TUN device.
struct TunTx(mpsc::Sender<Packet<Ip>>);

impl IpSend for TunTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        // A test that isn't listening doesn't hold up the node.
        let _ = self.0.try_send(packet);
        Ok(())
    }
}

/// The device's side of a mock TUN device.
struct TunRx {
    rx: mpsc::Receiver<Packet<Ip>>,
    mtu: u16,
}

impl IpRecv for TunRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "closed"))?;
        Ok(iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

fn secret(n: u8) -> StaticSecret {
    StaticSecret::from([n; 32])
}

fn public(n: u8) -> PublicKey {
    PublicKey::from(&secret(n))
}

/// Returns a UDP port that was free a moment ago.
fn free_port() -> u16 {
    UdpSocket::bind("[::]:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct NodeSpec {
    /// A number identifying the node, for its key.
    id: u8,
    port: u16,
    mtu: u16,
    addresses: Vec<&'static str>,
    mesh: Vec<&'static str>,
    attached: Vec<&'static str>,
    /// The peers, each with its number and its endpoint, if any.
    peers: Vec<(u8, Option<String>)>,
}

impl NodeSpec {
    /// A node with the default MTU and no attached networks, in the usual mesh.
    fn new(
        id: u8,
        port: u16,
        addresses: Vec<&'static str>,
        peers: Vec<(u8, Option<String>)>,
    ) -> Self {
        Self {
            id,
            port,
            mtu: 1400,
            addresses,
            mesh: MESH.to_vec(),
            attached: vec![],
            peers,
        }
    }

    fn config(&self) -> Config {
        let list = |items: &[&str]| {
            items
                .iter()
                .map(|item| format!("{item:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut text = format!(
            "[interface]\n\
             mtu = {}\n\
             addresses = [{}]\n\
             [wireguard]\n\
             private_key = \"{}\"\n\
             listen_port = {}\n\
             [routing]\n\
             mesh = [{}]\n\
             attached = [{}]\n\
             kernel_routes = false\n",
            self.mtu,
            list(&self.addresses),
            encode_key(&[self.id; 32]),
            self.port,
            list(&self.mesh),
            list(&self.attached),
        );
        for (peer, endpoint) in &self.peers {
            text += &format!(
                "[[peer]]\npublic_key = \"{}\"\n",
                encode_key(public(*peer).as_bytes())
            );
            if let Some(endpoint) = endpoint {
                text += &format!("endpoint = {endpoint:?}\n");
            }
        }
        Config::parse(&text, Some("cyn0")).unwrap()
    }
}

struct TestNode {
    node: Node<(UdpSocketFactory, TunTx, TunRx)>,
    /// What "the kernel" writes to the TUN.
    tx: mpsc::Sender<Packet<Ip>>,
    /// What "the kernel" reads from the TUN.
    rx: mpsc::Receiver<Packet<Ip>>,
}

impl TestNode {
    async fn start(spec: &NodeSpec) -> Self {
        let (to_device, device_rx) = mpsc::channel(64);
        let (device_tx, from_device) = mpsc::channel(64);

        let mut params = Params::new();
        params.set_hello_interval(Interval::new(10).unwrap());

        let builder = DeviceBuilder::new()
            .with_udp(UdpSocketFactory::default())
            .with_ip_pair(
                TunTx(device_tx),
                TunRx {
                    rx: device_rx,
                    mtu: spec.mtu,
                },
            );

        let node = Node::start(&spec.config(), params, builder).await.unwrap();

        Self {
            node,
            tx: to_device,
            rx: from_device,
        }
    }

    async fn send(&self, bytes: &[u8]) {
        let packet = Packet::copy_from(bytes).try_into_ip().unwrap();
        self.tx.send(packet).await.unwrap();
    }

    async fn recv(&mut self) -> Vec<u8> {
        timeout(PATIENCE, self.rx.recv())
            .await
            .expect("a packet should come out of the TUN")
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Checks that nothing comes out of the TUN for a while.
    async fn expect_silence(&mut self) {
        if let Ok(packet) = timeout(Duration::from_millis(300), self.rx.recv()).await {
            panic!("unexpected packet: {:02x?}", packet.unwrap().as_bytes());
        }
    }

    /// Returns what the node knows of a prefix, if anything.
    async fn entry_of(&self, prefix: &str) -> Option<PrefixSnapshot<PublicKey>> {
        let prefix: IpNet = prefix.parse().unwrap();
        let snapshot = self.node.snapshot().await?;
        (snapshot.prefixes.into_iter()).find(|entry| entry.prefix == prefix)
    }

    async fn status_of(&self, prefix: &str) -> Option<PrefixStatus<PublicKey>> {
        Some(self.entry_of(prefix).await?.status)
    }

    /// Waits until the node has selected a route to a prefix, through a certain peer.
    async fn wait_for_route(&self, prefix: &str, via: u8) {
        let selected = Some(PrefixStatus::Selected(public(via)));
        let what = format!("the route to {prefix} should be selected");
        wait_until(&what, async || self.status_of(prefix).await == selected).await;
    }
}

/// Waits until `done` holds, checking it every 20 ms, or panics with `what` should have happened.
async fn wait_until(what: &str, mut done: impl AsyncFnMut() -> bool) {
    let poll = async {
        while !done().await {
            sleep(Duration::from_millis(20)).await;
        }
    };
    timeout(PATIENCE, poll)
        .await
        .unwrap_or_else(|_| panic!("{what}"));
}

/// The Internet checksum, written apart from the code under test.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(source: &str, destination: &str, ttl: u8, payload_len: usize) -> Vec<u8> {
    let source: Ipv4Addr = source.parse().unwrap();
    let destination: Ipv4Addr = destination.parse().unwrap();
    let mut b = vec![0x45, 0];
    b.extend_from_slice(&((20 + payload_len) as u16).to_be_bytes());
    b.extend_from_slice(&[0x12, 0x34]);
    b.extend_from_slice(&DF.to_be_bytes());
    b.extend_from_slice(&[ttl, UDP, 0, 0]);
    b.extend_from_slice(&source.octets());
    b.extend_from_slice(&destination.octets());
    let check = checksum(&b);
    b[10..12].copy_from_slice(&check.to_be_bytes());
    b.resize(20 + payload_len, 0xab);
    b
}

fn ipv6(source: &str, destination: &str, hop_limit: u8, payload_len: usize) -> Vec<u8> {
    let source: Ipv6Addr = source.parse().unwrap();
    let destination: Ipv6Addr = destination.parse().unwrap();
    let mut b = vec![0x60, 0, 0, 0];
    b.extend_from_slice(&(payload_len as u16).to_be_bytes());
    b.extend_from_slice(&[UDP, hop_limit]);
    b.extend_from_slice(&source.octets());
    b.extend_from_slice(&destination.octets());
    b.resize(40 + payload_len, 0xab);
    b
}

/// Checks an ICMPv4 error and returns its source.
#[track_caller]
fn check_icmp_v4(reply: &[u8], ty: u8, code: u8, destination: &str) -> IpAddr {
    assert_eq!(reply[9], ICMP);
    assert_eq!(checksum(&reply[..20]), 0);
    assert_eq!(checksum(&reply[20..]), 0);
    assert_eq!((reply[20], reply[21]), (ty, code));
    let actual: [u8; 4] = reply[16..20].try_into().unwrap();
    assert_eq!(
        Ipv4Addr::from(actual),
        destination.parse::<Ipv4Addr>().unwrap()
    );
    let source: [u8; 4] = reply[12..16].try_into().unwrap();
    Ipv4Addr::from(source).into()
}

/// Checks an ICMPv6 error and returns its source.
#[track_caller]
fn check_icmp_v6(reply: &[u8], ty: u8, code: u8, destination: &str) -> IpAddr {
    assert_eq!(reply[6], ICMPV6);
    assert_eq!((reply[40], reply[41]), (ty, code));
    let actual: [u8; 16] = reply[24..40].try_into().unwrap();
    assert_eq!(
        Ipv6Addr::from(actual),
        destination.parse::<Ipv6Addr>().unwrap()
    );
    let source: [u8; 16] = reply[8..24].try_into().unwrap();
    Ipv6Addr::from(source).into()
}

/// A chain of three nodes, A - B - C, on an IPv4 and IPv6 mesh. A has a larger MTU than B.
struct Chain {
    a: TestNode,
    b: TestNode,
    c: TestNode,
}

const MESH: [&str; 2] = ["10.42.0.0/16", "fd42::/48"];

impl Chain {
    async fn start() -> Self {
        let (port_a, port_b, port_c) = (free_port(), free_port(), free_port());
        let endpoint = |port| Some(format!("127.0.0.1:{port}"));

        let b = TestNode::start(&NodeSpec::new(
            2,
            port_b,
            vec!["10.42.0.2", "fd42::2"],
            vec![(1, endpoint(port_a)), (3, endpoint(port_c))],
        ))
        .await;
        let a = TestNode::start(&NodeSpec {
            mtu: 1500,
            ..NodeSpec::new(
                1,
                port_a,
                vec!["10.42.0.1", "fd42::1"],
                vec![(2, endpoint(port_b))],
            )
        })
        .await;
        let c = TestNode::start(&NodeSpec::new(
            3,
            port_c,
            vec!["10.42.0.3", "fd42::3"],
            vec![(2, endpoint(port_b))],
        ))
        .await;

        a.wait_for_route("10.42.0.3/32", 2).await;
        a.wait_for_route("fd42::3/128", 2).await;
        c.wait_for_route("10.42.0.1/32", 2).await;
        c.wait_for_route("fd42::1/128", 2).await;

        Self { a, b, c }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn chain_forwards_and_answers_with_icmp() {
    let mut chain = Chain::start().await;
    let (a, b, c) = (&mut chain.a, &mut chain.b, &mut chain.c);

    // Babel's traffic never reached a TUN, during all that convergence.
    a.expect_silence().await;
    b.expect_silence().await;
    c.expect_silence().await;

    // Two hops: node A sends as is, since the kernel has already done its part, and node B
    // decrements, without its kernel seeing it.
    a.send(&ipv4("10.42.0.1", "10.42.0.3", 64, 100)).await;
    let got = c.recv().await;
    assert_eq!(got[8], 63);
    assert_eq!(checksum(&got[..20]), 0);
    assert_eq!(got.len(), 120);
    b.expect_silence().await;

    a.send(&ipv6("fd42::1", "fd42::3", 64, 100)).await;
    let got = c.recv().await;
    assert_eq!(got[7], 63);
    assert_eq!(got.len(), 140);

    // And back.
    c.send(&ipv4("10.42.0.3", "10.42.0.1", 64, 100)).await;
    assert_eq!(a.recv().await[8], 63);

    // A TTL of 1 goes out of node A, and runs out at node B.
    let packet = ipv4("10.42.0.1", "10.42.0.3", 1, 100);
    a.send(&packet).await;
    let reply = a.recv().await;
    let source = check_icmp_v4(&reply, 11, 0, "10.42.0.1");
    assert_eq!(source, "10.42.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(reply[28..], packet);

    a.send(&ipv6("fd42::1", "fd42::3", 1, 100)).await;
    let reply = a.recv().await;
    let source = check_icmp_v6(&reply, 3, 0, "fd42::1");
    assert_eq!(source, "fd42::2".parse::<IpAddr>().unwrap());

    // A destination with no route is answered by node A itself.
    a.send(&ipv4("10.42.0.1", "10.42.0.77", 64, 100)).await;
    let reply = a.recv().await;
    let source = check_icmp_v4(&reply, 3, 0, "10.42.0.1");
    assert_eq!(source, "10.42.0.1".parse::<IpAddr>().unwrap());

    a.send(&ipv6("fd42::1", "fd42::77", 64, 100)).await;
    let reply = a.recv().await;
    check_icmp_v6(&reply, 1, 0, "fd42::1");

    // A packet that fits node A's MTU but not node B's is refused by node B, with its MTU.
    a.send(&ipv4("10.42.0.1", "10.42.0.3", 64, 1450)).await;
    let reply = a.recv().await;
    let source = check_icmp_v4(&reply, 3, 4, "10.42.0.1");
    assert_eq!(source, "10.42.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(u16::from_be_bytes([reply[26], reply[27]]), 1400);

    a.send(&ipv6("fd42::1", "fd42::3", 64, 1450)).await;
    let reply = a.recv().await;
    check_icmp_v6(&reply, 2, 0, "fd42::1");
    assert_eq!(u32::from_be_bytes(reply[44..48].try_into().unwrap()), 1400);

    // What fits goes through.
    a.send(&ipv4("10.42.0.1", "10.42.0.3", 64, 1380)).await;
    assert_eq!(c.recv().await.len(), 1400);

    // The status lists every peer and route, with what Babel bases its choice of routes on.
    let text = status_text(&chain.b).await;
    for needle in [
        "interface: cyn0",
        "10.42.0.1/32",
        "10.42.0.2/32",
        "10.42.0.3/32",
        "fd42::3/128",
        "injected",
        "via",
        "latest handshake",
        "seqno",
        "rxcost",
        "hello history",
    ] {
        assert!(text.contains(needle), "{needle} should be in:\n{text}");
    }
    for peer in [1, 3] {
        let key = encode_key(public(peer).as_bytes());
        assert!(text.contains(&format!("peer: {key}")), "{text}");
    }
}

/// A stopping node says goodbye, so its neighbours don't wait for the link to fail, and errors
/// follow for its addresses.
#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_node_retracts_its_routes_at_once() {
    let Chain { mut a, b, c } = Chain::start().await;

    c.node.stop().await;

    // Far sooner than the link would take to fail, by a Hello interval of 0.1 s here, the goodbye
    // has node B hold the route, and node A in turn.
    timeout(Duration::from_secs(5), async {
        while b.status_of("10.42.0.3/32").await != Some(PrefixStatus::Held) {
            sleep(Duration::from_millis(5)).await;
        }
        while a.status_of("10.42.0.3/32").await != Some(PrefixStatus::Held) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the route should be held");

    // Node A answers for the held route: host unreachable, rather than network unreachable.
    a.send(&ipv4("10.42.0.1", "10.42.0.3", 64, 100)).await;
    let reply = a.recv().await;
    let source = check_icmp_v4(&reply, 3, 1, "10.42.0.1");
    assert_eq!(source, "10.42.0.1".parse::<IpAddr>().unwrap());

    a.node.stop().await;
    b.node.stop().await;
}

/// A node whose `mesh` lacks a prefix still carries it, but doesn't take it for itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_network_can_be_extended_through_a_node_not_yet_updated() {
    let (port_a, port_b, port_c) = (free_port(), free_port(), free_port());
    let endpoint = |port| Some(format!("127.0.0.1:{port}"));
    let extended = vec!["10.42.0.0/16", "10.43.0.0/16"];

    let mut b = TestNode::start(&NodeSpec {
        mesh: vec!["10.42.0.0/16"],
        ..NodeSpec::new(
            2,
            port_b,
            vec!["10.42.0.2"],
            vec![(1, endpoint(port_a)), (3, endpoint(port_c))],
        )
    })
    .await;
    let a = TestNode::start(&NodeSpec {
        mesh: extended.clone(),
        ..NodeSpec::new(
            1,
            port_a,
            vec!["10.42.0.1", "10.43.0.1"],
            vec![(2, endpoint(port_b))],
        )
    })
    .await;
    let mut c = TestNode::start(&NodeSpec {
        mesh: extended,
        ..NodeSpec::new(
            3,
            port_c,
            vec!["10.42.0.3", "10.43.0.3"],
            vec![(2, endpoint(port_b))],
        )
    })
    .await;

    // The route to the new prefix crosses node B.
    a.wait_for_route("10.43.0.3/32", 2).await;
    c.wait_for_route("10.43.0.1/32", 2).await;
    b.wait_for_route("10.43.0.3/32", 3).await;

    // So does its traffic.
    a.send(&ipv4("10.43.0.1", "10.43.0.3", 64, 100)).await;
    assert_eq!(c.recv().await[8], 63);
    b.expect_silence().await;

    // But node B's own host doesn't accept it.
    a.send(&ipv4("10.43.0.1", "10.42.0.2", 64, 100)).await;
    b.expect_silence().await;

    // While the rest of the mesh still does.
    a.send(&ipv4("10.42.0.1", "10.42.0.2", 64, 100)).await;
    assert_eq!(b.recv().await[8], 64);
}

/// A peer is a Babel neighbour from the start. Its startup packets keep asking for a WireGuard
/// session, here from a peer that has no way of asking first, and nothing sent before there is one
/// arrives late.
#[tokio::test(flavor = "multi_thread")]
async fn startup_packets_start_handshakes_for_a_peer_that_comes_later() {
    let (port_a, port_b) = (free_port(), free_port());

    let a = TestNode::start(&NodeSpec::new(
        1,
        port_a,
        vec!["10.42.0.1", "fd42::1"],
        vec![(2, Some(format!("127.0.0.1:{port_b}")))],
    ))
    .await;

    let neighbours = a.node.snapshot().await.unwrap().neighbours;
    assert_eq!(neighbours.len(), 1);
    assert_eq!(neighbours[0].key, public(2));

    sleep(Duration::from_secs(1)).await;

    let b = TestNode::start(&NodeSpec::new(
        2,
        port_b,
        vec!["10.42.0.2", "fd42::2"],
        vec![(1, None)],
    ))
    .await;

    a.wait_for_route("10.42.0.2/32", 2).await;
    b.wait_for_route("10.42.0.1/32", 1).await;
}

/// Link-local prefixes advertised by a peer are not learned, and packets from a peer's link-local
/// address that aren't Babel's reach nothing.
#[tokio::test(flavor = "multi_thread")]
async fn martian_prefixes_do_not_spread_and_link_local_traffic_stays_out() {
    let (port_a, port_b) = (free_port(), free_port());
    let endpoint = |port| Some(format!("127.0.0.1:{port}"));

    let mut b = TestNode::start(&NodeSpec::new(
        2,
        port_b,
        vec!["10.42.0.2", "fd42::2"],
        vec![(1, endpoint(port_a))],
    ))
    .await;
    let mut a = TestNode::start(&NodeSpec::new(
        1,
        port_a,
        vec!["10.42.0.1", "fd42::1"],
        vec![(2, endpoint(port_b))],
    ))
    .await;

    a.wait_for_route("fd42::2/128", 2).await;

    let snapshot = a.node.snapshot().await.unwrap();
    for entry in &snapshot.prefixes {
        assert!(
            !matches!(entry.prefix.addr(), IpAddr::V6(addr) if addr.is_unicast_link_local()),
            "{}",
            entry.prefix
        );
    }

    // From the TUN, link-local destinations go nowhere, not even as an error.
    let lla = link_local_address(&public(2)).to_string();
    a.send(&ipv6("fd42::1", &lla, 64, 20)).await;
    a.expect_silence().await;
    b.expect_silence().await;
}

/// A hostname is looked up when the node starts, and traffic flows.
#[tokio::test(flavor = "multi_thread")]
async fn hostname_endpoints_are_resolved() {
    let (port_a, port_b) = (free_port(), free_port());

    let mut b = TestNode::start(&NodeSpec::new(
        2,
        port_b,
        vec!["10.42.0.2"],
        vec![(1, None)],
    ))
    .await;
    let a = TestNode::start(&NodeSpec::new(
        1,
        port_a,
        vec!["10.42.0.1"],
        vec![(2, Some(format!("localhost:{port_b}")))],
    ))
    .await;

    let peers = a.node.device().peers().await;
    let endpoint = peers[0].peer.endpoint.expect("the endpoint should be set");
    assert_eq!(endpoint.port(), port_b);
    assert!(endpoint.ip().is_loopback());

    // Node B has no endpoint for node A until it hears from it.
    a.wait_for_route("10.42.0.2/32", 2).await;
    b.wait_for_route("10.42.0.1/32", 1).await;

    a.send(&ipv4("10.42.0.1", "10.42.0.2", 64, 100)).await;
    assert_eq!(b.recv().await.len(), 120);
}

/// Starts a chain of three nodes, A - B - C, on the IPv4 mesh, where node A is attached to
/// `network`, and node C has `c_addresses` beside its own and is attached to `c_attached`, and
/// waits until each end reaches the other.
async fn conflict_chain(
    network: &'static str,
    c_addresses: &[&'static str],
    c_attached: &[&'static str],
) -> (TestNode, TestNode, TestNode) {
    let (port_a, port_b, port_c) = (free_port(), free_port(), free_port());
    let endpoint = |port| Some(format!("127.0.0.1:{port}"));

    let b = TestNode::start(&NodeSpec::new(
        2,
        port_b,
        vec!["10.42.0.2"],
        vec![(1, endpoint(port_a)), (3, endpoint(port_c))],
    ))
    .await;
    let a = TestNode::start(&NodeSpec {
        attached: vec![network],
        ..NodeSpec::new(1, port_a, vec!["10.42.0.1"], vec![(2, endpoint(port_b))])
    })
    .await;
    let c_addresses = iter::once("10.42.0.3").chain(c_addresses.iter().copied());
    let c = TestNode::start(&NodeSpec {
        attached: c_attached.to_vec(),
        ..NodeSpec::new(
            3,
            port_c,
            c_addresses.collect(),
            vec![(2, endpoint(port_b))],
        )
    })
    .await;

    a.wait_for_route("10.42.0.3/32", 2).await;
    c.wait_for_route("10.42.0.1/32", 2).await;
    (a, b, c)
}

/// Waits until every one of `nodes` lists a conflict.
async fn wait_for_conflicts(nodes: &[&TestNode]) {
    wait_until("every node should report the conflict", async || {
        for node in nodes {
            if !status_text(node).await.contains("\nconflicts:\n") {
                return false;
            }
        }
        true
    })
    .await;
}

/// Returns the router-ids of the routes that a node has learnt for a prefix.
async fn router_ids(node: &TestNode, prefix: &str) -> Vec<u64> {
    node.entry_of(prefix).await.map_or(vec![], |entry| {
        let routes = entry.routes.iter();
        routes.map(|route| route.router_id.get()).collect()
    })
}

/// Returns a node's plain status, without colors.
async fn status_text(node: &TestNode) -> String {
    strip_colors(&node.node.status().text("cyn0").await.unwrap())
}

/// A network attached at two nodes, unmarked, is exclusive to each, so they conflict over it. Node
/// B keeps the route it learnt first and rejects the other, and the conflict shows in the status of
/// every node, the originators included, which can be traced from one to the other.
#[tokio::test(flavor = "multi_thread")]
async fn a_network_attached_at_two_nodes_is_reported_as_a_conflict() {
    let shared = "10.42.9.0/24";
    let (a, b, c) = conflict_chain(shared, &[], &[shared]).await;
    wait_for_conflicts(&[&a, &b, &c]).await;
    let texts = [
        status_text(&a).await,
        status_text(&b).await,
        status_text(&c).await,
    ];

    // Node B has a route through one of the others only.
    assert_eq!(router_ids(&b, "10.42.9.0/24").await.len(), 1);

    // Node B rejects updates from one end, and alerts the other, which it routes through. That
    // one learns of the conflict 1 hop away, and the end whose route node B rejects rejects node
    // B's.
    let [text_a, text_b, text_c] = &texts;
    let (learnt, direct, rejected) = if text_a.contains("away via") {
        (text_a, text_c, 3)
    } else {
        (text_c, text_a, 1)
    };
    // Each conflict goes on a line of its own, under a line for its prefix.
    let conflict = |line: String| format!("\nconflicts:\n  10.42.9.0/24\n    {line}, for ");
    let learnt_line = conflict(format!("1 hop away via {}", short(2)));
    assert!(learnt.contains(&learnt_line), "{learnt}");
    let direct_line = conflict(format!("directly with {}", short(2)));
    assert!(direct.contains(&direct_line), "{direct}");
    let b_line = conflict(format!("directly with {}", short(rejected)));
    assert!(text_b.contains(&b_line), "{text_b}");

    // Among each node's routes, the prefix says so too, last.
    for (text, beside) in [
        (text_a, "injected, conflicted"),
        (text_b, "conflicted"),
        (text_c, "injected, conflicted"),
    ] {
        let line = format!("\n  10.42.9.0/24  {beside}\n");
        assert!(text.contains(&line), "{text}");
    }
}

/// Returns the first characters of a node's key, as `cynet show` names a neighbour.
fn short(n: u8) -> String {
    short_key(&public(n))
}

/// A network attached at two nodes and marked nonexclusive at both is routed to both, as before
/// conflicts were detected, with none listed, and listed as nonexclusive among the routes.
#[tokio::test(flavor = "multi_thread")]
async fn a_network_attached_at_two_nodes_as_nonexclusive_is_routed_to_both() {
    let shared = "nonexclusive,10.42.9.0/24";
    let (a, b, c) = conflict_chain(shared, &[], &[shared]).await;
    wait_until("node B should keep a route through each end", async || {
        let mut ids = router_ids(&b, "10.42.9.0/24").await;
        ids.sort_unstable();
        ids.dedup();
        ids.len() == 2
    })
    .await;

    for node in [&a, &b, &c] {
        let text = status_text(node).await;
        assert!(!text.contains("\nconflicts:\n"), "{text}");
    }

    // The ends say they originate it as nonexclusive. Node B says its routes are nonexclusive, and
    // puts them below the prefix.
    for node in [&a, &c] {
        let text = status_text(node).await;
        assert!(
            text.contains("\n  10.42.9.0/24  injected, nonexclusive\n"),
            "{text}"
        );
    }
    let text = status_text(&b).await;
    let routes = "\n  10.42.9.0/24  nonexclusive\n    via ";
    assert!(text.contains(routes), "{text}");
    assert!(text.contains("\n    not via "), "{text}");
}

/// An address inside a network that another node is attached to, unmarked, would take an address
/// of that network, so the two conflict, and node B keeps one of them only.
#[tokio::test(flavor = "multi_thread")]
async fn an_address_inside_another_nodes_exclusive_network_conflicts() {
    let (a, b, c) = conflict_chain("10.42.9.0/24", &["10.42.9.3"], &[]).await;
    wait_for_conflicts(&[&a, &b, &c]).await;

    let network = router_ids(&b, "10.42.9.0/24").await;
    let address = router_ids(&b, "10.42.9.3/32").await;
    assert_eq!(network.len() + address.len(), 1, "{network:?}, {address:?}");
}

/// The same address is routed beside the network once the network is marked nonexclusive, as the
/// longest match takes it to node C.
#[tokio::test(flavor = "multi_thread")]
async fn an_address_inside_another_nodes_nonexclusive_network_is_routed_beside_it() {
    let (a, b, c) = conflict_chain("nonexclusive,10.42.9.0/24", &["10.42.9.3"], &[]).await;

    b.wait_for_route("10.42.9.0/24", 1).await;
    b.wait_for_route("10.42.9.3/32", 3).await;
    a.wait_for_route("10.42.9.3/32", 2).await;
    for node in [&a, &b, &c] {
        let text = status_text(node).await;
        assert!(!text.contains("\nconflicts:\n"), "{text}");
    }
}
