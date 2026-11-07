//! Whole nodes in one process: real Babel drivers and WireGuard devices over UDP on the loopback
//! interface, with channels in place of TUN devices, so that this runs without privileges.

use std::{
    io, iter,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    time::Duration,
};

use cynet::{
    babel::{Interval, Params, snapshot::PrefixStatus},
    config::{Config, encode_key},
    daemon::Node,
    router::link_local_address,
    show::strip_colors,
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

    for verbose in [false, true] {
        let mut command = Command::new(cli);
        command.args(["show", &name]);
        if verbose {
            command.arg("--verbose");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains(&format!("interface: {name}")), "{text}");
        assert!(text.contains("10.42.0.21/32"), "{text}");
        assert_eq!(text.contains("router-id:"), verbose, "{text}");
        assert!(!text.contains('\x1b'));
    }
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

    async fn status_of(&self, prefix: &str) -> Option<PrefixStatus<PublicKey>> {
        let prefix: IpNet = prefix.parse().unwrap();
        let snapshot = self.node.snapshot().await?;
        (snapshot.prefixes.iter())
            .find(|entry| entry.prefix == prefix)
            .map(|entry| entry.status)
    }

    /// Waits until the node has selected a route to a prefix, through a certain peer.
    async fn wait_for_route(&self, prefix: &str, via: u8) {
        let done = async {
            while self.status_of(prefix).await != Some(PrefixStatus::Selected(public(via))) {
                sleep(Duration::from_millis(20)).await;
            }
        };
        timeout(PATIENCE, done)
            .await
            .unwrap_or_else(|_| panic!("the route to {prefix} should be selected"));
    }
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

    // The status lists every peer and route.
    let text = strip_colors(&chain.b.node.status().text("cyn0", false).await.unwrap());
    for needle in [
        "interface: cyn0",
        "10.42.0.1/32",
        "10.42.0.2/32",
        "10.42.0.3/32",
        "fd42::3/128",
        "injected",
        "via",
        "latest handshake",
    ] {
        assert!(text.contains(needle), "{needle} should be in:\n{text}");
    }
    for peer in [1, 3] {
        let key = encode_key(public(peer).as_bytes());
        assert!(text.contains(&format!("peer: {key}")), "{text}");
    }
    for needle in ["seqno", "rxcost", "hello history"] {
        assert!(!text.contains(needle), "{needle} should not be in:\n{text}");
    }

    let text = strip_colors(&chain.b.node.status().text("cyn0", true).await.unwrap());
    for needle in ["seqno", "rxcost", "hello history"] {
        assert!(text.contains(needle), "{needle} should be in:\n{text}");
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
