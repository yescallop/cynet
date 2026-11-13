use std::{array::from_ref, collections::BTreeMap, iter};

use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::*;

const NOMINAL_COST: u16 = 96;
const INF: u16 = COST_INFINITY;

/// The rxcost, txcost and link cost of a link that is up with a negligible RTT.
const UP: (u16, u16, u16) = (NOMINAL_COST, NOMINAL_COST, NOMINAL_COST);

fn prefix(s: &str) -> IpNet {
    s.parse().unwrap()
}

/// Returns the default parameters, but with the Hello and Update timers not randomized, so
/// that Hellos and full dumps follow their intervals exactly.
fn params() -> Params {
    let mut params = Params::new();
    params.set_randomize_timers(false);
    params
}

/// Creates a new state for node `i`, starting at `now`.
fn state(i: usize, now: Instant) -> State {
    State::new(now, params(), RouterId::new((i + 1) as u64).unwrap(), None)
}

/// A packet sent by a node, whether or not it was delivered.
struct Sent {
    time: Instant,
    from: usize,
    to: usize,
    buf: Box<[u8]>,
}

/// An entry in a node's forwarding table, as set by its route outputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fib {
    Via(usize),
    Unreachable,
}

/// A change to a node's forwarding table.
struct FibChange {
    time: Instant,
    node: usize,
    prefix: IpNet,
    entry: Option<Fib>,
}

/// A report of a conflict output by a node (see [`Output::ConflictAlert`]).
#[derive(Clone, Copy, Debug)]
struct Report {
    time: Instant,
    node: usize,
    prefix: IpNet,
    from: usize,
    kind: ConflictAlertKind,
}

enum Event {
    Timeout(usize),
    Arrival(usize, usize, Box<[u8]>),
}

/// Returns what arrives of a packet sent from one node to another, if anything.
type Filter = fn(usize, usize, Packet) -> Option<Packet>;

/// Nodes connected by point-to-point links, driven by a clock of their own, which jumps from
/// each event to the next.
///
/// Whenever a forwarding table changes, they are all checked to be free of loops.
/// After every event, the node's route table is checked to keep no empty entries.
struct Net {
    /// The current time, which only moves forward.
    now: Instant,
    nodes: Vec<State>,
    /// Whether each node is stopped: its timers do not fire, and it loses the packets that
    /// reach it.
    stopped: Vec<bool>,
    /// The neighbour keys of each node, mapped to and from the indices of their neighbours.
    key_maps: Vec<NeighKeyMap<usize>>,
    /// The one-way latency of each link direction that is up.
    links: HashMap<(usize, usize), Duration>,
    /// Up to how much longer than its link's latency a packet takes to arrive, drawn for each
    /// packet. With none, the default, the packets on a link arrive in the order they were
    /// sent. Otherwise, they may overtake one another.
    jitter: Duration,
    filter: Filter,
    /// The arrivals of the packets in flight, ordered by time, then by the order the packets
    /// were sent.
    in_flight: BTreeMap<(Instant, u64), Event>,
    /// How many packets have been put in flight.
    transmitted: u64,
    /// When the last packet sent over each link arrives, or arrived.
    last_arrivals: HashMap<(usize, usize), Instant>,
    sent: Vec<Sent>,
    /// The prefixes each node originates.
    locals: Vec<Vec<IpNet>>,
    fibs: Vec<HashMap<IpNet, Fib>>,
    fib_changes: Vec<FibChange>,
    reports: Vec<Report>,
}

impl Net {
    fn new(n: usize) -> Self {
        // The clock starts at the real time, from which only the simulation moves it.
        let now = Instant::now();
        Self {
            now,
            nodes: (0..n).map(|i| state(i, now)).collect(),
            stopped: vec![false; n],
            key_maps: (0..n).map(|_| NeighKeyMap::new()).collect(),
            links: HashMap::new(),
            jitter: Duration::ZERO,
            filter: |_, _, packet| Some(packet),
            in_flight: BTreeMap::new(),
            transmitted: 0,
            last_arrivals: HashMap::new(),
            sent: Vec::new(),
            locals: vec![Vec::new(); n],
            fibs: vec![HashMap::new(); n],
            fib_changes: Vec::new(),
            reports: Vec::new(),
        }
    }

    /// Adds node `j` as a neighbour of node `i`, and sends the startup packet that node `i`
    /// outputs for it. A node outside the simulation acknowledges it at once, so that a test
    /// can go on to script its packets, which are discarded until then.
    fn add_neighbour(&mut self, i: usize, j: usize) {
        self.add_neighbour_unacknowledged(i, j);
        if j >= self.nodes.len() {
            self.acknowledge_startup(i, j);
        }
    }

    /// Adds node `j` as a neighbour of node `i` (see [`Self::add_neighbour`]), leaving the startup
    /// packet unacknowledged whichever node it is.
    fn add_neighbour_unacknowledged(&mut self, i: usize, j: usize) {
        self.add_neighbour_with_hello_seqno(i, j, Seqno::new(rand::random()));
    }

    /// Returns the Opaque value of the acknowledgement that node `i` awaits from node `j`.
    fn startup_opaque(&self, i: usize, j: usize) -> u16 {
        let startup = self.neigh(i, j).startup.as_ref();
        startup.expect("the neighbour should be starting up").opaque
    }

    /// Hands node `i` the acknowledgement of its startup packet to node `j`, as if it came from
    /// there.
    fn acknowledge_startup(&mut self, i: usize, j: usize) {
        let opaque = self.startup_opaque(i, j);
        self.inject_tlv(j, i, &Tlv::Acknowledgement { opaque });
    }

    /// Hands node `to` a packet of one TLV, as if it came from node `from`.
    fn inject_tlv(&mut self, from: usize, to: usize, tlv: &Tlv) {
        let mut encoder = PacketEncoder::new(1400);
        assert!(encoder.put_tlv(tlv));
        self.inject(from, to, encoder.finalize().as_bytes());
    }

    /// Adds node `j` as a neighbour of node `i` (see [`Self::add_neighbour`]), with the seqno
    /// of the first Hello that node `i` sends node `j`.
    fn add_neighbour_with_hello_seqno(&mut self, i: usize, j: usize, hello_seqno: Seqno) {
        let key = self.nodes[i].add_neighbour_with_hello_seqno(self.now, hello_seqno);
        self.key_maps[i].insert(j, key);
        self.process_outputs(i);
    }

    fn connect(&mut self, a: usize, b: usize, latency: Duration) {
        self.links.insert((a, b), latency);
        self.links.insert((b, a), latency);
        self.add_neighbour(a, b);
        self.add_neighbour(b, a);
    }

    /// Takes the link between two nodes down, and has each remove the other as a neighbour.
    fn disconnect(&mut self, a: usize, b: usize) {
        self.links.remove(&(a, b));
        self.links.remove(&(b, a));
        for (i, j) in [(a, b), (b, a)] {
            let key = self.key(i, j);
            self.nodes[i].remove_neighbour(self.now, key);
            self.key_maps[i].remove_by_external(&j);
            self.process_outputs(i);
        }
    }

    /// Restarts node `i` as `state`, which has no neighbours yet. The node is stopped for a
    /// second first, longer than any link's latency here, so that the packets it sent before
    /// arrive before any that it sends after, as a real restart takes longer too.
    fn restart(&mut self, i: usize, state: State) {
        self.stopped[i] = true;
        self.run_for(Duration::from_secs(1));
        self.stopped[i] = false;
        self.nodes[i] = state;
        self.key_maps[i] = NeighKeyMap::new();
        self.fibs[i].clear();
    }

    /// Shuts node `i` down, handling the outputs that its state returns, and stops it for
    /// good, as its process exits. A new state, never to run, takes the place of the old one.
    fn shutdown(&mut self, i: usize) {
        self.stopped[i] = true;
        let node = mem::replace(&mut self.nodes[i], state(i, self.now));
        let mut fib_changed = false;
        for output in node.shutdown(self.now) {
            fib_changed |= self.process_output(i, output);
        }
        if fib_changed {
            self.assert_loop_free();
        }
    }

    /// Returns the neighbour key of node `i` for node `j`.
    fn key(&self, i: usize, j: usize) -> NeighKey {
        self.key_maps[i].internal(&j).unwrap()
    }

    /// Returns the index of the node that a neighbour key of node `i` is for.
    fn index(&self, i: usize, key: NeighKey) -> usize {
        *self.key_maps[i].external(key).unwrap()
    }

    fn originate(&mut self, i: usize, prefix: IpNet) {
        self.originate_as(i, prefix, false);
    }

    /// Makes node `i` originate `prefix` as nonexclusive, which other nodes may originate too.
    fn originate_nonexclusive(&mut self, i: usize, prefix: IpNet) {
        self.originate_as(i, prefix, true);
    }

    fn originate_as(&mut self, i: usize, prefix: IpNet, nonexclusive: bool) {
        assert!(self.nodes[i].inject_route(prefix, nonexclusive));
        self.locals[i].push(prefix);
        self.process_outputs(i);
    }

    /// Runs the network for `duration`, handling every event in order.
    fn run_for(&mut self, duration: Duration) {
        let deadline = self.now + duration;
        while let Some(event) = self.next_event(deadline) {
            self.handle(event);
        }
    }

    /// Advances the clock to the next event, the earliest of the running nodes' timeouts and
    /// the packet arrivals, and returns it, or to `deadline` if that comes first. Timeouts come
    /// before arrivals at the same time, and lower nodes before higher ones. A timeout of a
    /// node that was stopped may be past, and is then handled at once.
    fn next_event(&mut self, deadline: Instant) -> Option<Event> {
        let nodes = self.nodes.iter_mut().zip(&self.stopped).enumerate();
        let timeout = nodes
            .filter(|(_, (_, stopped))| !**stopped)
            .filter_map(|(i, (node, _))| Some((node.poll_timeout()?, i)))
            .min();
        let arrival = self.in_flight.first_key_value().map(|(&(t, _), _)| t);

        let time = [timeout.map(|(t, _)| t), arrival]
            .into_iter()
            .flatten()
            .min();
        let Some(time) = time.filter(|&t| t <= deadline) else {
            self.now = deadline;
            return None;
        };
        self.now = self.now.max(time);
        Some(match timeout {
            Some((t, i)) if t == time => Event::Timeout(i),
            _ => self.in_flight.pop_first().unwrap().1,
        })
    }

    fn handle(&mut self, event: Event) {
        let i = match event {
            Event::Timeout(i) => {
                self.nodes[i].handle_timeout(self.now);
                i
            }
            Event::Arrival(_, to, _) if self.stopped[to] => return,
            Event::Arrival(from, to, buf) => {
                // It may have been removed as a neighbour while this was on the way.
                let Some(key) = self.key_maps[to].internal(&from) else {
                    return;
                };
                self.nodes[to].handle_packet(self.now, self.now, key, &buf);
                to
            }
        };
        self.process_outputs(i);
    }

    /// Hands a packet to node `to` as if it came from node `from`.
    fn inject(&mut self, from: usize, to: usize, buf: &[u8]) {
        let key = self.key(to, from);
        self.nodes[to].handle_packet(self.now, self.now, key, buf);
        self.process_outputs(to);
    }

    /// Handles every output of node `from` (see [`Self::process_output`]), then checks the
    /// network for loops if a forwarding table changed, and the node's route table.
    fn process_outputs(&mut self, from: usize) {
        let mut fib_changed = false;

        while let Some(output) = self.nodes[from].poll_output() {
            fib_changed |= self.process_output(from, output);
        }

        if fib_changed {
            self.assert_loop_free();
        }

        let node = &self.nodes[from];
        let table = &node.route_table;
        for (prefix, entry) in &table.prefix_entries {
            let empty = entry.is_empty();
            assert!(
                !empty,
                "node {from} should not keep an empty entry for {prefix}"
            );
            assert!(table.prefixes.contains(prefix), "node {from}: {prefix}");
        }
        assert_eq!(
            table.prefixes.len(),
            table.prefix_entries.len(),
            "node {from}"
        );

        // No two sources in the table conflict, which spares most updates the search for what
        // they conflict with (see `RouteTable::get_or_insert_with_known_source`).
        let sources: Vec<_> = (table.prefix_entries.iter())
            .flat_map(|(&prefix, entry)| entry.sources(prefix, node.router_id))
            .map(|(_, source)| source)
            .collect();
        for (i, a) in sources.iter().enumerate() {
            for b in &sources[i + 1..] {
                assert!(!a.conflicts_with(b), "node {from}: {a:?} and {b:?}");
            }
        }
    }

    /// Sends a packet output by node `from` over the link, if it is up, applies a route output
    /// to its forwarding table, or records a report, returning whether the table changed.
    fn process_output(&mut self, from: usize, output: Output) -> bool {
        let (prefix, entry) = match output {
            Output::Packet(dst, packet) => {
                self.transmit(from, self.index(from, dst), packet);
                return false;
            }
            Output::RouteSelect(prefix, neigh) => (prefix, Some(Fib::Via(self.index(from, neigh)))),
            Output::RouteHold(prefix) => (prefix, Some(Fib::Unreachable)),
            Output::RouteRemove(prefix) => (prefix, None),
            Output::ConflictAlert {
                prefix,
                from: neigh,
                kind,
            } => {
                self.reports.push(Report {
                    time: self.now,
                    node: from,
                    prefix,
                    from: self.index(from, neigh),
                    kind,
                });
                return false;
            }
        };

        let fib = &mut self.fibs[from];
        let old = fib.get(&prefix).copied();
        match entry {
            Some(Fib::Via(_)) => assert_ne!(old, entry, "route should change"),
            Some(Fib::Unreachable) => assert_matches!(old, Some(Fib::Via(_))),
            None => assert!(old.is_some(), "route to remove should exist"),
        }
        match entry {
            Some(entry) => fib.insert(prefix, entry),
            None => fib.remove(&prefix),
        };

        self.fib_changes.push(FibChange {
            time: self.now,
            node: from,
            prefix,
            entry,
        });
        true
    }

    /// Sends a packet over a link, if it is up, timestamping it as it is sent.
    fn transmit(&mut self, from: usize, to: usize, mut packet: Packet) {
        if let Some(&latency) = self.links.get(&(from, to))
            && let Some(mut packet) = (self.filter)(from, to, packet.clone())
        {
            let mut arrival = self.now + latency;
            if self.jitter.is_zero() {
                // Not before the previous packet, should the latency have dropped since.
                let last = self.last_arrivals.entry((from, to)).or_insert(arrival);
                arrival = arrival.max(*last);
                *last = arrival;
            } else {
                arrival += self.jitter.mul_f64(rand::random());
            }
            let key = (arrival, self.transmitted);
            let buf = packet.timestamp(self.now).into();
            self.in_flight.insert(key, Event::Arrival(from, to, buf));
            self.transmitted += 1;
        }
        self.sent.push(Sent {
            time: self.now,
            from,
            to,
            buf: packet.timestamp(self.now).into(),
        });
    }

    /// Returns the nodes that a packet to `dst` goes through from node `i`,
    /// starting with node `i`, and ending where it is delivered or dropped.
    /// Each node forwards it by the longest matching prefix, whether local or in
    /// its forwarding table, and drops it if that is unreachable.
    fn path(&self, i: usize, dst: IpAddr) -> Vec<usize> {
        let mut path = vec![i];
        loop {
            let j = *path.last().unwrap();
            let longest = |prefixes: &mut dyn Iterator<Item = &IpNet>| {
                prefixes
                    .filter(|prefix| prefix.contains(&dst))
                    .map(IpNet::prefix_len)
                    .max()
            };
            let local = self.locals.get(j).and_then(|l| longest(&mut l.iter()));
            let route = self.fibs.get(j).and_then(|fib| {
                let plen = longest(&mut fib.keys())?;
                fib.iter()
                    .find(|(p, _)| p.prefix_len() == plen && p.contains(&dst))
            });

            match route {
                Some((prefix, &Fib::Via(k))) if local < Some(prefix.prefix_len()) => {
                    assert!(
                        !path.contains(&k),
                        "forwarding loop to {dst}: {path:?}, {k}"
                    );
                    path.push(k);
                }
                _ => return path,
            }
        }
    }

    /// Returns the node that a packet to `dst` from node `i` is delivered to, if any.
    fn delivered_to(&self, i: usize, dst: IpAddr) -> Option<usize> {
        let j = *self.path(i, dst).last().unwrap();
        let local = self
            .locals
            .get(j)?
            .iter()
            .any(|prefix| prefix.contains(&dst));
        local.then_some(j)
    }

    fn assert_loop_free(&self) {
        let prefixes = self.fibs.iter().flat_map(HashMap::keys);
        let prefixes: HashSet<_> = prefixes.chain(self.locals.iter().flatten()).collect();
        for prefix in prefixes {
            for i in 0..self.nodes.len() {
                self.path(i, prefix.addr());
            }
        }
    }

    fn fib(&self, i: usize, prefix: IpNet) -> Option<Fib> {
        self.fibs[i].get(&prefix).copied()
    }

    /// Returns node `i`'s entry for node `j`.
    fn neigh(&self, i: usize, j: usize) -> &NeighEntry {
        &self.nodes[i].neigh_table[self.key(i, j)]
    }

    /// Returns node `i`'s rxcost, txcost and link cost for node `j`.
    fn costs(&self, i: usize, j: usize) -> (u16, u16, u16) {
        let neigh = self.neigh(i, j);
        (neigh.rxcost(), neigh.txcost, neigh.cost)
    }
}

/// Decodes the TLVs of a packet, which should all decode cleanly, leaving out Updates.
fn tlvs(buf: &[u8]) -> Vec<Tlv> {
    PacketDecoder::new(buf)
        .expect("packet should be well-formed")
        .filter_map(|item| match item.expect("TLV should decode") {
            PacketItem::Tlv(tlv) => Some(tlv),
            PacketItem::Update(_) => None,
        })
        .collect()
}

/// Decodes the Updates of a packet, which should all decode cleanly.
fn updates(buf: &[u8]) -> Vec<Update> {
    PacketDecoder::new(buf)
        .expect("packet should be well-formed")
        .filter_map(|item| match item.expect("TLV should decode") {
            PacketItem::Tlv(_) => None,
            PacketItem::Update(update) => Some(update),
        })
        .collect()
}

/// Checks whether a packet is a startup packet, which is the only one to ask for an
/// acknowledgement.
fn is_startup(buf: &[u8]) -> bool {
    (tlvs(buf).iter()).any(|tlv| matches!(tlv, Tlv::AcknowledgementRequest { .. }))
}

/// Has the first two startup packets from now on lost, for example while there is no session yet.
fn lose_first_two_startup_packets(net: &mut Net) {
    thread_local! {
        static LOST: Cell<u32> = const { Cell::new(0) };
    }
    LOST.set(0);
    net.filter = |_, _, packet| {
        let lost = is_startup(packet.as_bytes()) && LOST.replace(LOST.get() + 1) < 2;
        (!lost).then_some(packet)
    };
}

/// Builds a packet with the given body.
fn packet(body: &[u8]) -> Vec<u8> {
    let mut buf = vec![42, 2];
    buf.extend((body.len() as u16).to_be_bytes());
    buf.extend(body);
    buf
}

/// Builds a packet with a Route Request.
fn route_request(ae: Ae, plen: u8, prefix: &[u8]) -> Vec<u8> {
    packet(&[&[9, 2 + prefix.len() as u8, ae as u8, plen], prefix].concat())
}

/// Returns the Prefix field that carries a prefix in a TLV.
fn octets(prefix: IpNet) -> [u8; 16] {
    encode_prefix(prefix, Ae::Ipv4).2
}

/// Builds an Update for a prefix, with AE 4 for an IPv4 one.
fn update(prefix: IpNet, router_id: u64, seqno: u16, metric: u16, interval: u16) -> Update {
    let (ae, plen, prefix) = encode_prefix(prefix, Ae::V4ViaV6);
    Update {
        ae,
        plen,
        interval: Interval::new(interval).unwrap(),
        seqno: Seqno::new(seqno),
        metric,
        prefix,
        router_id: RouterId::new(router_id),
        nonexclusive: false,
    }
}

/// Returns an update as [`update`] does, marked nonexclusive, so that updates for the prefix from
/// other router-ids don't conflict with it, as in the tests that move between sources.
fn nonexclusive_update(
    prefix: IpNet,
    router_id: u64,
    seqno: u16,
    metric: u16,
    interval: u16,
) -> Update {
    Update {
        nonexclusive: true,
        ..update(prefix, router_id, seqno, metric, interval)
    }
}

/// Returns whether an Update is for the given prefix.
fn is_for(update: &Update, prefix: IpNet) -> bool {
    decode_prefix(update.ae, update.plen, update.prefix) == Some(prefix)
}

/// Re-encodes a packet without its retractions.
fn without_retractions(packet: Packet) -> Packet {
    let buf = packet.as_bytes();
    let mut encoder = PacketEncoder::new(buf.len() + 512);
    for item in PacketDecoder::new(buf).unwrap() {
        match item.unwrap() {
            PacketItem::Update(update) if update.metric == METRIC_INFINITY => {}
            PacketItem::Update(update) => assert!(encoder.put_update(&update)),
            // Router-ids are established along with the updates.
            PacketItem::Tlv(Tlv::RouterId { .. }) => {}
            PacketItem::Tlv(tlv) => assert!(encoder.put_tlv(&tlv)),
        }
    }
    encoder.finalize()
}

/// A neighbour outside the simulation, whose packets a test scripts.
struct Scripted {
    index: usize,
    hello_seqno: Seqno,
    /// The rxcost of the IHU sent with each Hello, or `None` to send no IHU.
    rxcost: Option<u16>,
}

impl Scripted {
    fn new(index: usize) -> Self {
        Self {
            index,
            hello_seqno: Seqno::new(0),
            rxcost: Some(NOMINAL_COST),
        }
    }

    /// Sends node `to` a packet built by [`Self::packet`].
    fn send(&mut self, net: &mut Net, to: usize, updates: &[Update]) {
        let buf = self.packet(updates);
        net.inject(self.index, to, &buf);
    }

    /// Builds a packet with the given updates, followed by a scheduled Hello and an
    /// IHU with `self.rxcost`, if any. With the nominal rxcost, the neighbour stays up
    /// if one is sent every 4 s.
    fn packet(&mut self, updates: &[Update]) -> Vec<u8> {
        let mut encoder = PacketEncoder::new(1400);
        for update in updates {
            assert!(encoder.put_update(update));
        }
        let hello = Tlv::Hello {
            seqno: self.hello_seqno,
            interval: Interval::new(400),
            transmit_timestamp: None,
        };
        assert!(encoder.put_tlv(&hello));
        if let Some(rxcost) = self.rxcost {
            assert!(encoder.put_tlv(&ihu(rxcost)));
        }
        self.hello_seqno += 1;
        encoder.finalize().as_bytes().to_vec()
    }
}

#[test]
fn link_cost() {
    // Each row gives the Hello history bits, the txcost and the RTT in milliseconds,
    // followed by the expected rxcost and link cost.
    #[rustfmt::skip]
    let rows = [
        // At least two of the last three Hellos make the rxcost finite.
        (0b111, 96, None, NOMINAL_COST, 96),
        (0b011, 96, None, NOMINAL_COST, 96),
        (0b101, 96, None, NOMINAL_COST, 96),
        (0b110, 96, None, NOMINAL_COST, 96),
        (0b001, 96, None, INF, INF),
        (0b100, 96, None, INF, INF),
        (0b1111_1000, 96, None, INF, INF),
        // The link cost is the txcost, but strictly positive.
        (0b111, 256, None, NOMINAL_COST, 256),
        (0b111, 0, None, NOMINAL_COST, 1),
        (0b111, INF, None, NOMINAL_COST, INF),
        // The RTT adds up to 150 to it, linearly from 10 to 120 ms.
        (0b111, 96, Some(-1.0), NOMINAL_COST, 96),
        (0b111, 96, Some(10.0), NOMINAL_COST, 96),
        (0b111, 96, Some(65.0), NOMINAL_COST, 96 + 75),
        (0b111, 96, Some(120.0), NOMINAL_COST, 96 + 150),
        (0b111, 96, Some(1000.0), NOMINAL_COST, 96 + 150),
        (0b111, 256, Some(65.0), NOMINAL_COST, 256 + 75),
        (0b111, INF - 100, Some(1000.0), NOMINAL_COST, INF),
        (0b100, 96, Some(65.0), INF, INF),
    ];

    for (bits, txcost, rtt_ms, rxcost, cost) in rows {
        let mut neigh = NeighEntry::new(&Params::new(), Seqno::new(0));

        // Receive or miss a Hello for each bit, the most recent last.
        for (i, seqno) in (0..16).rev().zip(0..) {
            let _ = match bits >> i & 1 {
                1 => neigh.hello_history.received(Seqno::new(seqno)),
                _ => neigh.hello_history.missed(),
            };
        }
        assert_eq!(neigh.hello_history.bits(), bits);

        neigh.txcost = txcost;
        neigh.rtt = rtt_ms.map(|rtt: f64| rtt * 1000.0);
        neigh.update_cost();

        let row = (bits, txcost, rtt_ms);
        assert_eq!((neigh.rxcost(), neigh.cost), (rxcost, cost), "{row:?}");
    }
}

#[test]
fn snapshots_show_what_a_link_cost_is_made_of() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::from_millis(30));

    let snapshot = net.nodes[0].snapshot(net.now, |key| key);
    let neigh = &snapshot.neighbours[0];
    assert!(neigh.in_startup);
    assert_eq!((neigh.rxcost, neigh.txcost, neigh.cost), (INF, INF, INF));
    assert_eq!((neigh.rtt_penalty, neigh.hello_history), (0, 0));

    net.run_for(Duration::from_secs(60));

    // The RTT is 60 ms, as in `neighbours_acquire_each_other`.
    let snapshot = net.nodes[0].snapshot(net.now, |key| key);
    let neigh = &snapshot.neighbours[0];
    assert!(!neigh.in_startup);
    assert_eq!((neigh.rxcost, neigh.txcost), (NOMINAL_COST, NOMINAL_COST));
    assert_eq!((neigh.rtt_penalty, neigh.cost), (68, 164));
    assert_eq!(neigh.hello_history & 0b111, 0b111);
}

#[test]
fn neighbours_acquire_each_other() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::from_millis(30));
    net.run_for(Duration::from_secs(20));

    // An RTT of 60 ms adds 150 × (60 − 10) / (120 − 10) ≈ 68 to the link cost
    // (RFC 9616 §4.2), but not to the rxcost sent to the neighbour. The link
    // then stays up at that cost.
    for _ in 0..60 {
        net.run_for(Duration::from_secs(1));
        for (i, j) in [(0, 1), (1, 0)] {
            assert_eq!(net.neigh(i, j).rtt.map(f64::round), Some(60_000.0));
            assert_eq!(net.costs(i, j), (NOMINAL_COST, NOMINAL_COST, 164));
        }
    }
}

#[test]
fn hellos_and_ihus_follow_the_rfcs() {
    const LATENCY: Duration = Duration::from_millis(30);

    let mut net = Net::new(2);
    net.connect(0, 1, LATENCY);
    net.run_for(Duration::from_secs(60));

    /// Returns the seqno, interval and transmit timestamp of the Hellos among TLVs, other than
    /// the far one of a startup packet, which has neither an interval nor a timestamp.
    fn hellos(tlvs: &[Tlv]) -> Vec<(Seqno, Option<Interval>, Option<u32>)> {
        let hellos = tlvs.iter().filter_map(|tlv| match *tlv {
            Tlv::Hello {
                interval: None,
                transmit_timestamp: None,
                ..
            } => None,
            Tlv::Hello {
                seqno,
                interval,
                transmit_timestamp,
            } => Some((seqno, interval, transmit_timestamp)),
            _ => None,
        });
        hellos.collect()
    }

    // The transmit timestamps of node 1's timestamped Hellos, and when they arrived
    // at node 0.
    let neighbour_hellos: Vec<_> = (net.sent.iter())
        .filter(|sent| sent.from == 1)
        .flat_map(|sent| {
            let arrival = sent.time + LATENCY;
            let hellos = hellos(&tlvs(&sent.buf)).into_iter();
            hellos.filter_map(move |(.., t)| Some((t?, arrival)))
        })
        .collect();
    let (_, first_arrival) = neighbour_hellos[0];

    // The seqnos of node 0's Hellos.
    let mut sent_hellos: Vec<Seqno> = Vec::new();
    let mut sent_ihus = 0;

    for sent in net.sent.iter().filter(|sent| sent.from == 0) {
        let tlvs = tlvs(&sent.buf);

        // A packet carries at most one Hello (RFC 8966 §4.6.5), timestamped when it
        // is sent (RFC 9616 §3.2), with the seqno incremented for every Hello.
        let hellos = hellos(&tlvs);
        assert!(hellos.len() <= 1, "packet should carry at most one Hello");

        if let Some(&(seqno, interval, transmit_timestamp)) = hellos.first() {
            // A Hello that only carries an unscheduled IHU has no interval.
            assert!(interval == Interval::new(400) || interval.is_none());
            let transmit_timestamp = transmit_timestamp.expect("Hello should be timestamped");
            assert_eq!(transmit_timestamp, timestamp(sent.time));

            if let Some(&first_seqno) = sent_hellos.first() {
                assert_eq!(seqno, first_seqno + sent_hellos.len() as u16);
            }
            sent_hellos.push(seqno);
        }

        for tlv in &tlvs {
            let Tlv::Ihu {
                ae,
                rxcost,
                interval,
                origin_receive_timestamps,
                ..
            } = *tlv
            else {
                continue;
            };
            sent_ihus += 1;

            // The rxcost comes from 2-out-of-3 link sensing, leaving out the RTT.
            assert_eq!(ae, Ae::Wildcard);
            assert!(rxcost == NOMINAL_COST || rxcost == INF);
            assert_eq!(interval, Interval::new(1200).unwrap());

            match origin_receive_timestamps {
                // A timestamped IHU is sent along with a timestamped Hello, and echoes
                // the timestamps of a Hello from the neighbour, sent one latency
                // before it arrived (RFC 9616 §3.2).
                Some((origin, receive)) => {
                    assert_eq!(hellos.len(), 1);
                    assert!(neighbour_hellos.iter().any(|&(t, _)| t == origin));
                    assert_eq!(receive.wrapping_sub(origin), LATENCY.as_micros() as u32);
                }
                // Once a timestamped Hello has arrived, IHUs MUST carry timestamps
                // (RFC 9616 §3.2), apart from those buffered already, which are sent
                // within half a Hello interval (RFC 8966 §3.1).
                None => assert!(sent.time < first_arrival + Duration::from_secs(2)),
            }
        }
    }

    assert!(sent_hellos.len() >= 14 && sent_ihus >= 4);
}

#[test]
fn neighbours_are_sent_hellos_and_dumps_on_schedules_of_their_own() {
    let p = prefix("fd00::/64");
    let mut net = Net::new(1);
    net.originate(0, p);
    net.add_neighbour(0, 8);
    net.run_for(Duration::from_secs(6));
    net.add_neighbour(0, 9);
    let added = [(8, net.now - Duration::from_secs(6)), (9, net.now)];
    net.run_for(Duration::from_secs(64));

    // Each neighbour is on a point-to-point link of its own, so it is sent Hellos with
    // consecutive seqnos of its own (RFC 8966 §3.4.1). With timers not randomized, it is sent
    // one every Hello interval and a full dump every Update interval, both counted from when
    // it was added, and each sent after the 0.75 to 1.25 s for which TLVs are buffered. The
    // Hello in its startup packet, acknowledged at once here, comes before all of those.
    let buffered = Duration::from_millis(750)..Duration::from_millis(1250);
    for (j, added) in added {
        let sent: Vec<_> = (net.sent.iter())
            .filter(|sent| (sent.from, sent.to) == (0, j) && !is_startup(&sent.buf))
            .collect();

        let hellos: Vec<_> = (sent.iter())
            .flat_map(|sent| {
                let time = sent.time;
                let hellos = tlvs(&sent.buf).into_iter().filter_map(|tlv| match tlv {
                    Tlv::Hello {
                        seqno,
                        interval: Some(_),
                        ..
                    } => Some(seqno),
                    _ => None,
                });
                hellos.map(move |seqno| (time, seqno))
            })
            .collect();
        assert!(hellos.len() >= 15);
        for (i, &(time, seqno)) in hellos.iter().enumerate() {
            assert_eq!(seqno, hellos[0].1 + i as u16);
            let due = added + Duration::from_secs(4) * i as u32;
            assert!(buffered.contains(&(time - due)));
        }

        let dumps: Vec<_> = (sent.iter())
            .filter(|sent| updates(&sent.buf).iter().any(|update| is_for(update, p)))
            .map(|sent| sent.time)
            .collect();
        assert!(dumps.len() >= 4);
        for (i, &time) in dumps.iter().enumerate() {
            let due = added + Duration::from_secs(16) * i as u32;
            assert!(buffered.contains(&(time - due)));
        }
    }
}

#[test]
fn hellos_and_full_dumps_are_spread_out_by_default() {
    const NEIGHS: usize = 50;
    let p = prefix("fd00::/64");
    let mut net = Net::new(1);
    net.nodes[0] = State::new(net.now, Params::new(), RouterId::new(1).unwrap(), None);
    net.originate(0, p);
    let added = net.now;
    for j in 1..=NEIGHS {
        net.add_neighbour(0, j);
    }
    net.run_for(Duration::from_hours(1));

    let secs = Duration::from_secs_f64;
    let mut phases = [vec![], vec![]];
    let mut drifts = [vec![], vec![]];
    for j in 1..=NEIGHS {
        // When node 0 sent neighbour `j` each of its Hellos, and each of its updates for P,
        // which a packet carries more than one of if two full dumps share it.
        let (mut hellos, mut dumps) = (vec![], vec![]);
        for sent in net
            .sent
            .iter()
            .filter(|sent| (sent.from, sent.to) == (0, j) && !is_startup(&sent.buf))
        {
            let tlvs = tlvs(&sent.buf);
            let count = tlvs
                .iter()
                .filter(|tlv| matches!(tlv, Tlv::Hello { .. }))
                .count();
            assert!(count <= 1, "packet should carry at most one Hello");
            hellos.extend(iter::repeat_n(sent.time, count));
            let count = updates(&sent.buf)
                .iter()
                .filter(|update| is_for(update, p))
                .count();
            dumps.extend(iter::repeat_n(sent.time, count));
        }

        // With the default timers, the first Hello and full dump are put at once, the second
        // a random part of the interval later, and each one after that 0.96875 to 1.03125
        // intervals after the one before. Each is sent within 1.25 s, as TLVs are buffered.
        for (i, (times, interval)) in [(hellos, secs(4.0)), (dumps, secs(16.0))]
            .iter()
            .enumerate()
        {
            assert!(times[0] - added <= secs(1.25));
            let phase = times[1] - times[0];
            assert!(phase <= *interval + secs(1.25));
            phases[i].push(phase);
            let bounds =
                interval.mul_f64(0.96875) - secs(1.25)..interval.mul_f64(1.03125) + secs(1.25);
            assert!(
                times[1..]
                    .windows(2)
                    .all(|pair| bounds.contains(&(pair[1] - pair[0])))
            );

            // How far the last has drifted from where fixed intervals would have put it.
            let last = times.len() - 1;
            let fixed = times[1] + *interval * (last - 1) as u32;
            drifts[i].push(times[last].max(fixed) - times[last].min(fixed));
        }
    }

    // The second Hellos and full dumps to the neighbours, added together, are spread over
    // their intervals, and the ones after them drift apart, by more than the 1.25 s that
    // buffering alone can account for.
    for (i, interval) in [secs(4.0), secs(16.0)].into_iter().enumerate() {
        assert!(phases[i].iter().any(|&phase| phase < interval / 2));
        assert!(phases[i].iter().any(|&phase| phase > interval / 2));
        assert!(drifts[i].iter().any(|&drift| drift > secs(1.5)));
    }
}

#[test]
fn one_way_loss_makes_link_unusable() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));

    // Node 0 stops hearing node 1. Two missed Hellos make its rxcost infinite,
    // which its next IHU tells node 1, and the IHU hold time makes its txcost
    // infinite.
    let latency = net.links.remove(&(1, 0)).unwrap();
    net.run_for(Duration::from_secs(45));
    assert_eq!(net.costs(0, 1), (INF, INF, INF));
    assert_eq!(net.costs(1, 0), (NOMINAL_COST, INF, INF));

    net.links.insert((1, 0), latency);
    net.run_for(Duration::from_secs(30));
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

#[test]
fn silent_neighbour_is_flushed_and_reacquired() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));

    // 16 missed Hellos empty the history, which flushes the neighbour entry.
    let links = std::mem::take(&mut net.links);
    net.run_for(Duration::from_secs(80));
    for (i, j) in [(0, 1), (1, 0)] {
        let neigh = net.neigh(i, j);
        assert_eq!(neigh.hello_history.bits(), 0);
        assert_eq!((neigh.txcost, neigh.rtt), (INF, None));
        assert!(neigh.incoming_hello_timer_key.is_none() && neigh.incoming_ihu_timer_key.is_none());
    }

    net.links = links;
    net.run_for(Duration::from_secs(30));
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

#[test]
fn removed_neighbour_leaves_nothing_behind() {
    let now = Instant::now();
    let mut node = state(0, now);
    let key = node.add_neighbour(now);

    // Its startup packet hasn't been polled yet, and the timer to send it again is running.
    node.remove_neighbour(now, key);

    assert!(node.poll_output().is_none());
    assert_eq!(node.poll_timeout(), None);
    assert!(node.snapshot(now, |key| key).neighbours.is_empty());
}

#[test]
fn removed_neighbour_is_sent_nothing_more() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));

    net.disconnect(0, 1);
    let start = net.now;
    net.run_for(Duration::from_secs(120));
    assert!(!net.sent.iter().any(|sent| sent.time >= start));
}

#[test]
fn routes_through_the_only_removed_neighbour_are_held_at_once() {
    let p = prefix("fd00:1::/64");
    let mut net = Net::new(2);
    net.originate(1, p);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));
    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));

    net.disconnect(0, 1);
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    let hold_time = params().get(DurationKey::RouteHoldTime);
    net.run_for(hold_time + Duration::from_secs(1));
    assert_eq!(net.fib(0, p), None);
}

#[test]
fn routes_through_a_removed_neighbour_move_to_another() {
    // Node 0 reaches node 3 through node 1 and node 2.
    let p = prefix("fd00:3::/64");
    let mut net = Net::new(4);
    net.originate(3, p);
    for (a, b) in [(0, 1), (0, 2), (1, 3), (2, 3)] {
        net.connect(a, b, Duration::from_millis(10));
    }
    net.run_for(Duration::from_secs(60));
    let Some(Fib::Via(selected)) = net.fib(0, p) else {
        panic!("node 0 should have a route");
    };

    net.disconnect(0, selected);
    net.run_for(Duration::from_secs(5));
    assert_eq!(net.fib(0, p), Some(Fib::Via(3 - selected)));
}

#[test]
fn removed_neighbour_is_reacquired_when_added_again() {
    let p = prefix("fd00:1::/64");
    let q = prefix("fd00:2::/64");
    let mut net = Net::new(2);
    net.originate(0, q);
    net.originate(1, p);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));
    let old_key = net.key(0, 1);

    net.disconnect(0, 1);
    net.run_for(Duration::from_secs(120));

    net.connect(0, 1, Duration::ZERO);
    assert_ne!(net.key(0, 1), old_key);
    net.run_for(Duration::from_secs(31));
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));
    assert_eq!(net.fib(1, q), Some(Fib::Via(0)));
}

#[test]
fn rebooted_neighbour_is_reacquired() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));

    // Node 1 reboots, and its Hello seqno jumps.
    let hello_seqno = net.neigh(1, 0).hello_seqno + 1000;
    net.restart(1, state(1, net.now));
    net.add_neighbour_with_hello_seqno(1, 0, hello_seqno);

    // Its startup packet flushes node 0's entry for it, restarting the history.
    net.run_for(Duration::from_millis(1));
    let neigh = net.neigh(0, 1);
    assert_eq!(neigh.hello_history.bits(), 0b1);
    assert_eq!((neigh.txcost, neigh.rtt), (INF, None));

    net.run_for(Duration::from_secs(30));
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

/// Builds an IHU with the given rxcost.
fn ihu(rxcost: u16) -> Tlv {
    Tlv::Ihu {
        ae: Ae::Wildcard,
        rxcost,
        interval: Interval::new(1200).unwrap(),
        address: [0; 8],
        origin_receive_timestamps: None,
    }
}

#[test]
fn rebooted_neighbour_routes_wait_for_the_link() {
    let p = prefix("fd00:1::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));

    // Node 1 reboots, its Hello seqno jumps, and it originates P. It sends node 0 a startup packet
    // at once (see `State::add_neighbour`), which flushes node 0's entry for it, and once that is
    // acknowledged, a packet with a Hello and an update for P.
    let hello_seqno = net.neigh(1, 0).hello_seqno + 1000;
    net.restart(1, state(1, net.now));
    net.add_neighbour_with_hello_seqno(1, 0, hello_seqno);
    net.originate(1, p);
    let changes = net.fib_changes.len();

    // Routes are selected once the whole packet has been handled, when the link cost is
    // infinite. It stays so until node 0 has received enough Hellos and an IHU, so node 0
    // selects the route only then, and never briefly before.
    net.run_for(Duration::from_secs(30));
    let entries: Vec<_> = net.fib_changes[changes..]
        .iter()
        .filter(|change| (change.node, change.prefix) == (0, p))
        .map(|change| change.entry)
        .collect();
    assert_eq!(entries, [Some(Fib::Via(1))]);
}

#[test]
fn rebooted_neighbour_old_routes_are_held_at_its_first_packet() {
    let p = prefix("fd00:1::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.originate(1, p);
    net.run_for(Duration::from_secs(31));
    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));

    // Node 1 reboots without P, and its Hello seqno jumps.
    let hello_seqno = net.neigh(1, 0).hello_seqno + 1000;
    net.restart(1, state(1, net.now));
    net.add_neighbour_with_hello_seqno(1, 0, hello_seqno);
    net.locals[1].clear();

    // It sends node 0 a startup packet at once (see `State::add_neighbour`), whose retraction
    // removes node 0's route to P through it, learnt before the reboot, so P is held at once.
    net.run_for(Duration::from_millis(1));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    assert!(
        net.nodes[0].route_table.prefix_entries[&p]
            .routes
            .is_empty()
    );

    // Its Hellos flush node 0's entry for it, so the link cost is infinite as well.
    assert_eq!(net.costs(0, 1).2, INF);
}

#[test]
fn added_neighbours_are_sent_a_startup_packet_alone_at_once() {
    // Node 0 has been running for a while, and has learnt a route from neighbour 9, when it
    // adds neighbour 8. The startup packet for neighbour 8 goes in a packet of its own, at once,
    // rather than with the next packet, up to 1.25 s later (see `State::add_neighbour`).
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(1);
    net.add_neighbour(0, 9);
    let mut n9 = Scripted::new(9);
    for _ in 0..4 {
        n9.send(&mut net, 0, &[update(p, 42, 1, 100, 0x8000)]);
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    let start = net.now;
    net.add_neighbour_unacknowledged(0, 8);
    let sent: Vec<_> = (net.sent.iter())
        .filter(|sent| sent.from == 0 && sent.time >= start)
        .collect();
    let [sent] = sent[..] else {
        panic!("node 0 should send exactly one packet");
    };
    assert_eq!(sent.to, 8);
    let items: Vec<_> = (PacketDecoder::new(&sent.buf).unwrap())
        .map(Result::unwrap)
        .collect();
    let [
        PacketItem::Update(retraction),
        PacketItem::Tlv(Tlv::Hello {
            seqno: far_seqno,
            interval: None,
            transmit_timestamp: None,
        }),
        PacketItem::Tlv(Tlv::Hello {
            seqno,
            interval,
            transmit_timestamp: Some(_),
        }),
        PacketItem::Tlv(Tlv::AcknowledgementRequest {
            interval: within, ..
        }),
    ] = &items[..]
    else {
        panic!("the packet should have a retraction, two Hellos and a request only: {items:?}");
    };
    assert_eq!(
        (retraction.ae, retraction.metric),
        (Ae::Wildcard, METRIC_INFINITY)
    );
    assert_eq!(*interval, Interval::new(400));
    assert_eq!(*far_seqno, *seqno + FAR_HELLO_SEQNO_OFFSET);
    assert_eq!(within.to_duration(), Duration::from_millis(10));
}

#[test]
fn startup_packets_are_sent_again_until_acknowledged() {
    let mut net = Net::new(1);
    let added = net.now;
    net.add_neighbour_unacknowledged(0, 9);
    net.run_for(Duration::from_secs(20));

    // They go out with new Hello seqnos, 0.25 s after the first, then twice as long each time,
    // up to the Hello interval, with nothing else in between.
    let sent: Vec<_> = (net.sent.iter()).filter(|sent| sent.to == 9).collect();
    assert!(sent.iter().all(|sent| is_startup(&sent.buf)));
    let times: Vec<_> = (sent.iter())
        .map(|sent| (sent.time - added).as_millis())
        .collect();
    assert_eq!(times, [0, 250, 750, 1750, 3750, 7750, 11750, 15750, 19750]);
    let opaques: HashSet<_> = (sent.iter())
        .flat_map(|sent| tlvs(&sent.buf))
        .filter_map(|tlv| match tlv {
            Tlv::AcknowledgementRequest { opaque, .. } => Some(opaque),
            _ => None,
        })
        .collect();
    assert_eq!(opaques.len(), 1);
    let scheduled_seqnos: Vec<_> = (sent.iter())
        .flat_map(|sent| tlvs(&sent.buf))
        .filter_map(|tlv| match tlv {
            Tlv::Hello {
                seqno,
                interval: Some(_),
                ..
            } => Some(seqno),
            _ => None,
        })
        .collect();
    for pair in scheduled_seqnos.windows(2) {
        assert_eq!(pair[1], pair[0] + 1);
    }

    // Once acknowledged, it gets the first Hello, a request for a full dump, and the first full
    // dump, and no more startup packets.
    let p = prefix("fd00::/64");
    net.originate(0, p);
    let start = net.now;
    net.acknowledge_startup(0, 9);
    net.run_for(Duration::from_secs(2));
    let sent: Vec<_> = (net.sent.iter())
        .filter(|sent| sent.to == 9 && sent.time >= start)
        .collect();
    assert!(sent.iter().all(|sent| !is_startup(&sent.buf)));
    let tlvs_sent: Vec<_> = sent.iter().flat_map(|sent| tlvs(&sent.buf)).collect();
    assert_matches!(
        tlvs_sent[0],
        Tlv::Hello {
            interval: Some(_),
            ..
        }
    );
    assert_matches!(
        tlvs_sent[1],
        Tlv::RouteRequest {
            ae: Ae::Wildcard,
            ..
        }
    );
    assert!(updates_sent(&net, 0, 9, start).iter().any(|u| is_for(u, p)));
}

#[test]
fn nothing_but_acknowledgements_is_taken_in_during_startup() {
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(1);
    net.add_neighbour_unacknowledged(0, 9);
    let mut n9 = Scripted::new(9);

    for _ in 0..4 {
        n9.send(&mut net, 0, &[update(p, 42, 1, 100, 0x8000)]);
        net.run_for(Duration::from_millis(100));
    }
    assert_eq!(net.fib(0, p), None);
    assert!(net.nodes[0].route_table.prefix_entries.is_empty());
    let neigh = net.neigh(0, 9);
    assert_eq!(neigh.hello_history.bits(), 0);
    assert_eq!(neigh.txcost, INF);

    // A request for an acknowledgement is answered, within its deadline, or two nodes starting up
    // together would wait for each other forever.
    let start = net.now;
    let request = Tlv::AcknowledgementRequest {
        opaque: 77,
        interval: Interval::new(1).unwrap(),
    };
    net.inject_tlv(9, 0, &request);
    net.run_for(Duration::from_millis(10));
    let answers = tlvs_sent(&net, 0, 9, start);
    assert!(answers.contains(&Tlv::Acknowledgement { opaque: 77 }));

    // An acknowledgement of something else changes nothing.
    let opaque = net.startup_opaque(0, 9).wrapping_add(1);
    net.inject_tlv(9, 0, &Tlv::Acknowledgement { opaque });
    assert!(net.neigh(0, 9).startup.is_some());

    // Once acknowledged, everything is taken in again.
    net.acknowledge_startup(0, 9);
    for _ in 0..3 {
        n9.send(&mut net, 0, &[update(p, 42, 1, 100, 0x8000)]);
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

/// A neighbour's IHU can be waiting in its buffer with an echo from before this node restarted,
/// and it leaves with the acknowledgement at the latest, in the same packet at the latest.
#[test]
fn the_packet_with_the_acknowledgement_is_discarded_with_any_echo_in_it() {
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(1);
    net.add_neighbour_unacknowledged(0, 9);
    let opaque = net.startup_opaque(0, 9);

    let now = timestamp(net.now);
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(p, 42, 1, 100, 0x8000)));
    let tlvs = [
        Tlv::Hello {
            seqno: Seqno::new(5),
            interval: Interval::new(400),
            transmit_timestamp: Some(0),
        },
        // An echo from 20 s ago, a little after which the neighbour heard it.
        Tlv::Ihu {
            ae: Ae::Wildcard,
            rxcost: NOMINAL_COST,
            interval: Interval::new(1200).unwrap(),
            address: [0; 8],
            origin_receive_timestamps: Some((now.wrapping_sub(20_000_000), 1000)),
        },
        Tlv::Acknowledgement { opaque },
    ];
    assert!(encoder.put_tlvs(&tlvs));
    let mut packet = encoder.finalize();
    net.inject(9, 0, packet.timestamp(net.now));

    let neigh = net.neigh(0, 9);
    assert!(neigh.startup.is_none());
    assert_eq!(neigh.rtt, None);
    assert_eq!(neigh.txcost, INF);
    assert_eq!(neigh.hello_history.bits(), 0);
    assert_eq!(neigh.origin_receive_timestamps, None);
    assert_eq!(net.fib(0, p), None);
}

#[test]
fn neighbours_are_sent_nothing_else_during_startup() {
    // Node 0 learns P from neighbour 9, and tells neighbour 7, but neighbour 8 hasn't acknowledged
    // its startup packet, and whatever it were told, the next one would retract.
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(1);
    net.add_neighbour(0, 7);
    net.add_neighbour(0, 9);
    net.add_neighbour_unacknowledged(0, 8);
    let (mut n7, mut n9) = (Scripted::new(7), Scripted::new(9));
    for _ in 0..4 {
        n7.send(&mut net, 0, &[]);
        n9.send(&mut net, 0, &[update(p, 42, 1, 100, 0x8000)]);
        net.run_for(Duration::from_secs(1));
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    assert!(
        updates_sent(&net, 0, 7, net.now - Duration::from_secs(4))
            .iter()
            .any(|u| is_for(u, p))
    );

    // It only hears of P on its acknowledgement, in the first full dump.
    let sent = (net.sent.iter()).filter(|sent| sent.to == 8);
    assert!(sent.into_iter().all(|sent| is_startup(&sent.buf)));
    let start = net.now;
    net.acknowledge_startup(0, 8);
    net.run_for(Duration::from_secs(2));
    assert!(updates_sent(&net, 0, 8, start).iter().any(|u| is_for(u, p)));
}

/// Requests that go to every neighbour leave it out as well, as its packets would be discarded.
#[test]
fn requests_to_every_neighbour_leave_out_those_in_startup() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near);
    net.add_neighbour_unacknowledged(0, 7);

    // Losing the route to P makes node 0 send a seqno request to every neighbour.
    let start = net.now;
    let retraction = update(p, 42, 1, METRIC_INFINITY, 0x8000);
    exchange(&mut net, &mut n8, &mut n9, 4, &[], from_ref(&retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    assert!(!requests_sent(&net, 0, 9, start).is_empty());
    assert_eq!(requests_sent(&net, 0, 7, start), []);
}

/// The first startup packets of both are lost, for example while there is no session yet, and they
/// cross on the way, so that each is asked for an acknowledgement while waiting for one.
#[test]
fn nodes_starting_together_acquire_each_other() {
    let p = prefix("fd00:1::/64");
    let mut net = Net::new(2);
    lose_first_two_startup_packets(&mut net);
    net.originate(1, p);
    net.connect(0, 1, Duration::from_millis(20));
    net.run_for(Duration::from_secs(30));

    assert!(net.neigh(0, 1).startup.is_none());
    assert!(net.neigh(1, 0).startup.is_none());
    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));
}

/// Without the two Hellos, this relied on the new seqno happening to be far from the old one.
#[test]
fn startup_flushes_a_neighbour_whatever_hello_seqno_it_expects() {
    for offset in [
        0, 1, 2, 16, 17, 1000, 0x7ffe, 0x7fff, 0x8000, 0x8001, 0x8002, 0xffff,
    ] {
        let mut net = Net::new(2);
        net.connect(0, 1, Duration::ZERO);
        net.run_for(Duration::from_secs(31));
        assert_eq!(net.costs(0, 1), UP);

        // Node 1 restarts, with its Hello seqno exactly where node 0 expects it, and so on.
        let expected = net.neigh(1, 0).hello_seqno;
        net.restart(1, state(1, net.now));
        net.add_neighbour_with_hello_seqno(1, 0, expected + offset);
        net.run_for(Duration::from_millis(1));

        let neigh = net.neigh(0, 1);
        assert_eq!(neigh.hello_history.bits(), 0b1, "{offset}");
        assert_eq!((neigh.txcost, neigh.rtt), (INF, None), "{offset}");
        assert_eq!(net.costs(0, 1).2, INF, "{offset}");

        net.run_for(Duration::from_secs(30));
        assert_eq!(net.costs(0, 1), UP, "{offset}");
        assert_eq!(net.costs(1, 0), UP, "{offset}");
    }
}

/// The network of `State`'s docs on reboots. Node 1 reboots while node 0 is out of reach, its first
/// startup packets are lost, and its Hello seqnos are close to the old ones, so nothing else would
/// tell its neighbours. It would select node 3's route, and packets would go round nodes 1, 3 and
/// 2, which `Net` panics at.
#[test]
fn no_loop_forms_when_a_reboot_goes_unnoticed_at_first() {
    let p = prefix("fd00:1::/64");
    let mut net = Net::new(4);
    for (a, b, ms) in [(0, 1, 10), (1, 2, 10), (2, 3, 10), (1, 3, 200)] {
        net.connect(a, b, Duration::from_millis(ms));
    }
    net.originate(0, p);
    net.run_for(Duration::from_secs(200));
    assert_eq!(net.path(3, p.addr()), [3, 2, 1, 0]);

    let (near2, near3) = (
        net.neigh(1, 2).hello_seqno + 1,
        net.neigh(1, 3).hello_seqno + 1,
    );
    net.links.remove(&(0, 1));
    net.links.remove(&(1, 0));
    lose_first_two_startup_packets(&mut net);
    net.restart(1, state(1, net.now));
    net.add_neighbour_with_hello_seqno(1, 2, near2);
    net.add_neighbour_with_hello_seqno(1, 3, near3);
    net.run_for(Duration::from_secs(60));

    assert_eq!(net.fib(1, p), None);
    assert_eq!(net.fib(2, p), Some(Fib::Unreachable));
    assert_eq!(net.fib(3, p), Some(Fib::Unreachable));
}

#[test]
fn an_unscheduled_ihu_goes_out_as_soon_as_a_neighbour_is_heard() {
    let mut net = Net::new(1);
    net.add_neighbour(0, 9);
    let mut n9 = Scripted::new(9);

    let ihus = |net: &Net, start| {
        let tlvs = tlvs_sent(net, 0, 9, start).into_iter();
        tlvs.filter(|tlv| {
            matches!(
                tlv,
                Tlv::Ihu {
                    rxcost: NOMINAL_COST,
                    ..
                }
            )
        })
        .count()
    };

    // Two out of the last three Hellos make the rxcost finite. It goes out at once, without any of
    // the time for which TLVs are buffered, but only the once.
    let start = net.now;
    n9.send(&mut net, 0, &[]);
    assert_eq!(ihus(&net, start), 0);
    n9.send(&mut net, 0, &[]);
    assert_eq!(ihus(&net, start), 1);
    n9.send(&mut net, 0, &[]);
    assert_eq!(ihus(&net, start), 1);
}

/// The neighbour gets an RTT sample along with hearing that it is heard, so that a route through it
/// is not selected at a cost that leaves the RTT out, only to get worse at the next IHU.
#[test]
fn an_unscheduled_ihu_comes_with_timestamps_and_a_hello_for_them() {
    const LATENCY: Duration = Duration::from_millis(30);
    let mut net = Net::new(2);
    net.connect(0, 1, LATENCY);
    for _ in 0..3000 {
        if net.costs(0, 1).2 != INF {
            break;
        }
        net.run_for(Duration::from_millis(10));
    }
    assert_ne!(net.costs(0, 1).2, INF);
    assert!(net.neigh(0, 1).rtt.is_some());
    assert!((net.neigh(0, 1).rtt.unwrap() - 60_000.0).abs() < 1000.0);

    let unscheduled: Vec<_> = (net.sent.iter())
        .map(|sent| tlvs(&sent.buf))
        .filter(|tlvs| {
            let ihu = tlvs.iter().any(|tlv| matches!(tlv, Tlv::Ihu { .. }));
            let hello = |tlv: &Tlv| {
                matches!(
                    tlv,
                    Tlv::Hello {
                        interval: None,
                        transmit_timestamp: Some(_),
                        ..
                    }
                )
            };
            ihu && tlvs.iter().any(hello)
        })
        .collect();
    assert!(!unscheduled.is_empty());
    for tlvs in unscheduled {
        assert!(tlvs.iter().any(|tlv| matches!(
            tlv,
            Tlv::Ihu {
                origin_receive_timestamps: Some(_),
                ..
            }
        )));
    }
}

#[test]
fn shutdown_says_goodbye_and_removes_routes() {
    let p = prefix("fd00:9::/64");
    let q = prefix("fd00:a::/64");

    // Node 0 selects P through neighbour 9, and holds Q, which neighbour 9 has retracted.
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    let updates9 = [update(p, 42, 1, 100, 0x8000), update(q, 42, 1, 100, 0x8000)];
    exchange(&mut net, &mut n8, &mut n9, 20, &[], &updates9);
    n9.send(&mut net, 0, &[update(q, 42, 1, METRIC_INFINITY, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    assert_eq!(net.fib(0, q), Some(Fib::Unreachable));

    // Node 0 shuts down. It sends each neighbour at once a packet of a wildcard retraction and
    // a Hello with a far seqno and an interval of 10 ms, dropping what was buffered for it, such
    // as the urgent retraction of Q. P and Q are removed.
    let sent_before = net.sent.len();
    let hello_seqnos = [8, 9].map(|j| (j, net.neigh(0, j).hello_seqno));
    net.shutdown(0);
    for (j, hello_seqno) in hello_seqnos {
        let sent: Vec<_> = net.sent[sent_before..]
            .iter()
            .filter(|sent| sent.to == j)
            .collect();
        let [sent] = sent[..] else {
            panic!("node 0 should send neighbour {j} exactly one packet");
        };
        let items: Vec<_> = (PacketDecoder::new(&sent.buf).unwrap())
            .map(Result::unwrap)
            .collect();
        let [retraction, hello] = &items[..] else {
            panic!("the packet should have a retraction and a Hello only");
        };
        assert_matches!(
            retraction,
            PacketItem::Update(u) if u.ae == Ae::Wildcard && u.metric == METRIC_INFINITY
        );
        let PacketItem::Tlv(Tlv::Hello {
            seqno,
            interval,
            transmit_timestamp: None,
        }) = *hello
        else {
            panic!("the last TLV should be an untimestamped Hello");
        };
        assert_eq!(
            (seqno, interval),
            (hello_seqno + FAR_HELLO_SEQNO_OFFSET, Interval::new(1))
        );
    }
    assert!(net.fibs[0].is_empty());
}

#[test]
fn neighbours_of_a_node_shut_down_switch_at_once_and_flush_it_soon() {
    let p = prefix("fd00:2::/64");

    // Node 2 originates P, which node 0 reaches through node 1, rather than over its own
    // slower link to node 2.
    let mut net = Net::new(3);
    for (a, b, ms) in [(0, 1, 10), (1, 2, 10), (0, 2, 100)] {
        net.connect(a, b, Duration::from_millis(ms));
    }
    net.originate(2, p);
    net.run_for(Duration::from_secs(200));
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // Node 1 shuts down. Its goodbye reaches node 0 10 ms later, and node 0 switches to its route
    // through node 2 at once, rather than once the link fails. The far Hello seqno flushes its
    // entry for node 1 there and then, echoes and RTT included.
    net.shutdown(1);
    net.run_for(Duration::from_millis(11));
    assert_eq!(net.fib(0, p), Some(Fib::Via(2)));
    let neigh = net.neigh(0, 1);
    assert_eq!(neigh.hello_history.bits(), 0b1);
    assert_eq!((neigh.txcost, neigh.rtt), (INF, None));
    assert_eq!(neigh.origin_receive_timestamps, None);
    assert_eq!(net.costs(0, 1).2, INF);

    // With node 1's Hello interval of 10 ms, node 0 counts a Hello as missed 15 ms after it, and
    // every 10 ms after that, which empties the history at the 16th, 175 ms after the shutdown.
    net.run_for(Duration::from_millis(150));
    assert_ne!(net.neigh(0, 1).hello_history.bits(), 0);
    net.run_for(Duration::from_millis(20));
    assert_eq!(net.neigh(0, 1).hello_history.bits(), 0);
}

#[test]
fn unnoticed_restarts_cause_no_loops() {
    let p = prefix("fd00::/64");

    for secs in 160..180 {
        // Node 0 originates P, which node 1 reaches directly, node 2 through node 1, and node
        // 3 through nodes 2 and 1, as its own link to node 1 is slower. Node 3 can take over
        // two minutes to settle on that route: if node 2 first routes through node 3, node 3
        // only learns of node 2's route later, and must then wait for its smoothed metric to
        // fall below that of its route through node 1 (RFC 8966 Appendix A.3).
        let mut net = Net::new(4);
        for (a, b, ms) in [(0, 1, 10), (1, 2, 10), (2, 3, 10), (3, 1, 100)] {
            net.connect(a, b, Duration::from_millis(ms));
        }
        net.originate(0, p);
        net.run_for(Duration::from_secs(secs));
        assert_eq!(net.path(3, p.addr()), [3, 2, 1, 0]);

        // Node 1 restarts, with its Hello seqnos where they were, so that its neighbours do not
        // notice (RFC 8966 Appendix A.1). Their routes through it are from before the
        // restart, and could form loops with the routes that it learns, as it has lost its
        // feasibility distances: it could learn P from node 3 before node 0, and node 3 then
        // switch to its old route through node 1. But node 1 sends each neighbour a wildcard
        // retraction (see `State::add_neighbour`), which removes them. The harness checks that
        // no forwarding loop forms meanwhile.
        let hello_seqnos = [0, 2, 3].map(|j| (j, net.neigh(1, j).hello_seqno));
        net.restart(1, state(1, net.now));
        for (j, hello_seqno) in hello_seqnos {
            net.add_neighbour_with_hello_seqno(1, j, hello_seqno);
        }
        net.run_for(Duration::from_secs(60));
        assert_eq!(net.delivered_to(3, p.addr()), Some(0));
    }
}

#[test]
fn restarted_neighbours_routes_are_removed_unless_refreshed() {
    let p = prefix("fd00:9::/64");
    let q = prefix("fd00:a::/64");

    // Node 0 learns P and Q from neighbour 9.
    let mut net = Net::new(1);
    net.add_neighbour(0, 9);
    let mut n9 = Scripted::new(9);
    let updates = [update(p, 42, 1, 100, 0x8000), update(q, 42, 1, 100, 0x8000)];
    n9.send(&mut net, 0, &updates);
    for _ in 0..4 {
        net.run_for(Duration::from_secs(4));
        n9.send(&mut net, 0, &[]);
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    assert_eq!(net.fib(0, q), Some(Fib::Via(9)));

    // Neighbour 9 restarts, sending no wildcard retraction, but its Hello seqno jumps, so node
    // 0 notices (RFC 8966 Appendix A.1). Its first packet has an update for P, then the Hello.
    // Node 0 removes the route to Q learnt before the restart, but keeps the one to P, which
    // the packet refreshed. As the link cost is infinite until the link is up again, both
    // prefixes are held.
    n9.hello_seqno += 1000;
    n9.send(&mut net, 0, &[update(p, 42, 1, 100, 0x8000)]);
    let routes = &net.nodes[0].route_table.prefix_entries;
    assert!(routes[&p].routes.contains_key(net.key(0, 9)));
    assert!(routes[&q].routes.is_empty());
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    assert_eq!(net.fib(0, q), Some(Fib::Unreachable));
}

/// Sets up node 0 with neighbour 8 up, outside the simulation, and no routes.
fn neighbour_8_up() -> Net {
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    let mut n8 = Scripted::new(8);
    for _ in 0..4 {
        n8.send(&mut net, 0, &[]);
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.costs(0, 8), UP);
    net
}

#[test]
fn ihu_applies_to_updates_in_the_same_packet() {
    let p = prefix("fd00:8::/64");
    let mut net = neighbour_8_up();

    // Neighbour 8 sends an update for P, followed by an IHU with an infinite rxcost, as
    // it has stopped hearing node 0. The link cost is then infinite, so node 0 does not
    // select the route, not even briefly.
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(p, 8, 1, 100, 400)));
    assert!(encoder.put_tlv(&ihu(INF)));
    net.inject(8, 0, encoder.finalize().as_bytes());
    assert_eq!(net.costs(0, 8), (NOMINAL_COST, INF, INF));
    assert!(net.fib_changes.iter().all(|change| change.prefix != p));
}

#[test]
fn announcing_and_retracting_a_prefix_in_one_packet_selects_nothing() {
    let p = prefix("fd00:8::/64");
    let mut net = neighbour_8_up();

    // Neighbour 8 announces P and retracts it in the same packet. Selection then runs for
    // P twice, and the first run removes its entry, which has no routes left.
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(p, 8, 1, 100, 400)));
    assert!(encoder.put_update(&update(p, 8, 1, METRIC_INFINITY, 400)));
    net.inject(8, 0, encoder.finalize().as_bytes());
    assert!(net.fib_changes.iter().all(|change| change.prefix != p));
    assert!(!net.nodes[0].route_table.prefix_entries.contains_key(&p));
}

#[test]
fn wildcard_retractions_remove_routes_added_between_them() {
    let (p, q) = (prefix("fd00:8::/64"), prefix("fd00:88::/64"));
    let mut net = neighbour_8_up();
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(q, 8, 1, 100, 400)));
    net.inject(8, 0, encoder.finalize().as_bytes());
    assert_eq!(net.fib(0, q), Some(Fib::Via(8)));

    // Neighbour 8 retracts all its routes, announces P, and retracts all its routes
    // again, in one packet. The second retraction removes the route to P, so neither
    // route is left, and P is never selected.
    let wildcard = Update {
        ae: Ae::Wildcard,
        plen: 0,
        prefix: [0; 16],
        router_id: None,
        ..update(p, 8, 1, METRIC_INFINITY, 400)
    };
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&wildcard));
    assert!(encoder.put_update(&update(p, 8, 1, 100, 400)));
    assert!(encoder.put_update(&wildcard));
    net.inject(8, 0, encoder.finalize().as_bytes());
    assert_eq!(net.fib(0, q), Some(Fib::Unreachable));
    assert!(net.fib_changes.iter().all(|change| change.prefix != p));
    assert!(!net.nodes[0].route_table.prefix_entries.contains_key(&p));
}

#[test]
fn acknowledgement_requests_are_answered_in_time() {
    // Node 1 is outside the simulation and only sends the requests.
    let mut net = Net::new(1);
    net.add_neighbour(0, 1);

    // More requests than one packet can hold Acknowledgments for.
    let interval = Interval::new(100).unwrap();
    let mut encoder = PacketEncoder::new(4096);
    for opaque in 0..400 {
        assert!(encoder.put_tlv(&Tlv::AcknowledgementRequest { opaque, interval }));
    }

    let start = net.now;
    net.inject(1, 0, encoder.finalize().as_bytes());
    net.run_for(interval.to_duration());

    let mut opaques = Vec::new();

    for sent in net.sent.iter().filter(|sent| sent.from == 0) {
        // Packets fit the MTU less the IPv6 and UDP headers (RFC 8966 §4).
        assert!(sent.buf.len() <= Params::new().get_mtu() as usize - 48);

        let acks = tlvs(&sent.buf).into_iter().filter_map(|tlv| match tlv {
            Tlv::Acknowledgement { opaque } => Some(opaque),
            _ => None,
        });
        let len = opaques.len();
        opaques.extend(acks);

        // Acknowledgments are sent before the interval elapses, with a margin.
        if opaques.len() > len {
            assert!(sent.time - start <= interval.to_duration() / 2);
        }
    }

    assert_eq!(opaques, Vec::from_iter(0..400));
}

#[test]
fn ignored_packets_and_tlvs_change_nothing() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31));

    let bits = net.neigh(0, 1).hello_history.bits();

    #[rustfmt::skip]
    let packets = [
        // Wrong magic, wrong version, and a body overrunning the datagram.
        vec![43, 2, 0, 0],
        vec![42, 1, 0, 0],
        vec![42, 2, 0, 1],
        packet(&[
            // A TLV of unknown type.
            99, 2, 0, 0,
            // A Unicast Hello.
            4, 6, 0x80, 0, 0, 1, 1, 0x90,
            // A Hello with an unknown mandatory sub-TLV.
            4, 8, 0, 0, 0, 1, 1, 0x90, 0x80, 0,
            // An Update with a finite metric but no router-id.
            8, 10, 2, 0, 0, 0, 1, 0x90, 0, 1, 0, 96,
            // An IHU overrunning the packet.
            5, 20, 0,
        ]),
    ];
    for buf in packets {
        net.inject(1, 0, &buf);
    }

    assert_eq!(net.neigh(0, 1).hello_history.bits(), bits);
    assert_eq!(net.costs(0, 1), UP);
}

/// The Route Hold time, which is 4 times the Update interval.
const ROUTE_HOLD_TIME: Duration = Duration::from_secs(64);

#[test]
fn routes_propagate_without_flapping() {
    let p = prefix("fd00:3::/64");
    let router_id = RouterId::new(4).unwrap();

    let mut net = Net::new(4);
    for i in 0..3 {
        net.connect(i, i + 1, Duration::ZERO);
    }
    net.originate(3, p);
    net.run_for(Duration::from_secs(60));

    assert_eq!(net.path(0, p.addr()), [0, 1, 2, 3]);
    let changes = net.fib_changes.len();

    // Routes then stay put, beyond the source GC time.
    net.run_for(Duration::from_secs(300));
    assert_eq!(net.fib_changes.len(), changes);

    // Each node advertises P with the originator's router-id and seqno, and a metric
    // adding the cost of the link it learnt P over (RFC 8966 §3.7), but not back over
    // that link (§3.7.4).
    let seqno = net.nodes[3].seqno;
    for (from, to, metric) in [(3, 2, 0), (2, 1, 96), (1, 0, 192)] {
        let sent_updates: Vec<_> = (net.sent.iter())
            .filter(|sent| (sent.from, sent.to) == (from, to))
            .flat_map(|sent| updates(&sent.buf))
            .filter(|update| is_for(update, p))
            .collect();
        assert!(sent_updates.len() >= 20);
        for update in sent_updates {
            assert_eq!((update.router_id, update.seqno), (Some(router_id), seqno));
            assert_eq!(update.metric, metric);
        }

        let back = (net.sent.iter())
            .filter(|sent| (sent.from, sent.to) == (to, from))
            .flat_map(|sent| updates(&sent.buf));
        assert!(!back.into_iter().any(|update| is_for(&update, p)));
    }

    // Feasibility distances are kept for as long as routes are advertised (§3.7.3).
    for (i, metric) in [(3, 0), (2, 96), (1, 192)] {
        let source = &net.nodes[i].source_table[&SourceKey {
            prefix: p,
            router_id,
        }];
        assert_eq!((source.seqno, source.metric), (seqno, metric));
    }
}

#[test]
fn ipv4_prefixes_are_routed_like_ipv6_ones() {
    let p4 = prefix("10.0.0.0/16");
    let p6 = prefix("fd00::/64");

    // Node 0 originates P4 and P6, which nodes 1 and 2 route through it.
    let mut net = Net::new(3);
    for i in 0..2 {
        net.connect(i, i + 1, Duration::ZERO);
    }
    net.originate(0, p4);
    net.originate(0, p6);
    net.run_for(Duration::from_secs(40));
    for i in 0..3 {
        for p in [p4, p6] {
            assert_eq!(net.delivered_to(i, p.addr()), Some(0), "from {i} to {p}");
        }
    }

    // P4 is announced with AE 4 (RFC 9229 §2.1), and AE 4 is used for nothing else.
    let updates: Vec<_> = (net.sent.iter())
        .flat_map(|sent| updates(&sent.buf))
        .collect();
    assert!(updates.iter().any(|update| is_for(update, p4)));
    for update in updates {
        assert_eq!(is_for(&update, p4), update.ae == Ae::V4ViaV6);
    }

    // Node 0 shuts down, so that node 1 loses both prefixes, retracts them, which node 2 then
    // holds, and sends a seqno request for each, with AE 1 for P4 (RFC 9229 §2.3).
    let start = net.now;
    net.shutdown(0);
    net.run_for(Duration::from_secs(1));
    for p in [p4, p6] {
        assert_eq!(net.fib(2, p), Some(Fib::Unreachable));
    }
    let requests: Vec<_> = (net.sent.iter())
        .filter(|sent| (sent.from, sent.to) == (1, 2) && sent.time >= start)
        .flat_map(|sent| tlvs(&sent.buf))
        .filter_map(|tlv| match tlv {
            Tlv::SeqnoRequest {
                ae, plen, prefix, ..
            } => Some((ae, plen, prefix)),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 2);
    assert!(requests.contains(&(Ae::Ipv4, 16, octets(p4))));
    assert!(requests.contains(&(Ae::Ipv6, 64, octets(p6))));
}

#[test]
fn ipv4_updates_with_ae_1_or_4_are_for_the_same_prefix() {
    let p = prefix("10.8.0.0/16");
    let mut net = neighbour_8_up();
    let send = |net: &mut Net, ae, metric| {
        let mut encoder = PacketEncoder::new(1400);
        let update = Update {
            ae,
            ..update(p, 8, 1, metric, 400)
        };
        assert!(encoder.put_update(&update));
        net.inject(8, 0, encoder.finalize().as_bytes());
    };

    // Neighbour 8 announces P with either AE, and retracts it with the other, which removes
    // the route (RFC 9229 §2.2).
    for (announce, retract) in [(Ae::Ipv4, Ae::V4ViaV6), (Ae::V4ViaV6, Ae::Ipv4)] {
        send(&mut net, announce, 100);
        assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
        send(&mut net, retract, METRIC_INFINITY);
        assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    }
}

#[test]
fn routes_through_the_only_neighbour_can_be_lost_after_the_source_gc_time() {
    let p = prefix("fd00:1::/64");

    // Node 0 selects P through node 1, its only neighbour, which split horizon keeps it from
    // sending P to. Its source table entry for P still outlasts the source GC time, as node 0
    // takes the seqno that it requests from there once the route is lost (RFC 8966 §3.8.2.1).
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.originate(1, p);
    net.run_for(Duration::from_mins(4));
    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));

    net.links.remove(&(0, 1));
    net.links.remove(&(1, 0));
    net.run_for(Duration::from_secs(15));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
}

#[test]
fn failed_link_retracts_routes_and_holds_prefix() {
    let p = prefix("fd00:2::/64");

    let mut net = Net::new(3);
    net.connect(0, 1, Duration::ZERO);
    net.connect(1, 2, Duration::ZERO);
    net.originate(2, p);
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // Node 1 loses node 2 after two missed Hellos, and retracts P, which node 0 learns
    // of. Both hold P as unreachable (RFC 8966 §3.5.4).
    net.links.remove(&(1, 2));
    net.links.remove(&(2, 1));
    let failure = net.now;
    net.run_for(Duration::from_secs(15));
    assert_eq!(net.fib(1, p), Some(Fib::Unreachable));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    net.run_for(Duration::from_secs(90));

    for i in [0, 1] {
        let changes: Vec<_> = (net.fib_changes.iter())
            .filter(|change| (change.node, change.prefix) == (i, p) && change.time > failure)
            .collect();
        let [held, removed] = changes[..] else {
            panic!("node {i} should hold P, then remove it");
        };
        assert_eq!((held.entry, removed.entry), (Some(Fib::Unreachable), None));
        assert_eq!(removed.time - held.time, ROUTE_HOLD_TIME);

        // While P is held, it is only retracted, with the router-id of the route lost,
        // at once as an urgent TLV within 0.2 s, and with every periodic dump (RFC 8966
        // §3.7), and afterwards not mentioned at all.
        let mut retractions = vec![];
        for sent in net
            .sent
            .iter()
            .filter(|sent| sent.from == i && sent.time > held.time)
        {
            for update in updates(&sent.buf).iter().filter(|update| is_for(update, p)) {
                let router_id = RouterId::new(3);
                assert_eq!(
                    (update.metric, update.router_id),
                    (METRIC_INFINITY, router_id)
                );
                // Allow for the buffering of a retraction put before the removal.
                assert!(sent.time <= removed.time + Duration::from_secs(2));
                retractions.push(sent.time);
            }
        }
        assert!(retractions.len() >= 4);
        assert!(retractions[0] - held.time <= Duration::from_millis(200));
    }
}

#[test]
fn held_prefix_outlasts_routes_through_the_node() {
    let p = prefix("fd00:2::/64");

    // Node 0 originates a default route, which covers P, nonexclusive so that node 2 may
    // originate P.
    let mut net = Net::new(3);
    net.connect(0, 1, Duration::ZERO);
    net.connect(1, 2, Duration::ZERO);
    net.originate_nonexclusive(0, prefix("::/0"));
    net.originate(2, p);
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // Node 0 misses node 1's retractions, so it keeps routing P through node 1 until the
    // route expires. Were node 1 to stop holding P before, it would route P along the
    // default route back to node 0, which the forwarding loop check would catch.
    net.filter = |from, _, packet| {
        Some(if from == 1 {
            without_retractions(packet)
        } else {
            packet
        })
    };
    net.links.remove(&(1, 2));
    net.links.remove(&(2, 1));
    net.run_for(Duration::from_secs(120));

    // The first change of node `i` away from routing P through node `i + 1`.
    let change = |i: usize| {
        let mut changes = net
            .fib_changes
            .iter()
            .filter(|change| (change.node, change.prefix) == (i, p));
        changes.find(|change| change.entry != Some(Fib::Via(i + 1)))
    };
    let held = change(1).unwrap();
    let expired = change(0).unwrap();
    let removed = (net.fib_changes.iter())
        .find(|change| (change.node, change.prefix, change.entry) == (1, p, None))
        .unwrap();

    // The route through node 1 lasts until it expires, 3.5 Update intervals after
    // node 0 last heard of it, but no longer than the hold.
    assert!(expired.time - held.time >= Duration::from_secs(40));
    assert!(expired.time < removed.time);
}

#[test]
fn unreachable_sources_are_not_counted_to_infinity() {
    let p = prefix("fd00::/64");

    // As in RFC 8966 §2.3: node 0 originates P, and nodes 2 and 3 reach it through node 1.
    // They are linked to each other once they have selected those routes.
    let mut net = Net::new(4);
    for (a, b) in [(0, 1), (1, 2), (1, 3)] {
        net.connect(a, b, Duration::ZERO);
    }
    net.originate(0, p);
    net.run_for(Duration::from_secs(60));
    net.connect(2, 3, Duration::ZERO);
    net.run_for(Duration::from_secs(60));
    for i in [2, 3] {
        assert_eq!(net.path(i, p.addr()), [i, 1, 0]);
    }

    // The link between nodes 0 and 1 fails. With plain Bellman-Ford, node 1 would switch
    // to the route through node 2 or 3, and they to each other's, increasing the metric
    // until it reached infinity. Here those routes are unfeasible (§2.4), so each node
    // holds P, and removes it once the hold time has expired, without ever switching. The
    // harness checks that no forwarding loop forms meanwhile.
    let changes = net.fib_changes.len();
    net.links.remove(&(0, 1));
    net.links.remove(&(1, 0));
    net.run_for(Duration::from_secs(120));
    for i in [1, 2, 3] {
        let entries: Vec<_> = (net.fib_changes[changes..].iter())
            .filter(|change| (change.node, change.prefix) == (i, p))
            .map(|change| change.entry)
            .collect();
        assert_eq!(entries, [Some(Fib::Unreachable), None], "node {i}");
    }
}

#[test]
fn feasible_routes_are_used_at_once_despite_larger_metrics() {
    let p = prefix("fd00::/64");

    // As in RFC 8966 §2.4: node 0 originates P, and is linked to nodes 2 and 3, which are
    // both linked to node 1, the latter once node 1 routes P through node 2, at metric 192.
    // With a round-trip time of 120 ms, the link between nodes 1 and 3 costs 96 + 150 (RFC
    // 9616 §4.2), so the route through node 3 has metric 342.
    let mut net = Net::new(4);
    for (a, b) in [(0, 2), (2, 1), (0, 3)] {
        net.connect(a, b, Duration::ZERO);
    }
    net.originate(0, p);
    net.run_for(Duration::from_secs(60));
    net.connect(3, 1, Duration::from_millis(60));
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.path(1, p.addr()), [1, 2, 0]);

    // The link between nodes 1 and 2 fails. Node 3 advertises metric 96, below node 1's
    // feasibility distance of 192, so its route is feasible, although its metric is
    // larger than that of the lost route. Node 1 switches to it once it notices the
    // failure, without holding P or requesting a new seqno.
    let start = net.now;
    let changes = net.fib_changes.len();
    net.links.remove(&(1, 2));
    net.links.remove(&(2, 1));
    net.run_for(Duration::from_secs(30));
    let entries: Vec<_> = (net.fib_changes[changes..].iter())
        .filter(|change| (change.node, change.prefix) == (1, p))
        .map(|change| change.entry)
        .collect();
    assert_eq!(entries, [Some(Fib::Via(3))]);
    for to in [2, 3] {
        assert_eq!(requests_sent(&net, 1, to, start), []);
    }
}

#[test]
fn retractions_and_expiry_unselect_routes() {
    let p = prefix("fd00:9::/64");
    // An interval of 4 s makes the route expire 14 s after the last update.
    let announcement = update(p, 42, 1, 0, 400);
    let retraction = update(p, 42, 1, METRIC_INFINITY, 400);
    let wildcard_retraction = Update {
        ae: Ae::Wildcard,
        plen: 0,
        prefix: [0; 16],
        router_id: None,
        ..retraction
    };

    let mut net = Net::new(1);
    net.add_neighbour(0, 9);
    let mut neighbour = Scripted::new(9);

    // Announcements are selected once the neighbour is up.
    for _ in 0..3 {
        neighbour.send(&mut net, 0, from_ref(&announcement));
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // A retraction unselects the route at once.
    neighbour.send(&mut net, 0, from_ref(&retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    net.run_for(Duration::from_secs(4));

    // A new route is unaffected by the expiry of the one retracted.
    for _ in 0..6 {
        neighbour.send(&mut net, 0, from_ref(&announcement));
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
        net.run_for(Duration::from_secs(4));
    }

    // So is a wildcard retraction.
    neighbour.send(&mut net, 0, from_ref(&wildcard_retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    net.run_for(Duration::from_secs(4));

    // A route that is not refreshed expires.
    neighbour.send(&mut net, 0, from_ref(&announcement));
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    for _ in 0..3 {
        net.run_for(Duration::from_secs(4));
        neighbour.send(&mut net, 0, &[]);
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    net.run_for(Duration::from_secs(4));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
}

#[test]
fn unfeasible_routes_are_never_selected() {
    let p = prefix("fd00:9::/64");
    // Neighbour 9 announces P once, with an interval long enough for it not to expire.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 400);

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    n9.send(&mut net, 0, from_ref(&far));
    for round in 0..40 {
        if round > 0 {
            n9.send(&mut net, 0, &[]);
        }
        let updates: &[Update] = if round >= 2 { from_ref(&near) } else { &[] };
        n8.send(&mut net, 0, updates);
        net.run_for(Duration::from_secs(4));
    }

    // Node 0 switched to the nearer route, and has advertised it.
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    let last = (net.sent.iter())
        .filter(|sent| sent.from == 0 && sent.to == 9)
        .flat_map(|sent| updates(&sent.buf))
        .rfind(|update| is_for(update, p));
    assert_eq!(last.map(|update| update.metric), Some(196));

    // Once neighbour 8 is lost, the far route is not feasible anymore, since it is not
    // strictly better than what node 0 has advertised (RFC 8966 §3.5.1, §3.6).
    for _ in 0..5 {
        n9.send(&mut net, 0, &[]);
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    // A snapshot says so, while the metric alone gives no reason.
    let via = net.key_maps[0].internal(&9).unwrap();
    let snapshot = net.nodes[0].snapshot(net.now, |key| key);
    let routes = &snapshot.prefixes[0].routes;
    let route = routes.iter().find(|route| route.via == via).unwrap();
    assert_ne!(route.metric, METRIC_INFINITY);
    assert!(!route.feasible);
}

/// Runs node 0 for `secs` seconds, with neighbours 8 and 9 sending a Hello and an IHU
/// every 4 s, preceded by the given updates in their first packets only.
fn exchange(
    net: &mut Net,
    n8: &mut Scripted,
    n9: &mut Scripted,
    secs: u64,
    updates8: &[Update],
    updates9: &[Update],
) {
    for round in 0..secs / 4 {
        let first = round == 0;
        n9.send(net, 0, if first { updates9 } else { &[] });
        n8.send(net, 0, if first { updates8 } else { &[] });
        net.run_for(Duration::from_secs(4));
    }
}

#[test]
fn snapshots_smooth_metrics_up_to_the_time_asked_for() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, _n8, mut n9) = two_routes(&far, &near);
    let via = net.key_maps[0].internal(&9).unwrap();

    let route_at = |net: &Net, at: Instant| {
        let snapshot = net.nodes[0].snapshot(at, |key| key);
        let routes = &snapshot.prefixes[0].routes;
        let route = routes.iter().find(|route| route.via == via).unwrap();
        (route.metric, route.smoothed_metric, route.feasible)
    };

    assert_eq!(route_at(&net, net.now), (196, 196, true));

    // Its metric rises, and smoothing takes its time to follow.
    n9.send(&mut net, 0, from_ref(&update(p, 42, 2, 300, 0x8000)));
    let (metric, smoothed, _) = route_at(&net, net.now);
    assert_eq!((metric, smoothed), (396, 196));

    let (_, smoothed, _) = route_at(&net, net.now + Duration::from_secs(12));
    assert!((300..396).contains(&smoothed), "{smoothed}");
    let (_, smoothed, _) = route_at(&net, net.now + Duration::from_secs(600));
    assert_eq!(smoothed, 396);
}

/// Sets up node 0 with neighbours 8 and 9, which announce P once each, with an interval
/// long enough for the routes not to expire. The route through neighbour 9 comes up
/// first, and is selected. Both smoothed metrics have converged after 160 s.
fn two_routes(far: &Update, near: &Update) -> (Net, Scripted, Scripted) {
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        160,
        from_ref(far),
        from_ref(near),
    );
    (net, n8, n9)
}

#[test]
fn unfeasible_update_with_an_unchanged_router_id_is_ignored() {
    let p = prefix("fd00:9::/64");
    let far = nonexclusive_update(p, 43, 1, 2000, 0x8000);
    let near = nonexclusive_update(p, 42, 1, 100, 0x8000);

    // Node 0 selects the route through neighbour 9, with or without one through neighbour 8.
    for alternative in [true, false] {
        let mut net = Net::new(1);
        net.add_neighbour(0, 8);
        net.add_neighbour(0, 9);
        let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
        let updates8: &[Update] = if alternative { from_ref(&far) } else { &[] };
        exchange(&mut net, &mut n8, &mut n9, 160, updates8, from_ref(&near));
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

        // Node 0 advertises P with metric 196, so an update from neighbour 9 with metric 300
        // and the same router-id is unfeasible. Rather than apply it and unselect the route,
        // node 0 ignores it (RFC 8966 §3.5.3, see `handle_update`), so P stays reachable, and
        // is still advertised with metric 196.
        let start = net.now;
        let changes = net.fib_changes.len();
        n9.send(&mut net, 0, &[nonexclusive_update(p, 42, 1, 300, 0x8000)]);
        assert_eq!(net.fib_changes.len(), changes);
        let advert = net.nodes[0].route_table.prefix_entries[&p].advert.unwrap();
        assert_eq!(advert.metric, 196);

        // It still sends neighbour 9 a seqno request, with the update's router-id and the
        // seqno in the source table plus 1 (§3.8.2.2), as an urgent TLV within 0.2 s.
        net.run_for(Duration::from_millis(200));
        assert_eq!(requests_sent(&net, 0, 9, start), [(42, 2, 64)]);
        assert_eq!(requests_sent(&net, 0, 8, start), []);
    }
}

#[test]
fn unfeasible_update_with_another_router_id_unselects_the_route() {
    let p = prefix("fd00:9::/64");
    let far = nonexclusive_update(p, 44, 1, 2000, 0x8000);

    for alternative in [true, false] {
        // Node 0 selects the route through neighbour 9, with router-id 43, and advertises it
        // with metric 196. Neighbour 9 then switches to router-id 42, and so does node 0.
        let mut net = Net::new(1);
        net.add_neighbour(0, 8);
        net.add_neighbour(0, 9);
        let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
        let updates8: &[Update] = if alternative { from_ref(&far) } else { &[] };
        let updates9 = [nonexclusive_update(p, 43, 1, 100, 0x8000)];
        exchange(&mut net, &mut n8, &mut n9, 20, updates8, &updates9);
        let updates9 = [nonexclusive_update(p, 42, 1, 100, 0x8000)];
        exchange(&mut net, &mut n8, &mut n9, 20, &[], &updates9);
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

        // Neighbour 9 switches back to router-id 43, with metric 300, which is unfeasible. With
        // another router-id, this is another source, so node 0 MUST unselect the route (RFC
        // 8966 §3.5.3). It selects the route through neighbour 8 instead, if there is one.
        let start = net.now;
        n9.send(&mut net, 0, &[nonexclusive_update(p, 43, 1, 300, 0x8000)]);
        let fib = if alternative {
            Fib::Via(8)
        } else {
            Fib::Unreachable
        };
        assert_eq!(net.fib(0, p), Some(fib));

        // Node 0 sends neighbour 9 a seqno request for router-id 43 (§3.8.2.2). If it has lost
        // P, it also sends every neighbour one for router-id 42 (§3.8.2.1).
        net.run_for(Duration::from_millis(200));
        let (to8, to9) = if alternative {
            (vec![], vec![(43, 2, 64)])
        } else {
            (vec![(42, 2, 64)], vec![(42, 2, 64), (43, 2, 64)])
        };
        assert_eq!(requests_sent(&net, 0, 8, start), to8);
        assert_eq!(requests_sent(&net, 0, 9, start), to9);
    }
}

#[test]
fn metric_increases_keep_routes_selected() {
    let p = prefix("fd00::/64");

    // Node 0 originates P, which nodes 1, 2 and 3 reach along a chain of links of 10 ms,
    // each costing 110 with its round-trip time of 20 ms (RFC 9616 §4.2). So node 2
    // advertises P with metric 220.
    let mut net = Net::new(4);
    for (a, b) in [(0, 1), (1, 2), (2, 3)] {
        net.connect(a, b, Duration::from_millis(10));
    }
    net.originate(0, p);
    net.run_for(Duration::from_secs(120));
    assert_eq!(net.path(3, p.addr()), [3, 2, 1, 0]);

    // The latency of the link between nodes 0 and 1 rises to 100 ms, so its cost, and node
    // 1's metric for P, rise to 246. Its updates become unfeasible at node 2, which ignores
    // them and keeps its route, as does node 3 (see `handle_update`), so P stays reachable.
    let changes = net.fib_changes.len();
    let start = net.now;
    let seqno = net.nodes[0].seqno;
    net.links.insert((0, 1), Duration::from_millis(100));
    net.links.insert((1, 0), Duration::from_millis(100));
    net.run_for(Duration::from_secs(300));
    assert_eq!(net.fib_changes.len(), changes);

    // Node 2 requests a new seqno (RFC 8966 §3.8.2.2), which node 0 raises by 1. The routes
    // advertised have that seqno, and the metrics as increased.
    assert!(!requests_sent(&net, 2, 1, start).is_empty());
    assert_eq!(net.nodes[0].seqno, seqno + 1);
    for (i, metric) in [(1, 246), (2, 356), (3, 466)] {
        let advert = net.nodes[i].route_table.prefix_entries[&p].advert.unwrap();
        assert_eq!((advert.seqno, advert.metric), (seqno + 1, metric));
    }
}

#[test]
fn selected_routes_expire_unless_refreshed_by_feasible_updates() {
    let p = prefix("fd00:9::/64");
    // An interval of 4 s makes the route expire 14 s after the last update that refreshes it.
    let feasible = update(p, 42, 1, 100, 400);
    let unfeasible = update(p, 42, 1, 300, 400);
    let reply = update(p, 42, 2, 300, 400);

    for answered in [false, true] {
        let mut net = Net::new(1);
        net.add_neighbour(0, 9);
        let mut n9 = Scripted::new(9);
        for _ in 0..3 {
            n9.send(&mut net, 0, from_ref(&feasible));
            net.run_for(Duration::from_secs(4));
        }
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

        // Node 0 advertises P with metric 196, so updates from neighbour 9 with metric 300
        // and the same router-id are unfeasible. They are ignored (see `handle_update`), so the
        // route stays selected, but is not refreshed, and expires 14 s after the last feasible
        // update, 10 s from now, and node 0 holds P. Should neighbour 9 have lost its
        // feasibility distances, a loop through the route would end then. But if neighbour 9
        // answers node 0's seqno request with seqno 2, its update is feasible, and refreshes
        // the route.
        let updates = if answered {
            [&unfeasible, &unfeasible, &reply, &reply]
        } else {
            [&unfeasible; 4]
        };
        for (round, update) in updates.into_iter().enumerate() {
            n9.send(&mut net, 0, from_ref(update));
            let held = !answered && round == 3;
            let fib = if held { Fib::Unreachable } else { Fib::Via(9) };
            assert_eq!(net.fib(0, p), Some(fib));
            net.run_for(Duration::from_secs(4));
        }
    }
}

#[test]
fn worse_selected_route_is_replaced_at_the_next_update_of_a_better_one() {
    let p = prefix("fd00:9::/64");
    let far = nonexclusive_update(p, 43, 1, 500, 0x8000);
    let near = nonexclusive_update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // At 162 s, the link to neighbour 9 gets worse, raising the route's metric from 196
    // to 1100, above 596 through neighbour 8. The route stays selected while usable.
    // Neighbour 8 refreshes its route every 4 s, and node 0 compares it with the
    // selected route each time. At 162 and 166 s, the selected route's smoothed metric,
    // 1100 - 904 exp(-t / 12 s), is still below 596. At 170 s, it is about 636, so node 0
    // switches then (RFC 8966 Appendix A.3).
    net.run_for(Duration::from_secs(2));
    n9.rxcost = Some(1000);
    let start = net.now;
    let changes = net.fib_changes.len();
    for _ in 0..5 {
        exchange(&mut net, &mut n8, &mut n9, 4, from_ref(&far), &[]);
    }

    let [switch] = &net.fib_changes[changes..] else {
        panic!("node 0 should switch once");
    };
    assert_eq!(switch.entry, Some(Fib::Via(8)));
    assert_eq!(switch.time - start, Duration::from_secs(8));
}

#[test]
fn router_id_change_by_hysteresis_is_advertised_urgently() {
    let p = prefix("fd00:9::/64");
    let far = nonexclusive_update(p, 43, 1, 500, 0x8000);
    let near = nonexclusive_update(p, 42, 1, 100, 0x8000);

    // As above, with node 1 receiving node 0's updates.
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        160,
        from_ref(&far),
        from_ref(&near),
    );
    assert_eq!(net.path(1, p.addr()), [1, 0, 9]);

    // The link to neighbour 9 gets worse, and node 0 switches to the route through
    // neighbour 8, with another router-id, when that route is next updated.
    net.run_for(Duration::from_secs(2));
    n9.rxcost = Some(1000);
    let changes = net.fib_changes.len();
    for _ in 0..5 {
        exchange(&mut net, &mut n8, &mut n9, 4, from_ref(&far), &[]);
    }
    let switch = net.fib_changes[changes..]
        .iter()
        .find(|change| (change.node, change.entry) == (0, Some(Fib::Via(8))))
        .expect("node 0 should switch to the route through neighbour 8");

    // The new router-id is advertised as an urgent TLV (RFC 8966 §3.7.2), within the
    // urgent timeout of 0.2 s.
    let sent = net.sent.iter().find(|sent| {
        let updates = updates(&sent.buf);
        let mut updates = updates.iter().filter(|update| is_for(update, p));
        (sent.from, sent.to) == (0, 1)
            && sent.time >= switch.time
            && updates.any(|update| update.router_id == RouterId::new(43))
    });
    let sent = sent.expect("new router-id should be advertised");
    assert!(sent.time - switch.time <= Duration::from_millis(200));
}

#[test]
fn hysteresis_needs_a_lower_metric_as_well() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // Both links come up at 4 s, the one to neighbour 9 first, and its route, of metric
    // 596, is selected. The route through neighbour 8 has metric 196, but its smoothed
    // metric starts at infinity, and it is not updated again for a while.
    let far = nonexclusive_update(p, 42, 1, 500, 0x8000);
    let near = nonexclusive_update(p, 43, 1, 100, 0x8000);
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        72,
        from_ref(&near),
        from_ref(&far),
    );
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // By 72 s, its smoothed metric, 196 + 65339 exp(-68 s / 12 s) ≈ 422, is below 596.
    // It is then updated with metric 1096, above 596. Node 0 keeps its route, since it
    // switches only when both m(R') < m(R) and ms(R') < ms(R) (RFC 8966 Appendix A.3).
    n8.send(&mut net, 0, &[nonexclusive_update(p, 43, 1, 1000, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[test]
fn hysteresis_never_switches_to_unfeasible_routes() {
    let p = prefix("fd00:9::/64");
    // Both routes have the same source, and node 0 advertises P with metric 196 through
    // neighbour 9, so the route through neighbour 8 is unfeasible.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // The link to neighbour 9 gets worse, raising the route's metric to 1100, above 596
    // through neighbour 8. The routes are refreshed meanwhile. Node 0 keeps the route
    // through neighbour 9, which is still feasible, and never switches, even briefly, to
    // one that is not.
    n9.rxcost = Some(1000);
    let changes = net.fib_changes.len();
    let start = net.now;
    for _ in 0..15 {
        exchange(
            &mut net,
            &mut n8,
            &mut n9,
            4,
            from_ref(&far),
            from_ref(&near),
        );
    }
    assert_eq!(net.fib_changes.len(), changes);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Instead, once the route through neighbour 8 would be selected were it feasible, at
    // its refresh 8 s in, when the selected route's smoothed metric, 1100 - 904 exp(-8 / 12)
    // ≈ 636, is above 596, node 0 SHOULD send neighbour 8 a seqno request (RFC 8966
    // §3.8.2.2, Erratum 7373), and does so at every refresh.
    assert_eq!(requests_sent(&net, 0, 8, start), [(42, 2, 64); 13]);
    let (after, ..) = seqno_requests_sent(&net, 0, 8, start)[0];
    assert!(after >= Duration::from_secs(8));
    assert_eq!(requests_sent(&net, 0, 9, start), []);
}

#[test]
fn metric_changed_by_a_timeout_is_smoothed_from_then() {
    let p = prefix("fd00:8::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        32,
        &[update(p, 8, 1, 100, 0x8000)],
        &[],
    );
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));

    // Neighbour 8 falls silent, while neighbour 9 keeps sending packets, 3 s apart.
    // Missed Hellos make the link cost to neighbour 8 infinite, and the metric of the
    // route through it as well. The smoothed metric follows from the time of the
    // timeout, not of the last packet received (RFC 8966 Appendix A.3).
    let changes = net.fib_changes.len();
    for _ in 0..4 {
        net.run_for(Duration::from_secs(3));
        n9.send(&mut net, 0, &[]);
    }
    let [lost] = &net.fib_changes[changes..] else {
        panic!("node 0 should lose the route once");
    };
    let route = &net.nodes[0].route_table.prefix_entries[&p].routes[net.key(0, 8)];
    assert_eq!(route.metric.get(), METRIC_INFINITY);
    let age = timestamp(net.now).wrapping_sub(route.metric_smoothed_at.get());
    assert_eq!(Duration::from_micros(age.into()), net.now - lost.time);
}

#[test]
fn source_expiry_keeps_hysteresis() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // The route through neighbour 9 is selected, and then changes router-id, so node 0's
    // source table entry for the old one expires 3 minutes after it last advertised it.
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        40,
        &[nonexclusive_update(p, 43, 1, 2000, 0x8000)],
        &[nonexclusive_update(p, 42, 1, 100, 0x8000)],
    );
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        4,
        &[],
        &[nonexclusive_update(p, 44, 1, 100, 0x8000)],
    );
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    let node = &net.nodes[0];
    let source = SourceKey {
        prefix: p,
        router_id: RouterId::new(42).unwrap(),
    };
    let expiry = node
        .timers
        .deadline(node.source_table[&source].gc_timer_key);

    // Shortly before, the route through neighbour 8 gets a metric of 146, below 196, but
    // its smoothed metric is still far above. Node 0 keeps its route, also when the entry
    // expires (RFC 8966 Appendix A.3).
    while net.now + Duration::from_secs(8) < expiry {
        exchange(&mut net, &mut n8, &mut n9, 4, &[], &[]);
    }
    n8.send(&mut net, 0, &[nonexclusive_update(p, 43, 1, 50, 0x8000)]);
    exchange(&mut net, &mut n8, &mut n9, 12, &[], &[]);
    assert!(!net.nodes[0].source_table.contains_key(&source));
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[test]
fn smoothed_metrics_survive_timestamp_wraparound() {
    let p = prefix("fd00:9::/64");
    let near = nonexclusive_update(p, 42, 1, 100, 0x8000);
    let far = nonexclusive_update(p, 43, 1, 500, 0x8000);

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(&mut net, &mut n8, &mut n9, 16, &[], from_ref(&near));
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Timestamps wrap around every 2^32 µs, about 72 minutes. The route through
    // neighbour 9 keeps its metric of 196 for longer than that, refreshed every 16 s.
    // The route through neighbour 8 appears a few minutes before, with metric 596.
    let route = &net.nodes[0].route_table.prefix_entries[&p].routes[net.key(0, 9)];
    let age = timestamp(net.now).wrapping_sub(route.metric_smoothed_at.get());
    let anchored = net.now - Duration::from_micros(age.into());
    let wrapped = anchored + Duration::from_micros(1 << 32) + Duration::from_secs(1);
    while net.now < wrapped {
        let soon = wrapped - net.now < Duration::from_secs(300);
        let updates8: &[Update] = if soon { from_ref(&far) } else { &[] };
        exchange(&mut net, &mut n8, &mut n9, 16, updates8, from_ref(&near));
    }

    // Just after the wraparound, the route through neighbour 8 gets a metric of 146.
    // Both smoothed metrics have long converged, to 196 and 596, so node 0 keeps its
    // route (RFC 8966 Appendix A.3).
    n8.send(&mut net, 0, &[nonexclusive_update(p, 43, 1, 50, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[test]
fn router_id_change_is_advertised_urgently() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.add_neighbour(0, 9);
    let mut neighbour = Scripted::new(9);

    for _ in 0..10 {
        neighbour.send(&mut net, 0, &[update(p, 42, 1, 0, 400)]);
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.path(1, p.addr()), [1, 0, 9]);

    // A new router-id for the selected route is advertised as an urgent TLV
    // (RFC 8966 §3.7.2), within the urgent timeout of 0.2 s.
    neighbour.send(&mut net, 0, &[update(p, 43, 1, 0, 400)]);
    let change = net.now;
    net.run_for(Duration::from_secs(4));

    let first = net.sent.iter().find(|sent| {
        let updates = updates(&sent.buf);
        let mut updates = updates.iter().filter(|update| is_for(update, p));
        sent.from == 0 && updates.any(|update| update.router_id == RouterId::new(43))
    });
    let first = first.expect("new router-id should be advertised");
    assert_eq!(first.to, 1);
    assert!(first.time - change <= Duration::from_millis(200));

    // Neither update goes back to neighbour 9 (§3.7.4).
    for sent in net.sent.iter().filter(|sent| sent.to == 9) {
        assert!(!updates(&sent.buf).iter().any(|update| is_for(update, p)));
    }
}

#[test]
fn better_routes_are_adopted_after_hysteresis() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // Routes of metrics 596 through neighbour 9 and 1096 through neighbour 8, long
    // enough for their smoothed metrics to converge.
    for _ in 0..50 {
        n8.send(&mut net, 0, &[update(p, 42, 1, 1000, 400)]);
        n9.send(&mut net, 0, &[update(p, 42, 1, 500, 400)]);
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // The route through neighbour 8 drops to 196. Its smoothed metric, with a time
    // constant of 12 s (RFC 8966 Appendix A.3), is 196 + 900 exp(-t / 12 s), and falls
    // below 596 after 12 s × ln(9 / 4) ≈ 9.7 s. Routes are selected every 4 s, as the
    // neighbours' packets arrive, so the switch happens 12 s after the drop.
    for round in 0..4 {
        n8.send(&mut net, 0, &[update(p, 42, 1, 100, 400)]);
        n9.send(&mut net, 0, &[update(p, 42, 1, 500, 400)]);
        let expected = if round < 3 { 9 } else { 8 };
        assert_eq!(
            net.fib(0, p),
            Some(Fib::Via(expected)),
            "after {} s",
            round * 4
        );
        net.run_for(Duration::from_secs(4));
    }
}

/// Sets up nodes 0, 1 and 2 in a line, with node 2 originating P, and once node 0 reaches
/// P, reboots node 2 with the same router-id, but a seqno smaller than before by `gap`.
/// Returns P and the time of the reboot.
fn rebooted_originator(gap: u16) -> (Net, IpNet, Instant) {
    let p = prefix("fd00:2::/64");

    let mut net = Net::new(3);
    net.connect(0, 1, Duration::ZERO);
    net.connect(1, 2, Duration::ZERO);
    net.originate(2, p);
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    let seqno = Seqno::new(net.nodes[2].seqno.get().wrapping_sub(gap));
    let hello_seqno = net.neigh(2, 1).hello_seqno + 1000;
    let node = State::new(net.now, params(), net.nodes[2].router_id, Some(seqno));
    net.restart(2, node);
    net.add_neighbour_with_hello_seqno(2, 1, hello_seqno);
    assert!(net.nodes[2].inject_route(p, false));

    let reboot = net.now;
    (net, p, reboot)
}

#[test]
fn originator_rebooted_with_seqno_smaller_by_100_or_more_is_reacquired_once_sources_expire() {
    for gap in [100, 1000] {
        let (mut net, p, reboot) = rebooted_originator(gap);

        // Node 2's updates are unfeasible at nodes 1 and 0, which have advertised P with the
        // larger seqno (RFC 8966 §3.5.1), so P becomes unreachable. Node 1 would ask for a
        // seqno exceeding node 2's by more than 100, more than requests make up, as node 2
        // raises its seqno by only 1 per request (§3.8.1.2). So node 1 sends no requests
        // beyond the one for the lost route and its 3 resends, and node 2 ignores those.
        net.run_for(Duration::from_secs(60));
        assert_eq!(requests_sent(&net, 1, 2, reboot).len(), 4);
        assert_eq!(net.delivered_to(0, p.addr()), None);

        // Each node's feasibility distance for P expires 3 minutes after the node last
        // advertised P with a finite metric, which it did before holding P. Its route
        // through the next node then becomes feasible, and is selected at once. Node 1 holds
        // P before node 0, and announces it as an urgent TLV.
        net.run_for(Duration::from_secs(240));
        assert_eq!(net.path(0, p.addr()), [0, 1, 2]);
        let mut changes = net
            .fib_changes
            .iter()
            .filter(|change| (change.node, change.prefix) == (0, p) && change.time >= reboot);
        let held = changes.next().unwrap();
        assert_eq!(held.entry, Some(Fib::Unreachable));
        let recovered = changes.next_back().unwrap();
        assert_eq!(recovered.entry, Some(Fib::Via(1)));
        assert!(recovered.time - held.time <= Duration::from_secs(3 * 60 + 2));
    }
}

#[test]
fn originator_rebooted_with_seqno_smaller_by_up_to_99_is_reacquired_through_requests() {
    // As above, but with node 2's seqno at most 99 short, so that node 1 asks for a seqno
    // exceeding it by at most 100. Each reply from node 2 raises its seqno by only 1, and is
    // unfeasible too, but once the link between nodes 1 and 2 is back up, prompts node 1 to
    // send another request, as the route would be selected were it feasible (RFC 8966
    // §3.8.2.2), until the route is feasible. This takes one request per seqno that node 2's
    // falls short by, and up to 2 more where requests overlap. P is regained within seconds,
    // rather than 3 minutes, and up to 3 more if the link is back up early enough that replies
    // overlap with the resends of the request for the lost route. The link is back up once node
    // 2 has heard two of node 1's Hellos and said so in an unscheduled IHU.
    for (gap, within) in [(10, 23), (99, 45)] {
        let (mut net, p, reboot) = rebooted_originator(gap);

        net.run_for(Duration::from_secs(60));
        assert_eq!(net.path(0, p.addr()), [0, 1, 2]);
        let changes: Vec<_> = (net.fib_changes.iter())
            .filter(|change| (change.node, change.prefix) == (0, p) && change.time >= reboot)
            .collect();
        let [held, regained] = changes[..] else {
            panic!("node 0 should hold P, then regain it");
        };
        assert_eq!(held.entry, Some(Fib::Unreachable));
        assert_eq!(regained.entry, Some(Fib::Via(1)));
        assert!(regained.time - held.time <= Duration::from_secs(within));
        let requests = requests_sent(&net, 1, 2, reboot).len();
        assert!(
            (usize::from(gap)..=usize::from(gap) + 3).contains(&requests),
            "{gap}: {requests}"
        );
    }
}

#[test]
fn random_link_failures_cause_no_loops() {
    random_link_failures(Duration::ZERO);
}

#[test]
fn reordered_packets_cause_no_loops() {
    // Loop-freedom does not rely on packets arriving in order: whether an update is feasible
    // depends only on its own seqno and metric (RFC 8966 §3.5.1), and a late one is still
    // backed by its sender's feasibility distance, which only gets better. Here, packets take
    // up to 1 s longer than their link's latency, so that those sent close together on a link
    // often arrive out of order.
    random_link_failures(Duration::from_secs(1));
}

/// Fails and recovers links at random in a mesh of 6 nodes, with packets delayed by up to
/// `jitter` beyond their link's latency, then checks that every node reaches every prefix.
fn random_link_failures(jitter: Duration) {
    const N: usize = 6;
    let edges = [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 0),
        (0, 3),
        (1, 4),
    ];
    let mut rng = StdRng::seed_from_u64(1);

    let mut net = Net::new(N);
    net.jitter = jitter;
    for (a, b) in edges {
        net.connect(a, b, Duration::from_millis(rng.random_range(0..60)));
    }
    let links = net.links.clone();

    // Every node originates a prefix, and node 0 a default route covering them all, nonexclusive
    // so that they don't conflict with it.
    let prefixes: Vec<_> = (0..N).map(|i| prefix(&format!("fd00:{i}::/64"))).collect();
    for (i, &p) in prefixes.iter().enumerate() {
        net.originate(i, p);
    }
    net.originate_nonexclusive(0, prefix("::/0"));

    // Links fail and recover at random, while the harness checks for forwarding loops
    // whenever a forwarding table changes.
    for _ in 0..60 {
        let (a, b) = edges[rng.random_range(0..edges.len())];
        if net.links.remove(&(a, b)).is_some() {
            net.links.remove(&(b, a));
        } else {
            net.links.insert((a, b), links[&(a, b)]);
            net.links.insert((b, a), links[&(b, a)]);
        }
        net.run_for(Duration::from_secs(rng.random_range(5..30)));
    }

    // Once all links are back, every node reaches every prefix. One that lost a prefix
    // regains it once a seqno request is answered, or at worst once its feasibility
    // distance is garbage-collected, 3 minutes after it last advertised the prefix.
    net.links = links;
    net.run_for(Duration::from_secs(400));
    for i in 0..N {
        for (j, p) in prefixes.iter().enumerate() {
            assert_eq!(net.delivered_to(i, p.addr()), Some(j), "from {i} to {p}");
        }
    }
}

/// Sets up node 0 with a route learnt from node 1, a local route, and neighbour 9,
/// outside the simulation. Returns the learnt and local prefixes, between periodic
/// dumps, which are sent every 16 s and flushed within 2 s.
fn requested_net() -> (Net, IpNet, IpNet) {
    let learnt = prefix("fd00:1::/64");
    let local = prefix("fd00::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.add_neighbour(0, 9);
    net.originate(0, local);
    net.originate(1, learnt);
    net.run_for(Duration::from_secs(20));
    assert_eq!(net.fib(0, learnt), Some(Fib::Via(1)));

    (net, learnt, local)
}

/// Returns the TLVs, other than updates, that node `from` sent to node `to` since `start`.
fn tlvs_sent(net: &Net, from: usize, to: usize, start: Instant) -> Vec<Tlv> {
    let sent = net.sent.iter();
    let sent = sent.filter(|sent| (sent.from, sent.to) == (from, to) && sent.time >= start);
    sent.flat_map(|sent| tlvs(&sent.buf)).collect()
}

/// Returns the updates that node `from` sent to node `to` since `start`.
fn updates_sent(net: &Net, from: usize, to: usize, start: Instant) -> Vec<Update> {
    let sent = net.sent.iter();
    let sent = sent.filter(|sent| (sent.from, sent.to) == (from, to) && sent.time >= start);
    sent.flat_map(|sent| updates(&sent.buf)).collect()
}

#[test]
fn route_requests_are_answered() {
    let (mut net, learnt, local) = requested_net();
    let unknown = prefix("fd00:9::/64");
    let local_v4 = prefix("10.0.0.0/16");
    let unknown_v4 = prefix("10.9.0.0/16");
    let interval = 1600;
    net.originate(0, local_v4);

    let start = net.now;
    for p in [learnt, local, unknown] {
        net.inject(9, 0, &route_request(Ae::Ipv6, 64, &octets(p)[..8]));
    }
    // A request for an IPv4 prefix may have AE 1 or 4.
    for p in [local_v4, unknown_v4] {
        for ae in [Ae::Ipv4, Ae::V4ViaV6] {
            net.inject(9, 0, &route_request(ae, 16, &octets(p)[..2]));
        }
    }
    // So is a request from the neighbour that the route was learnt from, although
    // updates are otherwise not sent back to it (RFC 8966 §3.7.4).
    net.inject(1, 0, &route_request(Ae::Ipv6, 64, &octets(learnt)[..8]));
    net.run_for(Duration::from_secs(3));

    // Each request is answered with the route that node 0 advertises, or else with
    // a retraction carrying its own router-id and seqno, with AE 4 for an IPv4 prefix
    // whichever AE the request has (RFC 8966 §3.8.1.1, RFC 9229 §2.3).
    let (seqno_0, seqno_1) = (net.nodes[0].seqno.get(), net.nodes[1].seqno.get());
    assert_eq!(
        updates_sent(&net, 0, 9, start),
        [
            update(learnt, 2, seqno_1, 96, interval),
            update(local, 1, seqno_0, 0, interval),
            update(unknown, 1, seqno_0, METRIC_INFINITY, interval),
            update(local_v4, 1, seqno_0, 0, interval),
            update(local_v4, 1, seqno_0, 0, interval),
            update(unknown_v4, 1, seqno_0, METRIC_INFINITY, interval),
            update(unknown_v4, 1, seqno_0, METRIC_INFINITY, interval),
        ]
    );
    assert_eq!(
        updates_sent(&net, 0, 1, start),
        [update(learnt, 2, seqno_1, 96, interval)]
    );
}

#[test]
fn wildcard_route_requests_are_answered_with_full_dumps() {
    let (mut net, learnt, local) = requested_net();

    // A wildcard request is answered with a full dump, sent to the requester only.
    let start = net.now;
    net.inject(9, 0, &route_request(Ae::Wildcard, 0, &[]));
    net.run_for(Duration::from_secs(3));

    // A dump of both prefixes, in whichever order.
    let dumped = |net: &Net, to, start| {
        let mut prefixes: Vec<_> = (updates_sent(net, 0, to, start).into_iter())
            .map(|update| (update.plen, update.prefix))
            .collect();
        prefixes.sort();
        prefixes
    };
    let [local, learnt] = [local, learnt].map(|p| (p.prefix_len(), octets(p)));
    assert_eq!(dumped(&net, 9, start), [local, learnt]);
    assert_eq!(updates_sent(&net, 0, 1, start), []);

    // So is one from the neighbour that a route was learnt from, but without that route,
    // as in periodic dumps (RFC 8966 §3.7.4).
    let start = net.now;
    net.inject(1, 0, &route_request(Ae::Wildcard, 0, &[]));
    net.run_for(Duration::from_secs(3));
    assert_eq!(dumped(&net, 1, start), [local]);
}

#[test]
fn selected_routes_are_requested_shortly_before_they_expire() {
    // An IPv4 prefix is requested with AE 1 (RFC 9229 §2.3).
    for (p, ae) in [
        (prefix("fd00:9::/64"), Ae::Ipv6),
        (prefix("10.9.0.0/16"), Ae::Ipv4),
    ] {
        let near = update(p, 42, 1, 100, 1600);
        let far = update(p, 42, 1, 500, 1600);
        let request = Tlv::RouteRequest {
            ae,
            plen: p.prefix_len(),
            prefix: octets(p),
        };
        // The times since `start` at which node 0 sent neighbour `to` a route request for P.
        let requested = |net: &Net, to, start| -> Vec<_> {
            (net.sent.iter())
                .filter(|sent| (sent.from, sent.to) == (0, to) && sent.time >= start)
                .filter(|sent| tlvs(&sent.buf).contains(&request))
                .map(|sent| sent.time - start)
                .collect()
        };
        let buffered = Duration::from_millis(40_750)..Duration::from_millis(41_250);

        // Node 0 learns P from neighbours 8 and 9, which advertise an Update interval of
        // 16 s, and selects the route through neighbour 9. Neither sends another update, but
        // both stay up.
        let mut net = Net::new(1);
        net.add_neighbour(0, 8);
        net.add_neighbour(0, 9);
        let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
        let start = net.now;
        exchange(
            &mut net,
            &mut n8,
            &mut n9,
            44,
            from_ref(&far),
            from_ref(&near),
        );
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

        // 2.5 Update intervals after the update, 40 s, node 0 requests P from neighbour 9
        // (RFC 8966 §3.8.2.3), in a TLV buffered for 0.75 to 1.25 s, but not from neighbour
        // 8, as its route is not selected.
        let [after] = requested(&net, 9, start)[..] else {
            panic!("node 0 should request {p} once");
        };
        assert!(buffered.contains(&after));
        assert_eq!(requested(&net, 8, start), []);

        // Neighbour 9 answers with an update, which refreshes the route, so that it outlasts
        // the 3.5 Update intervals, 56 s, after which the route through neighbour 8 expires.
        // Node 0 requests P again 40 s after the answer.
        let answered = net.now;
        exchange(&mut net, &mut n8, &mut n9, 44, &[], from_ref(&near));
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
        let routes = &net.nodes[0].route_table.prefix_entries[&p].routes;
        assert!(!routes.contains_key(net.key(0, 8)));
        let [after] = requested(&net, 9, answered)[..] else {
            panic!("node 0 should request {p} once more");
        };
        assert!(buffered.contains(&after));
    }
}

#[test]
fn routes_missing_one_full_dump_in_two_are_not_requested() {
    thread_local! {
        static DUMPS: Cell<u32> = const { Cell::new(0) };
    }
    let p = prefix("fd00:1::/64");

    // Node 0 learns P from node 1, both with the default timers, but misses every other full
    // dump. It then receives one at most 33 s after the one before, plus up to 1.25 s for
    // buffering, within the 40 s after which it would request P (RFC 8966 §3.8.2.3).
    let mut net = Net::new(2);
    for i in 0..2 {
        let router_id = RouterId::new(i as u64 + 1).unwrap();
        net.nodes[i] = State::new(net.now, Params::new(), router_id, None);
    }
    // Node 1's dumps are its only packets with finite updates.
    net.filter = |from, _, packet| {
        let updates = updates(packet.as_bytes());
        let dump = from == 1
            && updates
                .iter()
                .any(|update| update.metric != METRIC_INFINITY);
        let missed = dump && DUMPS.with(|dumps| dumps.replace(dumps.get() + 1) % 2 == 1);
        (!missed).then_some(packet)
    };
    net.connect(0, 1, Duration::ZERO);
    net.originate(1, p);
    net.run_for(Duration::from_hours(1));

    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));
    assert!(DUMPS.get() > 180);
    // Only the wildcard one that each sends once its startup is over.
    let requests = (net.sent.iter()).flat_map(|sent| tlvs(&sent.buf));
    let requests: Vec<_> = requests
        .filter_map(|tlv| match tlv {
            Tlv::RouteRequest { ae, .. } => Some(ae),
            _ => None,
        })
        .collect();
    assert_eq!(requests, [Ae::Wildcard; 2]);
}

#[test]
fn requests_are_handled_after_route_selection() {
    let p = prefix("fd00:9::/64");
    let near = update(p, 42, 1, 100, 0x8000);
    // A packet from neighbour 9 retracting P, then asking for it.
    let retract_and_ask = |request: Tlv| {
        let mut encoder = PacketEncoder::new(1400);
        assert!(encoder.put_update(&update(p, 42, 1, METRIC_INFINITY, 0x8000)));
        assert!(encoder.put_tlv(&request));
        encoder.finalize().as_bytes().to_vec()
    };

    // With a feasible route through neighbour 8, node 0 answers a route request with that
    // route, which it selects once the packet is handled, rather than the retracted one.
    let (mut net, _, _) = two_routes(&update(p, 42, 1, 150, 0x8000), &near);
    net.run_for(Duration::from_secs(2));
    let start = net.now;
    let request = Tlv::RouteRequest {
        ae: Ae::Ipv6,
        plen: 64,
        prefix: octets(p),
    };
    net.inject(9, 0, &retract_and_ask(request));
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    net.run_for(Duration::from_secs(2));
    assert_eq!(
        updates_sent(&net, 0, 9, start),
        [update(p, 42, 1, 246, 1600)]
    );

    // With only an unfeasible route through neighbour 8, node 0 holds P once the packet is
    // handled, so it does not forward a seqno request from neighbour 9. It sends its own for
    // the same seqno to every neighbour instead (RFC 8966 §3.8.2.1).
    let (mut net, _, _) = two_routes(&update(p, 42, 1, 500, 0x8000), &near);
    net.run_for(Duration::from_secs(2));
    let start = net.now;
    let request = Tlv::SeqnoRequest {
        ae: Ae::Ipv6,
        plen: 64,
        seqno: Seqno::new(2),
        hop_count: NonZeroU8::new(64).unwrap(),
        router_id: RouterId::new(42).unwrap(),
        prefix: octets(p),
    };
    net.inject(9, 0, &retract_and_ask(request));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    net.run_for(Duration::from_secs(1));
    for to in [8, 9] {
        assert_eq!(requests_sent(&net, 0, to, start), [(42, 2, 64)]);
    }
}

/// Builds a packet with a seqno request for an IPv6 prefix.
fn seqno_request(prefix: IpNet, router_id: u64, seqno: u16, hop_count: u8) -> Vec<u8> {
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_tlv(&Tlv::SeqnoRequest {
        ae: Ae::Ipv6,
        plen: prefix.prefix_len(),
        seqno: Seqno::new(seqno),
        hop_count: NonZeroU8::new(hop_count).unwrap(),
        router_id: RouterId::new(router_id).unwrap(),
        prefix: octets(prefix),
    }));
    encoder.finalize().as_bytes().to_vec()
}

/// Returns the seqno requests that node `from` sent to node `to` since `start`, each with
/// the time since `start`, and its router-id, seqno and hop count.
fn seqno_requests_sent(
    net: &Net,
    from: usize,
    to: usize,
    start: Instant,
) -> Vec<(Duration, u64, u16, u8)> {
    let sent = net.sent.iter();
    let sent = sent.filter(|sent| (sent.from, sent.to) == (from, to) && sent.time >= start);
    sent.flat_map(|sent| {
        tlvs(&sent.buf)
            .into_iter()
            .filter_map(move |tlv| match tlv {
                Tlv::SeqnoRequest {
                    seqno,
                    hop_count,
                    router_id,
                    ..
                } => Some((
                    sent.time - start,
                    router_id.get(),
                    seqno.get(),
                    hop_count.get(),
                )),
                _ => None,
            })
    })
    .collect()
}

/// Returns the router-ids, seqnos and hop counts of [`seqno_requests_sent`].
fn requests_sent(net: &Net, from: usize, to: usize, start: Instant) -> Vec<(u64, u16, u8)> {
    let requests = seqno_requests_sent(net, from, to, start).into_iter();
    requests
        .map(|(_, router_id, seqno, hop_count)| (router_id, seqno, hop_count))
        .collect()
}

/// Sets up node 0 with a local prefix, a route to P through neighbour 9 (router-id 42,
/// seqno 10, metric 196), and neighbours 7 and 8, all outside the simulation. Returns the
/// local prefix, P and neighbour 9, which has just sent a Hello, between periodic dumps.
fn seqno_net() -> (Net, IpNet, IpNet, Scripted) {
    let local = prefix("fd00::/64");
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.originate(0, local);
    for j in [7, 8, 9] {
        net.add_neighbour(0, j);
    }
    let mut n9 = Scripted::new(9);
    n9.send(&mut net, 0, &[update(p, 42, 10, 100, 0x8000)]);
    for _ in 0..5 {
        net.run_for(Duration::from_secs(4));
        n9.send(&mut net, 0, &[]);
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    (net, local, p, n9)
}

/// What node 0 sends: updates, and seqno requests, each with the neighbour it is sent to.
type Answers = (Vec<(usize, Update)>, Vec<(usize, (u64, u16, u8))>);

/// Sends node 0 a packet from node `from`, returning what node 0 sends neighbours 7, 8 and
/// 9 within the urgent timeout of 0.2 s.
fn ask(net: &mut Net, from: usize, buf: &[u8]) -> Answers {
    let start = net.now;
    net.inject(from, 0, buf);
    net.run_for(Duration::from_millis(200));

    let mut answers = Answers::default();
    for to in [7, 8, 9] {
        let updates = updates_sent(net, 0, to, start).into_iter();
        answers.0.extend(updates.map(|update| (to, update)));
        let requests = requests_sent(net, 0, to, start).into_iter();
        answers.1.extend(requests.map(|request| (to, request)));
    }
    answers
}

#[test]
fn seqno_requests_are_answered_or_forwarded() {
    let (mut net, local, p, _) = seqno_net();
    let other = prefix("fd00:77::/64");
    let seqno = net.nodes[0].seqno.get();
    let interval = 1600;

    // A request for its own prefix with a seqno larger than node 0's makes it increase its
    // seqno by only 1 (RFC 8966 §3.8.1.2), and send the requester an update as an urgent TLV.
    let answer = (7, update(local, 1, seqno.wrapping_add(1), 0, interval));
    let request = seqno_request(local, 1, seqno.wrapping_add(5), 64);
    assert_eq!(ask(&mut net, 7, &request), (vec![answer.clone()], vec![]));
    assert_eq!(net.nodes[0].seqno.get(), seqno.wrapping_add(1));

    // So does a request that its seqno already satisfies, without the increase.
    let request = seqno_request(local, 1, seqno.wrapping_add(1), 64);
    assert_eq!(ask(&mut net, 7, &request), (vec![answer], vec![]));

    // A request for a route that node 0 advertises is answered with that route, if the
    // seqno satisfies it, or if the router-ids differ.
    let answer = (7, update(p, 42, 10, 196, interval));
    for request in [seqno_request(p, 42, 10, 64), seqno_request(p, 99, 1, 64)] {
        assert_eq!(ask(&mut net, 7, &request), (vec![answer.clone()], vec![]));
    }

    // Otherwise, it is forwarded as an urgent TLV to the next hop, with its hop count
    // decremented, unless the hop count is 1, or the only next hop is the requester.
    let request = seqno_request(p, 42, 11, 3);
    assert_eq!(ask(&mut net, 7, &request), (vec![], vec![(9, (42, 11, 2))]));
    let request = seqno_request(p, 42, 12, 1);
    assert_eq!(ask(&mut net, 7, &request), Answers::default());
    let request = seqno_request(p, 42, 12, 3);
    assert_eq!(ask(&mut net, 9, &request), Answers::default());

    // A request for an unknown prefix is ignored.
    let request = seqno_request(other, 42, 1, 3);
    assert_eq!(ask(&mut net, 7, &request), Answers::default());
}

#[test]
fn seqno_requests_for_much_larger_seqnos_are_ignored() {
    let (mut net, local, _, _) = seqno_net();
    let seqno = net.nodes[0].seqno.get();
    let interval = 1600;

    // A request for its own prefix with a seqno exceeding node 0's by more than 100 most
    // likely comes from a seqno it has lost, and cannot be satisfied by raising its seqno
    // by 1, so it is ignored, as in babeld.
    let request = seqno_request(local, 1, seqno.wrapping_add(101), 64);
    assert_eq!(ask(&mut net, 7, &request), Answers::default());
    assert_eq!(net.nodes[0].seqno.get(), seqno);

    // One exceeding it by at most 100 is answered as usual.
    let answer = (7, update(local, 1, seqno.wrapping_add(1), 0, interval));
    let request = seqno_request(local, 1, seqno.wrapping_add(100), 64);
    assert_eq!(ask(&mut net, 7, &request), (vec![answer], vec![]));
}

#[test]
fn seqno_requests_are_forwarded_along_the_selected_route() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    for j in [7, 8, 9] {
        net.add_neighbour(0, j);
    }
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // As in `hysteresis_needs_a_lower_metric_as_well`, the route through neighbour 9, of
    // metric 596, is selected, and kept although the route through neighbour 8 has metric
    // 196. Both routes have the same source, and both are feasible.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        8,
        from_ref(&near),
        from_ref(&far),
    );
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // A request from neighbour 7 is forwarded to neighbour 9, the next hop of the selected
    // route, rather than to neighbour 8, whose route has the smallest metric. A reply then
    // updates the selected route, and is forwarded on as an urgent TLV (RFC 8966 §3.8.1.2).
    let request = seqno_request(p, 42, 2, 3);
    assert_eq!(ask(&mut net, 7, &request), (vec![], vec![(9, (42, 2, 2))]));

    // A request from neighbour 9 itself is forwarded to neighbour 8 instead.
    let request = seqno_request(p, 42, 3, 3);
    assert_eq!(ask(&mut net, 9, &request), (vec![], vec![(8, (42, 3, 2))]));
}

#[test]
fn seqno_requests_are_not_forwarded_over_failed_links() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    for j in [7, 8, 9] {
        net.add_neighbour(0, j);
    }
    let mut neighbours = [7, 8, 9].map(Scripted::new);

    // Node 0 selects the route through neighbour 9, of metric 196. The route through
    // neighbour 8, of metric 596, is unfeasible. That through neighbour 7 is feasible, with
    // an advertised metric of 50, but neighbour 7 reports an infinite rxcost, so the link
    // to it has failed one way, and the route has an infinite metric.
    neighbours[0].rxcost = Some(INF);
    let updates = [50, 500, 100].map(|metric| update(p, 42, 1, metric, 0x8000));
    for round in 0..2 {
        for (n, update) in neighbours.iter_mut().zip(&updates).rev() {
            n.send(&mut net, 0, if round == 0 { from_ref(update) } else { &[] });
        }
        net.run_for(Duration::from_secs(4));
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    let route = net.nodes[0].route_table.prefix_entries[&p]
        .routes
        .get(net.key(0, 7));
    assert_eq!(route.map(|r| r.metric.get()), Some(METRIC_INFINITY));

    // A request from neighbour 9, the next hop of the selected route, is forwarded to
    // neighbour 8, whose route is unfeasible, rather than to neighbour 7, whose route is
    // feasible, but whose link has failed (RFC 8966 §3.8.1.2).
    let request = seqno_request(p, 42, 2, 3);
    assert_eq!(ask(&mut net, 9, &request), (vec![], vec![(8, (42, 2, 2))]));
}

#[test]
fn replies_are_forwarded_urgently_when_a_requesters_retraction_is_late() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 42, 1, 150, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let reply = update(p, 42, 2, 150, 0x8000);
    let retraction = update(p, 42, 1, METRIC_INFINITY, 0x8000);

    for reply_first in [true, false] {
        // Node 0 selects the route through neighbour 9, and has a feasible one through
        // neighbour 8. Neighbour 9 loses P, but its retraction is late, and its seqno request
        // comes first. Node 0 still routes through neighbour 9, so it forwards the request
        // along the route through neighbour 8, which it selects once the retraction comes
        // (RFC 8966 §3.8.1.2).
        let (mut net, mut n8, mut n9) = two_routes(&far, &near);
        net.run_for(Duration::from_secs(2));
        let start = net.now;
        net.inject(9, 0, &seqno_request(p, 42, 2, 64));
        net.run_for(Duration::from_millis(200));
        assert_eq!(requests_sent(&net, 0, 8, start), [(42, 2, 63)]);

        // Whichever of neighbour 8's reply and neighbour 9's retraction comes first, nothing
        // is sent then. Once both have come, node 0 selects the route through neighbour 8
        // with the new seqno, which satisfies the request, so it announces the route to
        // neighbour 9 as an urgent TLV, within 0.125 s.
        if reply_first {
            n8.send(&mut net, 0, from_ref(&reply));
        } else {
            n9.send(&mut net, 0, from_ref(&retraction));
        }
        net.run_for(Duration::from_millis(500));
        assert_eq!(updates_sent(&net, 0, 9, start), []);

        let last = net.now;
        if reply_first {
            n9.send(&mut net, 0, from_ref(&retraction));
        } else {
            n8.send(&mut net, 0, from_ref(&reply));
        }
        assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
        net.run_for(Duration::from_millis(125));
        assert_eq!(
            updates_sent(&net, 0, 9, last),
            [update(p, 42, 2, 246, 1600)]
        );
    }
}

#[test]
fn redundant_seqno_requests_are_not_forwarded() {
    let (mut net, _, p, _) = seqno_net();
    let start = net.now;

    // A request from neighbour 7 is forwarded to neighbour 9.
    net.inject(7, 0, &seqno_request(p, 42, 11, 3));
    net.run_for(Duration::from_millis(500));

    // The same request from neighbour 8 within 1 s is redundant, and is not forwarded
    // (RFC 8966 §3.8.1.2). One with a newer seqno is.
    net.inject(8, 0, &seqno_request(p, 42, 11, 3));
    net.inject(8, 0, &seqno_request(p, 42, 12, 3));
    net.run_for(Duration::from_millis(1100));

    // After 1 s, the same request is forwarded again, since its originator may resend it
    // after the initial request timeout of 2 s, in case it was lost.
    net.inject(7, 0, &seqno_request(p, 42, 12, 3));
    net.run_for(Duration::from_millis(500));

    let requests = [(42, 11, 2), (42, 12, 2), (42, 12, 2)];
    assert_eq!(requests_sent(&net, 0, 9, start), requests);
}

#[test]
fn satisfying_updates_are_forwarded_urgently() {
    let (mut net, _, p, mut n9) = seqno_net();
    let interval = 1600;

    // Node 0 forwards a request from neighbour 7 to neighbour 9.
    net.inject(7, 0, &seqno_request(p, 42, 11, 3));
    net.run_for(Duration::from_millis(500));

    // An update from neighbour 9 satisfies it, so node 0 forwards it as an urgent TLV
    // (RFC 8966 §3.8.1.2), to every neighbour but neighbour 9, by split horizon.
    let start = net.now;
    n9.send(&mut net, 0, &[update(p, 42, 11, 100, 0x8000)]);
    net.run_for(Duration::from_millis(200));
    for to in [7, 8] {
        assert_eq!(
            updates_sent(&net, 0, to, start),
            [update(p, 42, 11, 196, interval)]
        );
    }

    // A newer seqno that satisfies no request waits for the next periodic update, since a
    // node SHOULD NOT send triggered updates to propagate a new seqno (RFC 8966 §3.7.2).
    let start = net.now;
    n9.send(&mut net, 0, &[update(p, 42, 12, 100, 0x8000)]);
    net.run_for(Duration::from_secs(2));
    assert_eq!(updates_sent(&net, 0, 7, start), []);
}

#[test]
fn lost_routes_are_requested_from_every_neighbour() {
    let p = prefix("fd00:9::/64");
    // Node 0 advertises P with metric 196 through neighbour 9, so the route through
    // neighbour 8 is unfeasible.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Neighbour 9 retracts P. Node 0 has lost all feasible routes but an unfeasible one,
    // so it MUST send a seqno request, with the router-id of the lost route and the seqno
    // in the source table plus 1, and SHOULD resend it if no route becomes feasible (RFC
    // 8966 §3.8.2.1): to every neighbour, 2, 6 and 14 s later (Appendix B), each as an
    // urgent TLV within 0.2 s after being due.
    let start = net.now;
    let retraction = update(p, 42, 1, METRIC_INFINITY, 0x8000);
    exchange(&mut net, &mut n8, &mut n9, 4, &[], from_ref(&retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    // Neighbour 8 refreshes its unfeasible route 4, 8 and 12 s in. Each refresh also prompts
    // a request to it, as the route would be selected were it feasible (§3.8.2.2, Erratum
    // 7373). These requests are not recorded, so the resends go on.
    for _ in 0..3 {
        exchange(&mut net, &mut n8, &mut n9, 4, from_ref(&far), &[]);
    }
    exchange(&mut net, &mut n8, &mut n9, 24, &[], &[]);
    for (to, due) in [(8, &[0, 2, 4, 6, 8, 12, 14][..]), (9, &[0, 2, 6, 14])] {
        assert_eq!(
            requests_sent(&net, 0, to, start),
            vec![(42, 2, 64); due.len()]
        );
        let requests = seqno_requests_sent(&net, 0, to, start);
        for ((after, ..), &due) in requests.into_iter().zip(due) {
            let due = Duration::from_secs(due);
            assert!(due <= after && after <= due + Duration::from_millis(200));
        }
    }
}

#[test]
fn requested_routes_are_announced_urgently_and_end_resends() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);

    // Neighbour 8 announces seqno 2, or router-id 43. Either makes its route feasible, and
    // satisfies the request (RFC 8966 §4.6.11).
    for regained in [update(p, 42, 2, 500, 0x8000), update(p, 43, 1, 500, 0x8000)] {
        let (mut net, mut n8, mut n9) = two_routes(&far, &near);

        // As above, node 0 loses P, and requests seqno 2 for router-id 42.
        let retraction = update(p, 42, 1, METRIC_INFINITY, 0x8000);
        exchange(&mut net, &mut n8, &mut n9, 4, &[], from_ref(&retraction));
        assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

        // Node 0 selects the route, which satisfies the request, so the request is dropped
        // at once. Node 0 announces the route as an urgent TLV, to neighbour 9 only, by split
        // horizon, and no longer resends the request.
        let start = net.now;
        n8.send(&mut net, 0, from_ref(&regained));
        assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
        assert!(!net.nodes[0].seqno_request_table.contains_key(&p));
        net.run_for(Duration::from_millis(200));
        let announced = Update {
            metric: 596,
            interval: Interval::new(1600).unwrap(),
            ..regained
        };
        assert_eq!(updates_sent(&net, 0, 9, start), [announced]);
        exchange(&mut net, &mut n8, &mut n9, 40, &[], &[]);
        for to in [8, 9] {
            assert_eq!(requests_sent(&net, 0, to, start), []);
        }
    }
}

#[test]
fn requests_are_satisfied_by_another_router_id_after_the_hold() {
    let p = prefix("fd00:9::/64");
    let near = nonexclusive_update(p, 42, 1, 100, 0x8000);
    let far = nonexclusive_update(p, 42, 1, 500, 0x8000);
    let other = nonexclusive_update(p, 43, 1, 500, 0x8000);

    // With a Hello interval of 1 s, node 0 holds a lost prefix for only 16 s, while a request
    // for it is pending for 30 s: sent at 0, 2, 6 and 14 s, and kept for 16 s after the last.
    // During the hold, neighbour 8 has an unfeasible route, which keeps the prefix's entry
    // once the hold expires, or none, so that the entry goes.
    for unfeasible in [true, false] {
        let mut params = params();
        params.set_hello_interval(Interval::new(100).unwrap());
        let mut net = Net::new(1);
        net.nodes[0] = State::new(net.now, params, RouterId::new(1).unwrap(), None);
        net.add_neighbour(0, 8);
        net.add_neighbour(0, 9);
        let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
        let updates8: &[Update] = if unfeasible { from_ref(&far) } else { &[] };
        exchange(&mut net, &mut n8, &mut n9, 20, updates8, from_ref(&near));
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

        // Neighbour 9 retracts P, and node 0 requests seqno 2 for router-id 42. 20 s later,
        // the hold has expired, but the request is still pending.
        let retraction = nonexclusive_update(p, 42, 1, METRIC_INFINITY, 0x8000);
        exchange(&mut net, &mut n8, &mut n9, 4, &[], from_ref(&retraction));
        exchange(&mut net, &mut n8, &mut n9, 16, &[], &[]);
        assert_eq!(net.fib(0, p), None);

        // Neighbour 8 then announces P with router-id 43, which satisfies the request (RFC
        // 8966 §4.6.11), although the advertisement for router-id 42 is gone, so the request
        // is dropped. Node 0 announces the route as an urgent TLV, within 0.125 s, to neighbour
        // 9 only, by split horizon.
        let regain = net.now;
        n8.send(&mut net, 0, from_ref(&other));
        assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
        assert!(!net.nodes[0].seqno_request_table.contains_key(&p));
        net.run_for(Duration::from_millis(125));
        let announced = Update {
            metric: 596,
            interval: Interval::new(400).unwrap(),
            ..other
        };
        assert_eq!(updates_sent(&net, 0, 9, regain), [announced]);
    }
}

#[test]
fn requests_are_not_resent_once_a_route_is_selected() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near);

    // As above, node 0 loses P, and requests seqno 2 for router-id 42.
    let retraction = update(p, 42, 1, METRIC_INFINITY, 0x8000);
    exchange(&mut net, &mut n8, &mut n9, 4, &[], from_ref(&retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    // Neighbour 8 then announces P with metric 50, below the 196 that node 0 advertised.
    // This makes its route feasible, though it does not satisfy the request, with the same
    // router-id and seqno. Node 0 selects it, and keeps the request until its timer expires,
    // but no longer resends it.
    let start = net.now;
    n8.send(&mut net, 0, &[update(p, 42, 1, 50, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    assert!(net.nodes[0].seqno_request_table.contains_key(&p));
    exchange(&mut net, &mut n8, &mut n9, 40, &[], &[]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    for to in [8, 9] {
        assert_eq!(requests_sent(&net, 0, to, start), []);
    }
}

#[test]
fn own_requests_stop_suppressing_forwarding_once_a_route_is_selected() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near);

    // As above, node 0 loses P, requests seqno 2 for router-id 42, and resends the request
    // 2 s later. Neighbour 8 then makes its route feasible without satisfying the request,
    // and node 0 selects it, so the request will not be resent again.
    n9.send(&mut net, 0, &[update(p, 42, 1, METRIC_INFINITY, 0x8000)]);
    net.run_for(Duration::from_millis(2500));
    n8.send(&mut net, 0, &[update(p, 42, 1, 50, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    net.run_for(Duration::from_millis(1500));

    // So a request from neighbour 9 for the same seqno, 2 s after the resend, is not
    // redundant, and node 0 forwards it to neighbour 8 (RFC 8966 §3.8.1.2).
    let start = net.now;
    net.inject(9, 0, &seqno_request(p, 42, 2, 3));
    net.run_for(Duration::from_millis(200));
    assert_eq!(requests_sent(&net, 0, 8, start), [(42, 2, 2)]);
}

#[test]
fn lost_routes_are_regained_through_seqno_requests() {
    let p = prefix("fd00:2::/64");

    // Node 0 reaches node 2 through node 1, and once connected to node 3, also through
    // nodes 3 and 4. Node 3 advertises P with metric 192, not below the 192 that node 0
    // advertises, so node 0's route through node 3 is unfeasible.
    let mut net = Net::new(5);
    for (a, b) in [(0, 1), (1, 2), (3, 4), (4, 2)] {
        net.connect(a, b, Duration::from_millis(10));
    }
    net.originate(2, p);
    net.run_for(Duration::from_secs(60));
    net.connect(0, 3, Duration::from_millis(10));
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // The link between nodes 0 and 1 fails. Once node 0 notices, it holds P, and sends a
    // seqno request (RFC 8966 §3.8.2.1). Nodes 3 and 4 forward it to node 2, which
    // increases its seqno, and they forward the reply back (§3.8.1.2). Each of these six
    // packets is sent as an urgent TLV within 0.125 s, so over links of 10 ms, the route
    // through node 3 becomes feasible within 1 s, rather than once node 0's feasibility
    // distance expires, 3 minutes after it last advertised P.
    let changes = net.fib_changes.len();
    net.links.remove(&(0, 1));
    net.links.remove(&(1, 0));
    net.run_for(Duration::from_secs(30));
    assert_eq!(net.path(0, p.addr()), [0, 3, 4, 2]);

    let changes: Vec<_> = (net.fib_changes[changes..].iter())
        .filter(|change| (change.node, change.prefix) == (0, p))
        .collect();
    let [held, regained] = changes[..] else {
        panic!("node 0 should hold P, then regain it");
    };
    assert_eq!(held.entry, Some(Fib::Unreachable));
    assert_eq!(regained.entry, Some(Fib::Via(3)));
    assert!(regained.time - held.time <= Duration::from_secs(1));
}

#[test]
fn ending_a_hold_is_announced_urgently() {
    let p = prefix("fd00::/64");

    for flap in [true, false] {
        // Node 0 originates P, which nodes 1 to 4 reach along a chain. The link between nodes
        // 0 and 1 fails, so they all hold P.
        let mut net = Net::new(6);
        for (a, b) in [(0, 1), (1, 2), (2, 3), (3, 4), (0, 5)] {
            net.connect(a, b, Duration::from_millis(10));
        }
        net.originate(0, p);
        net.run_for(Duration::from_secs(60));
        let changes = net.fib_changes.len();
        let latency = net.links.remove(&(0, 1)).unwrap();
        net.links.remove(&(1, 0));

        // Node 1 then regains P, either as the link comes back after 15 s, or through node 5,
        // connected 40 s after the failure, once its request for a new seqno has expired.
        // Neither need satisfy that request.
        if flap {
            net.run_for(Duration::from_secs(15));
            assert_eq!(net.fib(4, p), Some(Fib::Unreachable));
            net.links.insert((0, 1), latency);
            net.links.insert((1, 0), latency);
        } else {
            net.run_for(Duration::from_secs(40));
            assert_eq!(net.fib(4, p), Some(Fib::Unreachable));
            net.connect(1, 5, Duration::from_millis(10));
        }
        net.run_for(Duration::from_secs(60));
        let path: &[usize] = if flap {
            &[4, 3, 2, 1, 0]
        } else {
            &[4, 3, 2, 1, 5, 0]
        };
        assert_eq!(net.path(4, p.addr()), path);

        // Each node ending its hold announces P as an urgent TLV (see `select_route`), so each
        // regains P within 0.2 s of the one before it.
        let regained = |i| {
            let changes = net.fib_changes[changes..].iter();
            let mut changes = changes.filter(|change| (change.node, change.prefix) == (i, p));
            let change = changes.next_back().unwrap();
            assert!(matches!(change.entry, Some(Fib::Via(_))));
            change.time
        };
        for i in 2..5 {
            assert!(regained(i) - regained(i - 1) <= Duration::from_millis(200));
        }
    }
}

#[test]
fn newly_reachable_prefixes_are_announced_urgently() {
    let q = prefix("fd00:99::/64");

    // Nodes 0 to 5 form a chain, along which node 0 starts originating Q. Node 1 first learns
    // of it from node 0's next periodic update (see `State::inject_route`).
    let mut net = Net::new(6);
    for i in 0..5 {
        net.connect(i, i + 1, Duration::from_millis(10));
    }
    net.run_for(Duration::from_secs(60));
    net.originate(0, q);
    let mut reached = [None; 6];
    for _ in 0..800 {
        net.run_for(Duration::from_millis(25));
        for (i, reached) in reached.iter_mut().enumerate().skip(1) {
            if reached.is_none() && net.delivered_to(i, q.addr()) == Some(0) {
                *reached = Some(net.now);
            }
        }
    }

    // Each node that newly reaches Q announces it as an urgent TLV (see `select_route`), so
    // each reaches Q within 0.2 s of the one before it.
    for i in 2..6 {
        let (Some(now), Some(before)) = (reached[i], reached[i - 1]) else {
            panic!("nodes {} and {i} should reach Q", i - 1);
        };
        assert!(now - before <= Duration::from_millis(200));
    }
}

/// Sets up a chain in which nodes 0 and 3 both originate P as nonexclusive, with router-ids 1 and
/// 4, so that node 1 routes P through node 0, and node 2 through node 3, each with a fallback route
/// through the other, which an exclusive P would rule out (see
/// [Duplicate addresses](State#duplicate-addresses)). Returns P.
fn two_sources_net() -> (Net, IpNet) {
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(4);
    for i in 1..4 {
        net.connect(i - 1, i, Duration::from_millis(10));
    }
    net.originate_nonexclusive(0, p);
    net.originate_nonexclusive(3, p);
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.fib(1, p), Some(Fib::Via(0)));
    assert_eq!(net.fib(2, p), Some(Fib::Via(3)));
    assert!(has_route(&net, 1, 2, p) && has_route(&net, 2, 1, p));
    (net, p)
}

/// Returns whether node `i` has a route to `p` through node `j`.
fn has_route(net: &Net, i: usize, j: usize, p: IpNet) -> bool {
    let entry = net.nodes[i].route_table.prefix_entries.get(&p);
    entry.is_some_and(|entry| entry.routes.contains_key(net.key(i, j)))
}

#[test]
fn switching_to_another_router_id_through_another_neighbour_retracts_the_route_from_it() {
    // Node 1 loses its route through node 0, and switches to the one through node 2, with
    // another router-id. Split horizon leaves node 2 out of the update for it, so node 1
    // retracts its old route from node 2 instead, which drops it.
    let (mut net, p) = two_sources_net();
    net.disconnect(0, 1);
    assert_eq!(net.fib(1, p), Some(Fib::Via(2)));
    net.run_for(Duration::from_secs(1));
    assert!(!has_route(&net, 2, 1, p));

    // So once node 2 loses its own route, it holds P, rather than routing it back through node
    // 1 by the stale route, which would make a loop until that route expired.
    net.disconnect(2, 3);
    assert_eq!(net.fib(2, p), Some(Fib::Unreachable));
    net.run_for(Duration::from_secs(1));
    assert_eq!(net.fib(1, p), Some(Fib::Unreachable));
}

#[test]
fn lost_retraction_of_a_stale_route_is_repeated_in_full_dumps() {
    thread_local! {
        static LOST: Cell<bool> = const { Cell::new(false) };
    }

    let (mut net, p) = two_sources_net();
    // The first retraction from node 1 to node 2 is lost.
    LOST.set(false);
    net.filter = |from, to, packet| {
        let retraction = (updates(packet.as_bytes()).iter())
            .any(|update| update.ae != Ae::Wildcard && update.metric == METRIC_INFINITY);
        let lost = (from, to) == (1, 2) && retraction && !LOST.replace(true);
        (!lost).then_some(packet)
    };
    net.disconnect(0, 1);
    let switch = net.now;
    net.run_for(Duration::from_secs(1));
    assert!(LOST.get());
    assert!(has_route(&net, 2, 1, p));

    // The next full dump from node 1 to node 2 retracts it again.
    net.run_for(Duration::from_secs(16));
    assert!(!has_route(&net, 2, 1, p));

    // So does every full dump until node 2 must have expired the route anyway, as long after
    // the switch as a prefix is held. After that, full dumps leave P out, by split horizon.
    let hold_time = net.nodes[1].params.get(DurationKey::RouteHoldTime);
    net.run_for(switch + hold_time + Duration::from_secs(20) - net.now);
    let retractions: Vec<_> = (net.sent.iter())
        .filter(|sent| (sent.from, sent.to) == (1, 2) && sent.time >= switch)
        .filter(|sent| (updates(&sent.buf).iter()).any(|update| is_for(update, p)))
        .map(|sent| sent.time - switch)
        .collect();
    // The urgent one, lost, then one per full dump, every 16 s.
    assert_eq!(retractions.len(), 5, "{retractions:?}");
    assert!(retractions.iter().all(|&after| after < hold_time));
}

#[test]
fn switching_from_a_held_prefix_to_another_router_id_retracts_the_prefix_again() {
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    let route = update(p, 42, 1, 100, 0x8000);
    exchange(&mut net, &mut n8, &mut n9, 20, &[], from_ref(&route));
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Node 0 loses its route, holds P, and retracts it from neighbour 8, which had learnt it, at
    // once and in its full dumps.
    n9.send(&mut net, 0, &[update(p, 42, 1, METRIC_INFINITY, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    let held = net.now;
    exchange(&mut net, &mut n8, &mut n9, 28, &[], &[]);

    // It then selects a route through neighbour 8, with another router-id. Should every
    // retraction so far have been lost, neighbour 8 would keep the stale route, so node 0 goes on
    // retracting P from it, at once and in its full dumps, rather than leaving it out of them.
    let start = net.now;
    n8.send(&mut net, 0, &[update(p, 43, 1, 100, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    exchange(&mut net, &mut n8, &mut n9, 60, &[], &[]);
    let retractions: Vec<_> = (net.sent.iter())
        .filter(|sent| (sent.from, sent.to) == (0, 8) && sent.time >= start)
        .filter(|sent| {
            (updates(&sent.buf).iter())
                .any(|update| is_for(update, p) && update.metric == METRIC_INFINITY)
        })
        .map(|sent| sent.time - held)
        .collect();
    assert!(retractions.len() >= 2, "{retractions:?}");

    // It does so only until the hold would have ended, by when neighbour 8 would have expired
    // any route through node 0 anyway, as it learnt it before the hold began. A dump is sent
    // within a flush delay of when it is put together.
    let hold_time = net.nodes[0].params.get(DurationKey::RouteHoldTime);
    let flush_delay = Duration::from_secs(2);
    assert!(
        retractions
            .iter()
            .all(|&after| after < hold_time + flush_delay),
        "{retractions:?}"
    );
}

/// Returns what node `node` reported of conflicts over `p` since `start`, as the neighbour each
/// report names and its kind, each pair once, in order.
fn reported(net: &Net, node: usize, p: IpNet, start: Instant) -> Vec<(usize, ConflictAlertKind)> {
    let mut seen: Vec<_> = (net.reports.iter())
        .filter(|r| r.node == node && r.prefix == p && r.time >= start)
        .map(|r| (r.from, r.kind))
        .collect();
    seen.sort_unstable();
    seen.dedup();
    seen
}

/// Returns the Conflict Alerts that node `from` sent to node `to` since `start`, as their
/// prefixes and Hops Away.
fn conflict_alerts_sent(net: &Net, from: usize, to: usize, start: Instant) -> Vec<(IpNet, u8)> {
    (tlvs_sent(net, from, to, start).into_iter())
        .filter_map(|tlv| match tlv {
            Tlv::ConflictAlert {
                ae,
                plen,
                hops_away,
                prefix,
            } => Some((decode_prefix(ae, plen, prefix).unwrap(), hops_away.get())),
            _ => None,
        })
        .collect()
}

/// Returns a Conflict Alert TLV for `p`, which says that the node that rejected an update is
/// `hops_away`.
fn conflict_alert(p: IpNet, hops_away: u8) -> Tlv {
    let (ae, plen, prefix) = encode_prefix(p, Ae::Ipv4);
    Tlv::ConflictAlert {
        ae,
        plen,
        hops_away: NonZeroU8::new(hops_away).unwrap(),
        prefix,
    }
}

/// Returns the kind of a report of a Conflict Alert that says the routes meet `hops` away.
fn alerted(hops: usize) -> ConflictAlertKind {
    ConflictAlertKind::Alerted {
        hops: NonZeroU8::new(hops as u8).unwrap(),
    }
}

#[test]
fn conflicting_origins_keep_their_sides_and_are_both_told() {
    use ConflictAlertKind::Rejected;

    const N: usize = 6;
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(N);
    for i in 1..N {
        net.connect(i - 1, i, Duration::from_millis(10));
    }
    net.originate(0, p);
    net.originate(N - 1, p);
    net.run_for(Duration::from_secs(60));

    // Each node keeps the route to the originator it heard of first, so the chain splits into
    // two sides, which meet between nodes k and k + 1.
    let sides: Vec<_> = (0..N).map(|i| net.delivered_to(i, p.addr())).collect();
    let k = sides.iter().rposition(|&o| o == Some(0)).unwrap();
    assert!(k < N - 1, "{sides:?}");
    assert!(
        sides[k + 1..].iter().all(|&o| o == Some(N - 1)),
        "{sides:?}"
    );

    // Nothing changes over the next minutes, while every node reports what it sees, again and
    // again: those where the sides meet reject each other's updates, and send alerts towards
    // their own originators, which the nodes on the way forward, each knowing how far away the
    // rejecting node on its side is.
    let start = net.now;
    let changes = net.fib_changes.len();
    net.run_for(Duration::from_secs(180));
    assert_eq!(net.fib_changes.len(), changes, "routes should stay put");

    for i in 0..N {
        let expected = if i == k {
            vec![(k + 1, Rejected)]
        } else if i == k + 1 {
            vec![(k, Rejected)]
        } else if i < k {
            vec![(i + 1, alerted(k - i))]
        } else {
            vec![(i - 1, alerted(i - (k + 1)))]
        };
        assert_eq!(
            reported(&net, i, p, start),
            expected,
            "node {i}, meeting at {k}"
        );

        let count = (net.reports.iter())
            .filter(|r| r.node == i && r.time >= start)
            .count();
        assert!(count >= 9, "node {i} reported only {count} times");
    }

    // From either originator, following the neighbours that the reports name leads to where
    // the sides meet, and from there, the selected routes lead to the other originator.
    let trace = |origin: usize| {
        let mut path = vec![origin];
        loop {
            let [(from, kind)] = reported(&net, *path.last().unwrap(), p, start)[..] else {
                panic!("each node should report one thing");
            };
            path.push(from);
            if kind == Rejected {
                return (path, net.delivered_to(from, p.addr()));
            }
        }
    };
    let (path, other) = trace(0);
    assert_eq!((path, other), ((0..=k + 1).collect(), Some(N - 1)));
    let (path, other) = trace(N - 1);
    assert_eq!((path, other), ((k..N).rev().collect(), Some(0)));
}

#[test]
fn conflicting_update_removes_the_route_through_its_sender() {
    let p = prefix("fd00:9::/64");
    // Node 0 learns P with one router-id from neighbours 8 and 9, and selects the route through
    // neighbour 9. The one through neighbour 8 has a newer seqno, so that it is feasible.
    let far = update(p, 42, 2, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, _n8, mut n9) = two_routes(&far, &near);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Neighbour 9 switches to another router-id, which conflicts with the route through
    // neighbour 8. Its update is rejected, and its old route removed, so node 0 switches to the
    // route through neighbour 8, and sends an alert along it.
    let start = net.now;
    n9.send(&mut net, 0, &[update(p, 43, 1, 100, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    assert!(!has_route(&net, 0, 9, p));
    assert_eq!(
        reported(&net, 0, p, start),
        [(9, ConflictAlertKind::Rejected)]
    );
    net.run_for(Duration::from_secs(2));
    assert_eq!(conflict_alerts_sent(&net, 0, 8, start), [(p, 1)]);
    assert_eq!(conflict_alerts_sent(&net, 0, 9, start), []);
}

#[test]
fn unfeasible_routes_block_conflicting_updates() {
    let p = prefix("fd00:9::/64");
    // The route through neighbour 8 is unfeasible, as its metric exceeds that of the route
    // through neighbour 9, which node 0 advertises.
    let far = update(p, 42, 1, 2000, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, _n8, mut n9) = two_routes(&far, &near);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Neighbour 9 loses its route, and node 0 holds P, asking for a new seqno, which could make
    // the route through neighbour 8 feasible. Meanwhile, a route with another router-id doesn't
    // take over.
    n9.send(&mut net, 0, &[update(p, 42, 1, METRIC_INFINITY, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    let start = net.now;
    n9.send(&mut net, 0, &[update(p, 43, 1, 100, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    assert_eq!(
        reported(&net, 0, p, start),
        [(9, ConflictAlertKind::Rejected)]
    );
}

/// Node 0 learns `old` through neighbour 8, whose link then fails, and then `new` from another
/// router-id through neighbour 9, which conflicts with the route over the failed link until that
/// route expires.
fn route_over_a_failed_link_blocks_until_it_expires(old: IpNet, new: IpNet) {
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        20,
        &[update(old, 42, 1, 100, 1600)],
        &[],
    );
    assert_eq!(net.fib(0, old), Some(Fib::Via(8)));

    // The link to neighbour 8 fails, which makes the metric of the route through it infinite,
    // and node 0 holds the prefix. The route stays until it expires, 56 s after its update, and
    // blocks conflicting updates meanwhile.
    n8.rxcost = Some(INF);
    n8.send(&mut net, 0, &[]);
    assert_eq!(net.fib(0, old), Some(Fib::Unreachable));
    assert!(has_route(&net, 0, 8, old));

    let start = net.now;
    n9.send(&mut net, 0, &[update(new, 43, 1, 100, 1600)]);
    assert_eq!(net.fib(0, old), Some(Fib::Unreachable));
    assert!(has_route(&net, 0, 8, old) && !has_route(&net, 0, 9, new));
    assert_eq!(
        reported(&net, 0, old, start),
        [(9, ConflictAlertKind::Rejected)]
    );

    // Once the route through neighbour 8 has expired, the route through neighbour 9 no longer
    // conflicts, and is taken in.
    exchange(&mut net, &mut n8, &mut n9, 40, &[], &[]);
    assert!(!has_route(&net, 0, 8, old));
    n9.send(&mut net, 0, &[update(new, 43, 1, 100, 1600)]);
    assert_eq!(net.fib(0, new), Some(Fib::Via(9)));
}

#[test]
fn routes_over_failed_links_block_another_router_id_until_they_expire() {
    let p = prefix("fd00:9::/64");
    route_over_a_failed_link_blocks_until_it_expires(p, p);
}

#[test]
fn losing_the_route_lets_another_originator_in_within_a_round_trip() {
    let p = prefix("fd00:9::/64");
    // Node 1 learns P from node 0, before node 2 comes along with it.
    let mut net = Net::new(3);
    net.connect(0, 1, Duration::from_millis(10));
    net.originate(0, p);
    net.originate(2, p);
    net.run_for(Duration::from_secs(30));
    net.connect(1, 2, Duration::from_millis(10));
    net.run_for(Duration::from_secs(60));
    assert_eq!(net.delivered_to(1, p.addr()), Some(0));

    // Node 0 shuts down, retracting its routes. Node 1 asks for a new seqno for the lost route,
    // and node 2 answers with its own route, which no longer conflicts.
    net.shutdown(0);
    net.run_for(Duration::from_millis(500));
    assert_eq!(net.delivered_to(1, p.addr()), Some(2));
}

#[test]
fn nonexclusive_origins_are_routed_to_as_before_unless_one_is_exclusive() {
    let p = prefix("fd00:9::/64");
    for exclusive in [false, true] {
        let mut net = Net::new(4);
        for i in 1..4 {
            net.connect(i - 1, i, Duration::from_millis(10));
        }
        net.originate_nonexclusive(0, p);
        if exclusive {
            net.originate(3, p);
        } else {
            net.originate_nonexclusive(3, p);
        }
        net.run_for(Duration::from_secs(60));

        let sides: Vec<_> = (0..4).map(|i| net.delivered_to(i, p.addr())).collect();
        let routes = |i: usize| &net.nodes[i].route_table.prefix_entries[&p].routes;
        if exclusive {
            // The chain splits into two sides, meeting between nodes k and k + 1, which depend
            // on which route each node learnt first.
            let k = sides.iter().rposition(|&o| o == Some(0)).unwrap();
            assert!(sides[..=k].iter().all(|&o| o == Some(0)), "{sides:?}");
            assert!(sides[k + 1..].iter().all(|&o| o == Some(3)), "{sides:?}");

            // There, each node rejects the other's update, in both directions, an originator
            // included.
            assert!(!net.reports.is_empty());
            assert!(
                !has_route(&net, k, k + 1, p) && !has_route(&net, k + 1, k, p),
                "{sides:?}"
            );
        } else {
            // Each node routes to the nearer originator, and nodes 1 and 2 keep a route to
            // each, both nonexclusive, as the nodes that advertise them on keep the flag.
            assert_eq!(sides, [Some(0), Some(0), Some(3), Some(3)]);
            assert!(net.reports.is_empty());
            for (i, j) in [(1, 0), (1, 2), (2, 1), (2, 3)] {
                assert!(routes(i)[net.key(i, j)].nonexclusive, "{i} via {j}");
            }
        }
    }
}

#[test]
fn conflict_alerts_follow_selected_routes() {
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(3);
    net.connect(0, 1, Duration::from_millis(10));
    net.connect(1, 2, Duration::from_millis(10));
    net.add_neighbour(2, 9);
    net.originate(0, p);
    net.run_for(Duration::from_secs(30));

    // An alert from neighbour 9, as it rejected an update, goes along the selected routes, to the
    // originator, each node reporting how far away the rejecting node is by it, and sending it on
    // one hop further.
    let start = net.now;
    net.inject_tlv(9, 2, &conflict_alert(p, 1));
    net.run_for(Duration::from_secs(3));
    assert_eq!(conflict_alerts_sent(&net, 2, 1, start), [(p, 2)]);
    assert_eq!(conflict_alerts_sent(&net, 1, 0, start), [(p, 3)]);
    assert_eq!(reported(&net, 2, p, start), [(9, alerted(1))]);
    assert_eq!(reported(&net, 1, p, start), [(2, alerted(2))]);
    assert_eq!(reported(&net, 0, p, start), [(1, alerted(3))]);

    // Within the Conflict Alert interval, more alerts are reported, but not sent on.
    let start = net.now;
    for _ in 0..3 {
        net.inject_tlv(9, 2, &conflict_alert(p, 1));
    }
    net.run_for(Duration::from_secs(3));
    assert_eq!(conflict_alerts_sent(&net, 2, 1, start), []);
    let reports = (net.reports.iter()).filter(|r| r.node == 2 && r.time >= start);
    assert_eq!(reports.count(), 3);

    // After it, one that has come 254 hops is sent on once more. The next node still reports it,
    // with its rejecting node 255 hops away, but sends it no further.
    net.run_for(Duration::from_secs(8));
    let start = net.now;
    net.inject_tlv(9, 2, &conflict_alert(p, 254));
    net.run_for(Duration::from_secs(3));
    assert_eq!(reported(&net, 2, p, start), [(9, alerted(254))]);
    assert_eq!(conflict_alerts_sent(&net, 2, 1, start), [(p, 255)]);
    assert_eq!(reported(&net, 1, p, start), [(2, alerted(255))]);
    assert_eq!(conflict_alerts_sent(&net, 1, 0, start), []);
    assert_eq!(reported(&net, 0, p, start), []);

    // An alert from the next hop has nowhere to go, nor one for an unknown prefix.
    net.run_for(Duration::from_secs(8));
    let start = net.now;
    net.inject_tlv(1, 2, &conflict_alert(p, 1));
    net.inject_tlv(9, 2, &conflict_alert(prefix("fd00:8::/64"), 1));
    net.run_for(Duration::from_secs(3));
    assert_eq!(conflict_alerts_sent(&net, 2, 1, start), []);
    assert_eq!(reported(&net, 2, p, start), []);

    // Nor is one taken in from a neighbour still starting up.
    net.add_neighbour_unacknowledged(2, 8);
    net.inject_tlv(8, 2, &conflict_alert(p, 1));
    net.run_for(Duration::from_secs(3));
    assert_eq!(conflict_alerts_sent(&net, 2, 1, start), []);
}

#[test]
fn originator_restarting_with_a_new_router_id_is_reacquired() {
    let p = prefix("fd00:9::/64");
    let mut net = Net::new(4);
    for (a, b, ms) in [(0, 1, 10), (0, 2, 30), (1, 3, 10), (2, 3, 10)] {
        net.connect(a, b, Duration::from_millis(ms));
    }
    net.originate(0, p);
    net.run_for(Duration::from_secs(60));

    // Node 0 crashes, and comes back with a new router-id, as the daemon picks on every start.
    let node = State::new(net.now, params(), RouterId::new(100).unwrap(), None);
    net.restart(0, node);
    let restart = net.now;
    net.add_neighbour(0, 1);
    net.add_neighbour(0, 2);
    assert!(net.nodes[0].inject_route(p, false));

    net.run_for(Duration::from_secs(5));
    for i in 1..4 {
        assert_eq!(net.delivered_to(i, p.addr()), Some(0), "from {i}");
        let routes = &net.nodes[i].route_table.prefix_entries[&p].routes;
        assert!(routes.values().all(|route| route.router_id.get() == 100));
    }
    net.run_for(Duration::from_secs(60));
    let reports: Vec<_> = (net.reports.iter()).filter(|r| r.time >= restart).collect();
    assert!(reports.is_empty(), "{reports:?}");
}

#[test]
fn addresses_inside_an_exclusive_prefix_are_kept_from_other_origins() {
    // Node 0 originates P, and node 3 Q, inside it.
    let p = prefix("fd00:9::/48");
    let q = prefix("fd00:9:0:5::/64");
    let in_q: IpAddr = "fd00:9:0:5::1".parse().unwrap();
    let elsewhere_in_p: IpAddr = "fd00:9:0:6::1".parse().unwrap();

    for (p_nonexclusive, q_nonexclusive) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let case = format!("P nonexclusive: {p_nonexclusive}, Q nonexclusive: {q_nonexclusive}");
        let mut net = Net::new(4);
        net.originate_as(0, p, p_nonexclusive);
        net.originate_as(3, q, q_nonexclusive);
        for i in 1..4 {
            net.connect(i - 1, i, Duration::from_millis(10));
        }
        net.run_for(Duration::from_secs(60));

        if p_nonexclusive {
            // Q may come from another origin than P, and takes its addresses by the longest
            // match, whether it is exclusive or not.
            for i in 0..4 {
                assert_eq!(net.delivered_to(i, in_q), Some(3), "{case}, node {i}");
                assert_eq!(
                    net.delivered_to(i, elsewhere_in_p),
                    Some(0),
                    "{case}, node {i}"
                );
            }
            assert!(net.reports.is_empty(), "{case}");
            continue;
        }

        // P is exclusive, so Q conflicts with it. Each node keeps the prefix it learnt first,
        // and rejects the other: one on node 0's side reaches all of P's addresses there, Q's
        // included, and one on node 3's side only Q's, at node 3. No node routes Q's addresses
        // to node 3 and the rest of P's to node 0.
        let sides: Vec<_> = (0..4)
            .map(|i| net.delivered_to(i, elsewhere_in_p))
            .collect();
        for (i, &side) in sides.iter().enumerate() {
            if side == Some(0) {
                assert_eq!(net.delivered_to(i, in_q), Some(0), "{case}, node {i}");
            } else {
                assert_eq!(side, None, "{case}, node {i}");
                assert_eq!(net.delivered_to(i, in_q), Some(3), "{case}, node {i}");
            }
        }
        assert_eq!(sides[0], Some(0), "{case}");
        assert_eq!(sides[3], None, "{case}");

        // Each origin is told of the conflict over its own prefix, and only over that.
        for (node, own) in [(0, p), (3, q)] {
            let reports = net.reports.iter().filter(|r| r.node == node);
            let prefixes: HashSet<_> = reports.map(|r| r.prefix).collect();
            assert_eq!(prefixes, HashSet::from([own]), "{case}, node {node}");
        }
    }
}

#[test]
fn an_origin_may_have_prefixes_inside_its_own_exclusive_ones() {
    let p = prefix("fd00:9::/48");
    let q = prefix("fd00:9:0:5::/64");
    let mut net = Net::new(3);
    net.originate(0, p);
    net.originate(0, q);
    net.connect(0, 1, Duration::from_millis(10));
    net.connect(1, 2, Duration::from_millis(10));
    net.run_for(Duration::from_secs(60));

    for i in 1..3 {
        assert_eq!(net.fib(i, p), Some(Fib::Via(i - 1)), "node {i}");
        assert_eq!(net.fib(i, q), Some(Fib::Via(i - 1)), "node {i}");
    }
    assert!(net.reports.is_empty());
}

#[test]
fn injected_prefixes_keep_out_what_conflicts_with_them() {
    let p = prefix("fd00:9::/48");
    let q = prefix("fd00:9:0:5::/64");
    let entry = |net: &Net, prefix| {
        net.nodes[0]
            .route_table
            .prefix_entries
            .contains_key(&prefix)
    };

    // Node 0 originates P, exclusive. A route from another origin to Q, inside it, is rejected,
    // and the conflict reported over P. No alert goes out, as node 0 is P's origin.
    let mut net = Net::new(1);
    net.originate(0, p);
    net.add_neighbour(0, 9);
    let mut n9 = Scripted::new(9);
    let start = net.now;
    n9.send(&mut net, 0, &[update(q, 42, 1, 100, 0x8000)]);
    net.run_for(Duration::from_secs(3));
    assert!(!entry(&net, q));
    assert_eq!(
        reported(&net, 0, p, start),
        [(9, ConflictAlertKind::Rejected)]
    );
    assert_eq!(conflict_alerts_sent(&net, 0, 9, start), []);

    // Node 0 originates Q instead. An exclusive P from another origin would take its addresses,
    // and is rejected too, while a nonexclusive one is taken in.
    let mut net = Net::new(1);
    net.originate(0, q);
    net.add_neighbour(0, 9);
    let mut n9 = Scripted::new(9);
    let start = net.now;
    n9.send(&mut net, 0, &[update(p, 42, 1, 100, 0x8000)]);
    assert!(!entry(&net, p));
    assert_eq!(
        reported(&net, 0, q, start),
        [(9, ConflictAlertKind::Rejected)]
    );
    n9.send(&mut net, 0, &[nonexclusive_update(p, 42, 1, 100, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[test]
fn routes_over_failed_links_block_a_prefix_containing_them_until_they_expire() {
    // A route blocks an exclusive prefix containing it, as it does the same prefix.
    route_over_a_failed_link_blocks_until_it_expires(
        prefix("fd00:9:0:5::/64"),
        prefix("fd00:9::/48"),
    );
}
