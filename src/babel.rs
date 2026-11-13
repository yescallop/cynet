mod base;
pub mod driver;
mod packet;
mod params;
pub mod snapshot;
mod timer;

#[cfg(test)]
mod tests;

use std::{
    assert_matches,
    cell::Cell,
    collections::{HashMap, HashSet, VecDeque, hash_map},
    hash::Hash,
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU8,
    time::{Duration, Instant},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::joint::JointPrefixSet;
use slotmap::{SecondaryMap, SlotMap, SparseSecondaryMap, sparse_secondary};

use crate::babel::{
    base::{Ae, HelloEffect, HelloHistory, timestamp},
    packet::{
        PacketDecoder, PacketEncoder, PacketItem, Update,
        tlv::{Tlv, UpdateFlags},
    },
    params::{DurationKey, F64Key, IntervalKey, U8Key},
    snapshot::{NeighbourSnapshot, PrefixSnapshot, RouteSnapshot, Snapshot},
    timer::{TimerKey, TimerQueue},
};

pub use crate::babel::{
    base::{COST_INFINITY, Interval, METRIC_INFINITY, RouterId, Seqno, martian_prefix},
    packet::Packet,
    params::Params,
};

/// What the IPv6 and UDP headers of a Babel packet take up of a link's MTU (RFC 8966 §4).
pub const LINK_HEADERS_LEN: usize = 48;

/// How far the seqno of a seqno request may exceed its source's seqno for the source to
/// answer it, as in babeld. A larger difference most likely means that the source lost
/// its seqno by rebooting. Requests for unfeasible routes are then not sent, no request
/// is answered, and the stale source table entries are left to expire.
const MAX_SEQNO_GAP: i16 = 100;

slotmap::new_key_type! {
    /// Identifies a neighbour internally.
    pub struct NeighKey;
}

/// A one-to-one mapping between internal neighbour keys and external ones that
/// identify the same neighbours elsewhere, such as WireGuard public keys.
pub struct NeighKeyMap<K> {
    inward: HashMap<K, NeighKey>,
    outward: SecondaryMap<NeighKey, K>,
}

impl<K: Clone + Eq + Hash> NeighKeyMap<K> {
    /// Creates an empty `NeighKeyMap`.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inward: HashMap::new(),
            outward: SecondaryMap::new(),
        }
    }

    /// Maps `external` and `internal` to each other. Neither may be already mapped.
    pub fn insert(&mut self, external: K, internal: NeighKey) {
        assert!(
            !self.inward.contains_key(&external) && !self.outward.contains_key(internal),
            "keys should not be already mapped"
        );
        self.inward.insert(external.clone(), internal);
        self.outward.insert(internal, external);
    }

    /// Removes a mapping by the external key.
    pub fn remove_by_external(&mut self, external: &K) {
        let Some(internal) = self.inward.remove(external) else {
            panic!("mapping should exist");
        };
        self.outward.remove(internal);
    }

    /// Returns the corresponding internal key, if any.
    pub fn internal(&self, external: &K) -> Option<NeighKey> {
        self.inward.get(external).copied()
    }

    /// Returns the corresponding external key, if any.
    pub fn external(&self, internal: NeighKey) -> Option<&K> {
        self.outward.get(internal)
    }
}

struct NeighEntry {
    hello_history: HelloHistory,
    txcost: u16,
    /// The link cost, as last computed by `update_cost`.
    cost: u16,
    last_hello_interval: Option<Interval>,
    incoming_hello_timer_key: Option<TimerKey>,
    incoming_ihu_timer_key: Option<TimerKey>,
    outgoing_hello_timer_key: Option<TimerKey>,
    outgoing_update_timer_key: Option<TimerKey>,
    hello_seqno: Seqno,
    hellos_until_ihu: u8,
    packet_buf: PacketBuf,
    origin_receive_timestamps: Option<(u32, u32)>,
    rtt: Option<f64>,
    /// What is awaited from the neighbour before anything else it sends is taken in, if anything
    /// (see [Reboots](State#reboots)).
    startup: Option<Startup>,
}

/// A startup packet to a neighbour that hasn't been acknowledged yet.
struct Startup {
    /// The Opaque value of its acknowledgement.
    opaque: u16,
    /// How long was last waited, or is being waited, before sending it again.
    timeout: Duration,
    /// The timer that sends it again.
    timer_key: TimerKey,
}

impl NeighEntry {
    fn new(params: &Params, hello_seqno: Seqno) -> Self {
        Self {
            hello_history: HelloHistory::new(),
            txcost: COST_INFINITY,
            cost: COST_INFINITY,
            last_hello_interval: None,
            incoming_hello_timer_key: None,
            incoming_ihu_timer_key: None,
            outgoing_hello_timer_key: None,
            outgoing_update_timer_key: None,
            hello_seqno,
            hellos_until_ihu: params.get(U8Key::HellosPerIhu),
            packet_buf: PacketBuf {
                encoder: PacketEncoder::new(params.get_mtu() as usize - LINK_HEADERS_LEN),
                flush_timer_key: None,
            },
            origin_receive_timestamps: None,
            rtt: None,
            startup: None,
        }
    }

    /// Flushes the neighbour entry, except for the Hello history, which records
    /// the Hello, if any, that caused the flush, and the packet buffer, the TLVs
    /// in which, if any, are still to be sent.
    fn flush(&mut self, timers: &mut TimerQueue<Timer>) {
        if let Some(key) = self.incoming_hello_timer_key.take() {
            timers.remove(key);
        }
        if let Some(key) = self.incoming_ihu_timer_key.take() {
            timers.remove(key);
        }
        self.txcost = COST_INFINITY;
        self.last_hello_interval = None;
        self.origin_receive_timestamps = None;
        self.rtt = None;
    }

    /// Returns a timestamped Hello with the next seqno, which has an interval if it is scheduled.
    fn hello(&self, interval: Option<Interval>) -> Tlv {
        Tlv::Hello {
            seqno: self.hello_seqno,
            interval,
            transmit_timestamp: Some(0),
        }
    }

    /// Returns a Hello with a seqno far from the next one, and no timestamp.
    fn far_hello(&self, interval: Option<Interval>) -> Tlv {
        Tlv::Hello {
            seqno: self.hello_seqno + FAR_HELLO_SEQNO_OFFSET,
            interval,
            transmit_timestamp: None,
        }
    }

    /// Returns an IHU, echoing the timestamps of the last Hello heard, if any.
    fn ihu(&self, interval: Interval) -> Tlv {
        Tlv::Ihu {
            ae: Ae::Wildcard,
            rxcost: self.rxcost(),
            interval,
            address: [0; 8],
            origin_receive_timestamps: self.origin_receive_timestamps,
        }
    }

    /// Computes the rxcost by 2-out-of-3 link sensing with a nominal cost of 96
    /// (RFC 8966 Appendix A.2.1).
    fn rxcost(&self) -> u16 {
        const NOMINAL_COST: u16 = 96;

        let last_3 = self.hello_history.bits() & 0b111;
        if last_3.count_ones() >= 2 {
            NOMINAL_COST
        } else {
            COST_INFINITY
        }
    }

    /// Maps the smoothed RTT to a penalty: zero penalty up to rtt-min, rising linearly
    /// to max-rtt-penalty at rtt-max, and constant above (RFC 9616 §4.2).
    fn rtt_penalty(&self) -> u16 {
        const RTT_MIN: f64 = 10_000.0;
        const RTT_MAX: f64 = 120_000.0;
        const MAX_RTT_PENALTY: f64 = 150.0;

        let Some(rtt) = self.rtt else {
            return 0;
        };
        let penalty =
            (rtt.clamp(RTT_MIN, RTT_MAX) - RTT_MIN) / (RTT_MAX - RTT_MIN) * MAX_RTT_PENALTY;
        penalty.round_ties_even() as u16
    }

    /// Updates the link cost to infinity if the rxcost is infinite, or otherwise to
    /// the txcost plus the RTT penalty (RFC 9616 §4.2), returning whether the cost
    /// has changed.
    fn update_cost(&mut self) -> bool {
        let old_cost = self.cost;
        self.cost = if self.rxcost() == COST_INFINITY {
            COST_INFINITY
        } else {
            // The cost MUST be strictly positive (RFC 8966 §3.4.3).
            self.txcost.saturating_add(self.rtt_penalty()).max(1)
        };
        self.cost != old_cost
    }
}

/// Identifies a source of routing information (destination of data traffic).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SourceKey {
    prefix: IpNet,
    router_id: RouterId,
}

struct SourceEntry {
    seqno: Seqno,
    metric: u16,
    gc_timer_key: TimerKey,
}

struct RouteEntry {
    router_id: RouterId,
    advertised_metric: u16,
    // These are kept in cells and can be modified through a shared borrow, so that
    // `select_route` can update them up front and keep the borrow for later comparison.
    metric: Cell<u16>,
    /// The smoothed metric at `metric_smoothed_at`, since when `metric` has not changed.
    metric_smoothed: Cell<f32>,
    /// A timestamp, as returned by [`timestamp`].
    metric_smoothed_at: Cell<u32>,
    seqno: Seqno,
    /// The Interval of the last update applied, from which the route's expiry is timed.
    last_update_interval: Interval,
    /// The route's timer key: first for near-expiry, then for expiry.
    timer_key: TimerKey,
    /// Whether the last update applied was nonexclusive (see
    /// [Duplicate addresses](State#duplicate-addresses)).
    nonexclusive: bool,
}

impl RouteEntry {
    /// Returns the smoothed metric at `now`, smoothing the metric exponentially with
    /// the time constant `tau` (RFC 8966 Appendix A.3).
    fn ms_at(&self, now: u32, tau: u32) -> f32 {
        let ms = self.metric_smoothed.get();
        let dt = now.wrapping_sub(self.metric_smoothed_at.get());
        if dt == 0 {
            return ms;
        }
        // Since the metric m has been constant since t0:
        // ms(t) = m + (ms(t0) - m) exp(-(t - t0) / τ)
        let m = self.metric.get() as f32;
        m + (ms - m) * (-(dt as f32) / (tau as f32)).exp()
    }

    /// Sets the metric at `now`, after smoothing the previous one up to then.
    /// This must be done whenever the route is updated.
    fn set_metric(&self, metric: u16, now: u32, tau: u32) {
        // Timestamps wrap around every 2^32 µs, about 72 minutes. A route is updated
        // within its expiry time, at most 3.5 × 655.35 s, about 38 minutes, or removed,
        // so re-anchoring once older than 2^30 µs keeps the anchor within range.
        const MAX_ANCHOR_AGE: u32 = 1 << 30;

        if metric == self.metric.get()
            && now.wrapping_sub(self.metric_smoothed_at.get()) < MAX_ANCHOR_AGE
        {
            // The smoothed metric continues to follow the same curve.
            return;
        }
        self.metric_smoothed.set(self.ms_at(now, tau));
        self.metric_smoothed_at.set(now);
        self.metric.set(metric);
    }

    /// Checks whether the route is feasible (see [`update_feasible`]).
    fn is_feasible(&self, prefix: IpNet, source_table: &HashMap<SourceKey, SourceEntry>) -> bool {
        let key = SourceKey {
            prefix,
            router_id: self.router_id,
        };
        update_feasible(source_table, key, self.seqno, self.advertised_metric)
    }

    /// Checks whether the route may be selected, that is, whether it is feasible and its
    /// metric is finite (RFC 8966 §3.6).
    fn is_usable(&self, prefix: IpNet, source_table: &HashMap<SourceKey, SourceEntry>) -> bool {
        self.metric.get() != METRIC_INFINITY && self.is_feasible(prefix, source_table)
    }
}

/// Checks whether an update for a source with the given seqno and finite metric is
/// feasible (RFC 8966 §3.5.1). The feasibility distances change as updates are sent, so
/// this is checked whenever it matters.
fn update_feasible(
    source_table: &HashMap<SourceKey, SourceEntry>,
    key: SourceKey,
    seqno: Seqno,
    metric: u16,
) -> bool {
    source_table.get(&key).is_none_or(|source| {
        source.seqno.lt(seqno) || (seqno == source.seqno && metric < source.metric)
    })
}

/// Returns the prefix that a TLV carries in its AE, Plen and Prefix fields, or `None` for
/// AE 0 (wildcard). AEs 1 and 4 (v4-via-v6) carry an IPv4 prefix alike (RFC 9229 §4.1),
/// and a request with either MUST be treated in the same manner (§2.3).
fn decode_prefix(ae: Ae, plen: u8, prefix: [u8; 16]) -> Option<IpNet> {
    Some(match ae {
        Ae::Wildcard => return None,
        Ae::Ipv4 | Ae::V4ViaV6 => {
            let addr = Ipv4Addr::from_octets(*prefix.first_chunk().unwrap());
            Ipv4Net::new_assert(addr, plen).into()
        }
        Ae::Ipv6 => Ipv6Net::new_assert(Ipv6Addr::from_octets(prefix), plen).into(),
        Ae::LinkLocalIpv6 => panic!("AE 3 should not carry a prefix"),
    })
}

/// Returns the AE, Plen and Prefix fields that carry a prefix in a TLV, with `ipv4_ae`
/// for an IPv4 prefix: AE 4 (v4-via-v6) in an Update, as packets are sent over IPv6 (RFC
/// 9229 §2.1), and AE 1 in a request (§2.3).
fn encode_prefix(prefix: IpNet, ipv4_ae: Ae) -> (Ae, u8, [u8; 16]) {
    let mut octets = [0; 16];
    let ae = match prefix.addr() {
        IpAddr::V4(addr) => {
            octets[..4].copy_from_slice(&addr.octets());
            ipv4_ae
        }
        IpAddr::V6(addr) => {
            octets = addr.octets();
            Ae::Ipv6
        }
    };
    (ae, prefix.prefix_len(), octets)
}

/// The status of a prefix.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PrefixStatus {
    /// A route for the prefix is injected into the Babel domain by the local node, as nonexclusive
    /// or not (see [Duplicate addresses](State#duplicate-addresses)).
    Injected { nonexclusive: bool },
    /// The route through this neighbour is selected for the prefix.
    /// Its metric is finite, and it is feasible.
    ///
    /// With a timer, the neighbour may still hold a stale route through this node, with
    /// another router-id, and every full dump to it retracts the prefix until the timer
    /// expires (see [`State::select_route`]).
    Selected(NeighKey, Option<TimerKey>),
    /// The prefix is held, with an unreachable route installed (RFC 8966 §3.5.4), after
    /// the selected route was lost with no other to select. It is retracted at once and
    /// in every periodic update, until a route is selected or this timer expires. When
    /// it expires, if ever, a neighbour running this code will have expired any route for
    /// the prefix through this node, and any other still routing it through this node
    /// must have missed every retraction while it was held.
    Held(TimerKey),
    /// No route to the prefix is selected. The entry is kept only for fallback routes,
    /// and removed once there is no fallback route left.
    #[default]
    None,
}

impl PrefixStatus {
    /// Returns the selected next-hop neighbour, if any.
    fn selected(self) -> Option<NeighKey> {
        match self {
            Self::Selected(key, _) => Some(key),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Advert {
    router_id: RouterId,
    seqno: Seqno,
    metric: u16,
    /// Whether the route is nonexclusive, which a retraction leaves out.
    nonexclusive: bool,
}

#[derive(Default)]
struct PrefixEntry {
    routes: SparseSecondaryMap<NeighKey, RouteEntry>,
    status: PrefixStatus,
    /// Advertisement for a selected or held route: the selected route's router-id, seqno,
    /// and metric, kept with an infinite metric while held. `None` for an injected route
    /// or when no route to the prefix is selected. An injected route is advertised with
    /// this node's router-id and seqno instead (see [`State::advert_for_prefix`]).
    advert: Option<Advert>,
}

impl PrefixEntry {
    /// Checks whether no route to the prefix is selected and no fallback route exists,
    /// so that the entry can be safely removed.
    fn is_empty(&self) -> bool {
        self.status == PrefixStatus::None && self.routes.is_empty()
    }

    /// Returns the sources in the entry for `prefix` (see
    /// [Duplicate addresses](State#duplicate-addresses)): that of each route, with its neighbour,
    /// and if this node injects the prefix, its own, with `own_router_id` and no neighbour.
    fn sources(
        &self,
        prefix: IpNet,
        own_router_id: RouterId,
    ) -> impl Iterator<Item = (Option<NeighKey>, Source)> {
        let injected = match self.status {
            PrefixStatus::Injected { nonexclusive } => {
                let source = Source {
                    prefix,
                    router_id: own_router_id,
                    nonexclusive,
                };
                Some((None, source))
            }
            _ => None,
        };
        let routes = self.routes.iter().map(move |(key, route)| {
            let source = Source {
                prefix,
                router_id: route.router_id,
                nonexclusive: route.nonexclusive,
            };
            (Some(key), source)
        });
        injected.into_iter().chain(routes)
    }
}

/// The source of a route or of an injected prefix, as far as duplicate addresses go (see
/// [Duplicate addresses](State#duplicate-addresses)).
#[derive(Clone, Copy, Debug)]
struct Source {
    prefix: IpNet,
    router_id: RouterId,
    nonexclusive: bool,
}

impl Source {
    /// Checks whether two sources conflict: their router-ids differ, and the prefix of one
    /// contains the other's, or is the same, and is exclusive.
    fn conflicts_with(&self, other: &Source) -> bool {
        let covers = |a: &Source, b: &Source| !a.nonexclusive && a.prefix.contains(&b.prefix);
        self.router_id != other.router_id && (covers(self, other) || covers(other, self))
    }
}

#[derive(Default)]
struct RouteTable {
    prefix_entries: HashMap<IpNet, PrefixEntry>,
    /// The prefixes of `prefix_entries`, in a trie, for finding those that contain a prefix or that
    /// a prefix contains (see [`Self::conflicting`]). Looking up and walking a trie cost far more
    /// than they do in a hash map, so it serves that alone, and is kept up to date as entries come
    /// and go.
    prefixes: JointPrefixSet<IpNet>,
    neigh_prefixes: SecondaryMap<NeighKey, HashSet<IpNet>>,
}

impl RouteTable {
    fn inject(&mut self, prefix: IpNet, nonexclusive: bool) -> bool {
        match self.prefix_entries.entry(prefix) {
            hash_map::Entry::Occupied(_) => false,
            hash_map::Entry::Vacant(e) => {
                e.insert(PrefixEntry {
                    status: PrefixStatus::Injected { nonexclusive },
                    ..Default::default()
                });
                self.prefixes.insert(prefix);
                true
            }
        }
    }

    /// Removes the entry for a prefix.
    fn remove_entry(&mut self, prefix: &IpNet) {
        assert!(self.prefix_entries.remove(prefix).is_some());
        self.prefixes.remove(prefix);
    }

    /// Returns the prefixes whose sources conflict with an update for `update.prefix` from
    /// neighbour `from`: routes and prefixes injected with `own_router_id`, for prefixes that
    /// contain the update's prefix or that it contains, but for the route through `from` for its
    /// prefix, which it replaces (see [Duplicate addresses](State#duplicate-addresses)).
    fn conflicting(
        &self,
        from: NeighKey,
        update: Source,
        own_router_id: RouterId,
    ) -> Vec<IpNet> {
        let mut found = Vec::new();
        let mut look_at = |prefix: IpNet| {
            let entry = &self.prefix_entries[&prefix];
            let conflicts = entry.sources(prefix, own_router_id).any(|(via, source)| {
                let replaced = prefix == update.prefix && via == Some(from);
                !replaced && source.conflicts_with(&update)
            });
            if conflicts {
                found.push(prefix);
            }
        };

        // The prefixes that contain the update's, its own included, which conflict with it if
        // they are exclusive, or it is and they are the same.
        for prefix in self.prefixes.cover(&update.prefix) {
            look_at(prefix);
        }
        // And those that it contains, which conflict with it if it is exclusive.
        if !update.nonexclusive {
            for prefix in self.prefixes.children(&update.prefix) {
                if prefix != update.prefix {
                    look_at(prefix);
                }
            }
        }
        found.sort_unstable();
        found
    }

    /// Returns the status of the prefix, and the route entry for the prefix
    /// through the neighbour, or `None` if it is not present, in which case
    /// a new route returned by `f` is inserted.
    fn get_or_insert_with(
        &mut self,
        prefix: IpNet,
        key: NeighKey,
        f: impl FnOnce() -> RouteEntry,
    ) -> (PrefixStatus, Option<&mut RouteEntry>) {
        let entry = match self.prefix_entries.entry(prefix) {
            hash_map::Entry::Occupied(e) => e.into_mut(),
            hash_map::Entry::Vacant(e) => {
                self.prefixes.insert(prefix);
                e.insert(PrefixEntry::default())
            }
        };
        let route =
            get_or_insert_route(&mut self.neigh_prefixes, &mut entry.routes, prefix, key, f);
        (entry.status, route)
    }

    /// Does what [`Self::get_or_insert_with`] does if the prefix already has a route from
    /// `router_id`, as nonexclusive or not, through any neighbour, and otherwise returns `None`,
    /// changing nothing. An update from such a source conflicts with nothing, as no two sources in
    /// the table conflict, so this takes it in with no check (see
    /// [Duplicate addresses](State#duplicate-addresses)). That covers the refreshes that make up
    /// nearly all updates, and looks their prefix up once.
    fn get_or_insert_with_known_source(
        &mut self,
        prefix: IpNet,
        key: NeighKey,
        router_id: RouterId,
        nonexclusive: bool,
        f: impl FnOnce() -> RouteEntry,
    ) -> Option<(PrefixStatus, Option<&mut RouteEntry>)> {
        let entry = self.prefix_entries.get_mut(&prefix)?;
        let known = (entry.routes.values())
            .any(|route| route.router_id == router_id && route.nonexclusive == nonexclusive);
        if !known {
            return None;
        }
        let route =
            get_or_insert_route(&mut self.neigh_prefixes, &mut entry.routes, prefix, key, f);
        Some((entry.status, route))
    }

    fn remove(&mut self, prefix: &IpNet, key: NeighKey) -> Option<RouteEntry> {
        let route = self.prefix_entries.get_mut(prefix)?.routes.remove(key)?;
        assert!(self.neigh_prefixes[key].remove(prefix));
        Some(route)
    }
}

/// Returns the route through neighbour `key` among the `routes` to a prefix, or `None` if it is
/// not present, in which case a new route returned by `f` is inserted, and recorded in
/// `neigh_prefixes`.
fn get_or_insert_route<'a>(
    neigh_prefixes: &mut SecondaryMap<NeighKey, HashSet<IpNet>>,
    routes: &'a mut SparseSecondaryMap<NeighKey, RouteEntry>,
    prefix: IpNet,
    key: NeighKey,
    f: impl FnOnce() -> RouteEntry,
) -> Option<&'a mut RouteEntry> {
    match routes.entry(key).unwrap() {
        sparse_secondary::Entry::Occupied(e) => Some(e.into_mut()),
        sparse_secondary::Entry::Vacant(e) => {
            assert!(neigh_prefixes[key].insert(prefix));
            e.insert(f());
            None
        }
    }
}

/// A seqno request that this node has recently forwarded, or originated for a route that
/// it lost. Requests that it originates for unfeasible routes are not recorded.
///
/// One entry per prefix is enough: a request is forwarded only when there is a selected
/// route, and originated only when it is lost, both for its router-id.
struct SeqnoRequestEntry {
    router_id: RouterId,
    seqno: Seqno,
    /// How many more times the request will be resent while no route to its prefix is
    /// selected. This also determines its timeout
    /// (see [`Params::seqno_request_timeout`]).
    resends_left: u8,
    /// When the request was last sent, as a timestamp.
    sent_at: u32,
    timer_key: TimerKey,
}

struct PacketBuf {
    encoder: PacketEncoder,
    // `None` iff `encoder.is_empty()`.
    flush_timer_key: Option<TimerKey>,
}

impl PacketBuf {
    fn flush(&mut self, key: NeighKey, outputs: &mut VecDeque<Output>) {
        assert!(
            !self.encoder.is_empty(),
            "empty buffer should not be flushed"
        );

        outputs.push_back(Output::Packet(key, self.encoder.finalize()));
        self.encoder.clear();
    }

    fn put(
        &mut self,
        key: NeighKey,
        outputs: &mut VecDeque<Output>,
        timers: &mut TimerQueue<Timer>,
        params: &Params,
        f: impl Fn(&mut PacketEncoder) -> bool,
    ) {
        let was_empty = self.encoder.is_empty();

        // Usually, a TLV SHOULD be sent within half the Multicast Hello interval (RFC
        // 8966 §3.1). Take half of that and multiply it by 0.75 ~ 1.25, as outgoing TLVs
        // SHOULD be sent with a random delay (§3.1).
        //
        // A Hello then waits at most 0.3125 Hello intervals, and is put at most 1.03125
        // intervals after the one before, so consecutive Hellos are at most 1.34375
        // intervals apart, within the 1.5 intervals after which a neighbour counts a
        // Hello as missed. After a lost Hello, the next is at most 2.375 intervals after
        // the last one received, within the 2.5 intervals after which the neighbour
        // counts a second Hello as missed, which makes its link cost infinite. With the
        // default Hello interval of 4 s, the delay may then grow by up to 0.5 s between
        // the two Hellos. That is the worst case, where the first was sent early, in a
        // buffer led by another TLV.
        let timeout = || {
            params
                .get(DurationKey::HelloInterval)
                .mul_f64(rand::random_range(0.1875..0.3125))
        };

        if !f(&mut self.encoder) {
            // Encoding failed. The buffer is full. Flush it now.
            self.flush(key, outputs);

            timers.reset(self.flush_timer_key.as_mut().unwrap(), timeout());

            assert!(
                f(&mut self.encoder),
                "encoding into empty buffer should succeed"
            );
        } else if was_empty {
            // Encoding succeeded. The buffer was empty. Set a timer to flush it.
            assert!(self.flush_timer_key.is_none());

            self.flush_timer_key = Some(timers.insert(Timer::BufferFlush(key), timeout()));
        }
    }

    fn schedule_flush(&mut self, timers: &mut TimerQueue<Timer>, timeout: Duration) {
        if self.encoder.is_empty() {
            return;
        }

        let key = self.flush_timer_key.as_mut().unwrap();

        // Take half of the timeout and add some jitter as in `put`.
        let timeout = timeout.mul_f64(rand::random_range(0.375..0.625));
        let new_deadline = timers.now() + timeout;
        let deadline = timers.deadline(*key);

        if new_deadline < deadline {
            timers.reset_at(key, new_deadline);
        }
    }
}

enum Timer {
    Startup(NeighKey),
    OutgoingHello(NeighKey),
    OutgoingUpdate(NeighKey),
    IncomingHello(NeighKey),
    IncomingIhu(NeighKey),
    SourceGc(SourceKey),
    RouteNearExpiry(IpNet, NeighKey),
    RouteExpiry(IpNet, NeighKey),
    RouteHold(IpNet),
    StaleRouteRetraction(IpNet),
    SeqnoRequest(IpNet),
    ConflictAlert((IpNet, NeighKey)),
    BufferFlush(NeighKey),
}

/// An output of a Babel router, with neighbours identified by `K`.
pub enum Output<K = NeighKey> {
    /// Sends a Babel packet to a neighbour. Its transmit timestamp is left to be filled in just
    /// before it is sent (see [`Packet::timestamp`]).
    Packet(K, Packet),
    /// Selects a neighbour as the next-hop router to a prefix.
    RouteSelect(IpNet, K),
    /// Holds a prefix by installing an unreachable route.
    RouteHold(IpNet),
    /// Removes the route to a prefix.
    RouteRemove(IpNet),
    /// Reports a sign of a conflict over a prefix, which came from a neighbour, for tracing the
    /// conflict by hand (see [Duplicate addresses](State#duplicate-addresses)).
    ConflictAlert {
        /// The prefix in conflict.
        prefix: IpNet,
        /// The neighbour that the rejected update or the Conflict Alert came from.
        from: K,
        /// What this node saw.
        kind: ConflictAlertKind,
    },
}

/// What a node saw of a conflict over a prefix (see
/// [Duplicate addresses](State#duplicate-addresses)).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConflictAlertKind {
    /// This node rejected an update from the neighbour, whose route leads to another origin: the
    /// routes from the two origins meet here.
    Rejected,
    /// A Conflict Alert came from the neighbour, which routes the prefix through this node: the
    /// routes meet `hops` hops away, through the neighbour.
    Alerted {
        /// How many hops away the node that rejected an update is, as the alert says.
        hops: NonZeroU8,
    },
}

impl Output {
    /// Identifies the neighbour, if any, by something other than its internal key.
    pub fn with_key<K>(self, f: impl FnOnce(NeighKey) -> K) -> Output<K> {
        match self {
            Self::Packet(key, packet) => Output::Packet(f(key), packet),
            Self::RouteSelect(prefix, key) => Output::RouteSelect(prefix, f(key)),
            Self::RouteHold(prefix) => Output::RouteHold(prefix),
            Self::RouteRemove(prefix) => Output::RouteRemove(prefix),
            Self::ConflictAlert { prefix, from, kind } => Output::ConflictAlert {
                prefix,
                from: f(from),
                kind,
            },
        }
    }
}

/// How far a Hello seqno is put from the current one to be sure of being far from what a neighbour
/// expects: half of the seqno space. A Hello right after it is then as far away again.
const FAR_HELLO_SEQNO_OFFSET: u16 = 0x8000;

/// The state of a Babel router.
///
/// # Time
///
/// `State` reads no clock. It is given the current time, `now`, as it is created, and by
/// every method that may send a packet or set a timer, and [`State::poll_timeout`]
/// returns when to call [`State::handle_timeout`] next. [`State::handle_packet`] also
/// takes the time the packet arrived, as its receive timestamp (RFC 9616 §3.1), while a
/// packet to send has its transmit timestamp left to be filled in just before it is sent
/// (see [`Packet::timestamp`]). A `now` earlier than one given before is ignored, so that
/// time never goes backward.
///
/// # Reboots
///
/// A node that reboots loses its feasibility distances, so it may select a previously
/// unfeasible route and create a loop. For example, take this network, where node 0
/// originates P, and the link between nodes 1 and 3 is slow, so that node 3 routes P
/// through node 2, and node 2 through node 1:
///
/// ```text
/// 0 --- 1 --- 2
///        \   /
///         \ /
///          3
/// ```
///
/// Should node 1 reboot, and come back while node 0 is unreachable, for example because
/// the link between them is not up again yet, node 3 still advertises P to node 1, as its
/// route is not through node 1. Node 1 has no feasibility distance for P left, so it
/// selects that route, and packets for P go round nodes 1, 3 and 2.
///
/// So the routes through a node from before it reboots need to be removed before it learns
/// anything new. It says goodbye to every neighbour as it shuts down (see [`State::shutdown`]),
/// which removes the routes before it reboots, and after rebooting, which also covers a crash, it
/// sends each one a startup packet, and takes in nothing from it until that is acknowledged:
///
/// - A wildcard retraction removes the routes through the node.
/// - Two Hellos flush the neighbour's entry for it (RFC 8966 Appendix A.1), whatever Hello seqno
///   the neighbour expects: the first moves the seqno it expects far away from the second. This
///   goes against the SHOULD NOT of RFC 8966 §4.6.5, for a reset that can't depend on chance.
/// - An acknowledgement request, with a short deadline, shows when it has all been handled. The
///   packet is sent again until then, which also keeps asking for a session in a daemon that sends
///   nothing over a WireGuard session it doesn't have.
///
/// The acknowledgement is also a barrier for timestamps. A neighbour's IHU echoes the last Hello it
/// heard, which after a restart can be one from the old process, on a clock with another origin
/// (RFC 9616 §3.3). Flushing the entry removes the echo, but not an IHU already in the neighbour's
/// packet buffer, which leaves with the acknowledgement at the latest. So the rest of the packet
/// with the acknowledgement is discarded too.
///
/// A small window remains, as the node starts up with each neighbour separately. It can learn
/// routes from one while its startup packet to another hasn't arrived, and that one still routes
/// through it. That takes the packets to that neighbour being lost for the few seconds it takes
/// the first to become usable, while those from it get through. It ends with the first startup
/// packet to arrive, or when the neighbour counts two of this node's Hellos as missed.
///
/// # Duplicate addresses
///
/// A prefix that a node originates is exclusive to its router-id, unless it is injected as
/// nonexclusive (see [`State::inject_route`]): no other router may originate it, nor any prefix
/// inside it, which would take some of its addresses by the longest match. A nonexclusive prefix's
/// updates carry a Nonexclusive sub-TLV, an experimental extension, which the nodes that advertise
/// the route on keep.
///
/// Two sources conflict if their router-ids differ, and the prefix of one contains the other's,
/// or is the same, and is exclusive. So an exclusive prefix conflicts with the same prefix, and any
/// prefix inside it, from another router, while a nonexclusive one, such as a default route at each
/// of several exit nodes, conflicts with nothing inside it. An update conflicts with what a node
/// has if it conflicts with a route injected by the node, or with any route through a neighbour,
/// except the route through the sender of the update for the same prefix, which the update
/// replaces.
///
/// A conflicting update is rejected. It still removes the route through its sender, which no
/// longer advertises it, as a retraction would. For each prefix whose sources block it, the node
/// sends a Conflict Alert, another experimental extension, to the next hop of the prefix's selected
/// route, and each node on the way sends it on along its own, until it reaches the prefix's
/// originator. The alert counts the hops it has come, so that each node can tell how far away the
/// rejecting node is. Of two nodes originating prefixes that conflict, each hears of the
/// other, over its own prefix, from the nodes where their routes meet, which reject each other's
/// updates. At most one alert per prefix and next hop goes out per Conflict Alert interval.
///
/// Each node reports what it sees as an [`Output::ConflictAlert`], naming the neighbour that the
/// update or alert came from, and for an alert, how many hops away the routes meet, so that the
/// conflict can be traced by hand from either side. Following those neighbours from an originator
/// leads to where the routes meet, and from there, the selected routes lead to the other
/// originator. Router-ids are left out: they are random on every start, so they would tell no one
/// which node to look at.
///
/// Nothing else is done about a conflict: each node keeps what it learnt first until it loses it,
/// and then the seqno request that it sends for the lost route is answered with a route from
/// another router, if a neighbour has one. Where an exclusive prefix was learnt first, that keeps
/// the addresses of a prefix inside it from being taken over. Where the prefix inside it was, the
/// exclusive one is rejected, and the rest of its addresses can't be reached from there until the
/// conflict is resolved. A node that restarts with a new router-id can briefly conflict with its
/// own old routes, until the retractions of those have reached every node (see
/// [Reboots](State#reboots)).
///
/// No two sources in a node's table conflict, as every conflicting update is rejected. So an update
/// from a source that the prefix already has a route from conflicts with nothing, and only the
/// others are checked, which keeps the cost of the check out of the refreshes that make up nearly
/// all updates.
pub struct State {
    params: Params,
    router_id: RouterId,
    seqno: Seqno,
    neigh_table: SlotMap<NeighKey, NeighEntry>,
    source_table: HashMap<SourceKey, SourceEntry>,
    route_table: RouteTable,
    seqno_request_table: HashMap<IpNet, SeqnoRequestEntry>,
    /// The prefixes and next hops that this node has sent a Conflict Alert for within the
    /// Conflict Alert interval, which it sends no other for until then.
    conflict_alerts_sent: HashSet<(IpNet, NeighKey)>,
    outputs: VecDeque<Output>,
    timers: TimerQueue<Timer>,
    /// The current time, as a timestamp (see [`timestamp`]).
    now: u32,
    // Temporary states for each received packet.
    /// The prefixes whose routes through the sender have been added, modified, or removed
    /// by the packet. A single prefix may appear more than once.
    updated_prefixes: Vec<IpNet>,
    /// The route and seqno requests received, to be handled after route selection.
    requests: Vec<Tlv>,
    /// The prefixes of the Conflict Alerts to send on after route selection: those received,
    /// with how many hops away they say the node that rejected an update is, and those of the
    /// updates rejected, with none.
    conflict_alerts: Vec<(IpNet, Option<NonZeroU8>)>,
    /// The receive timestamp of the packet (RFC 9616 §3.1).
    receive_timestamp: u32,
    hello_timestamp: Option<u32>,
    ihu_timestamps: Option<(u32, u32)>,
}

impl State {
    /// Creates a new `State` at `now`, with the given parameters, router-id, and seqno
    /// (if any). Seqno defaults to a random one if not given.
    pub fn new(now: Instant, params: Params, router_id: RouterId, seqno: Option<Seqno>) -> Self {
        Self {
            params,
            router_id,
            seqno: seqno.unwrap_or_else(|| Seqno::new(rand::random())),
            neigh_table: SlotMap::with_key(),
            source_table: HashMap::new(),
            route_table: RouteTable::default(),
            seqno_request_table: HashMap::new(),
            conflict_alerts_sent: HashSet::new(),
            outputs: VecDeque::new(),
            timers: TimerQueue::new(now),
            now: timestamp(now),
            updated_prefixes: Vec::new(),
            requests: Vec::new(),
            conflict_alerts: Vec::new(),
            receive_timestamp: 0,
            hello_timestamp: None,
            ihu_timestamps: None,
        }
    }

    /// Adds a neighbour and returns its key.
    ///
    /// The neighbour is sent a startup packet at once, unbuffered, to remove any route
    /// through this node from before a reboot, and anything else it sends is discarded
    /// until that is acknowledged (see [Reboots]). If this node has already learnt routes,
    /// packets coming from the neighbour could loop until it arrives, for example when
    /// node 1 adds node 2 after node 3 in the network of [Reboots].
    ///
    /// Once it is acknowledged, the neighbour is sent the first Hello, a request for a
    /// full route table dump, and the first such dump of this node, buffered as usual.
    /// The second Hello and dump go a random part of their intervals later, and each one
    /// after that 0.96875 to 1.03125 intervals after the one before.
    ///
    /// [Reboots]: State#reboots
    pub fn add_neighbour(&mut self, now: Instant) -> NeighKey {
        self.add_neighbour_with_hello_seqno(now, Seqno::new(rand::random()))
    }

    /// Adds a neighbour, with the seqno of the first Hello sent to it.
    fn add_neighbour_with_hello_seqno(&mut self, now: Instant, hello_seqno: Seqno) -> NeighKey {
        self.set_now(now);

        let key = (self.neigh_table).insert(NeighEntry::new(&self.params, hello_seqno));
        self.route_table.neigh_prefixes.insert(key, HashSet::new());

        let opaque = rand::random();
        let timeout = (self.params.get(DurationKey::StartupTimeout))
            .min(self.params.get(DurationKey::HelloInterval));
        self.neigh_table[key].startup = Some(Startup {
            opaque,
            timeout,
            timer_key: self.timers.insert(Timer::Startup(key), timeout),
        });
        self.send_startup_packet(key, opaque);

        key
    }

    /// Sends a neighbour the startup packet.
    fn send_startup_packet(&mut self, key: NeighKey, opaque: u16) {
        let retraction = self.wildcard_retraction();
        let neigh = &mut self.neigh_table[key];
        let tlvs = [
            retraction,
            neigh.far_hello(None),
            neigh.hello(Some(self.params.get(IntervalKey::Hello))),
            Tlv::AcknowledgementRequest {
                opaque,
                interval: Interval::new(1).expect("the interval should not be zero"),
            },
        ];
        neigh.hello_seqno += 1;

        self.send(Some(key), Some(Duration::ZERO), |e| e.put_tlvs(&tlvs));
    }

    /// Starts on the usual exchange with a neighbour, whose startup is over.
    fn finish_startup(&mut self, key: NeighKey) {
        let startup = self.neigh_table[key].startup.take();
        self.timers.remove(
            startup
                .expect("the neighbour should be starting up")
                .timer_key,
        );

        self.send_hello(key);
        let request = Tlv::RouteRequest {
            ae: Ae::Wildcard,
            plen: 0,
            prefix: [0; 16],
        };
        self.send(Some(key), None, |e| e.put_tlv(&request));
        self.dump_routes(key);

        let neigh = &mut self.neigh_table[key];
        let timeout = self.params.random_part(DurationKey::HelloInterval);
        neigh.outgoing_hello_timer_key =
            Some(self.timers.insert(Timer::OutgoingHello(key), timeout));
        let timeout = self.params.random_part(DurationKey::UpdateInterval);
        neigh.outgoing_update_timer_key =
            Some(self.timers.insert(Timer::OutgoingUpdate(key), timeout));
    }

    /// Removes a neighbour, for example because it can't be reached for the time being. Nothing
    /// more is sent to it, including anything not yet polled with [`Self::poll_output`], and its
    /// routes are removed at once, as if it had been flushed. It can be added again later, with a
    /// new key, and is then treated as any new neighbour.
    pub fn remove_neighbour(&mut self, now: Instant, key: NeighKey) {
        self.set_now(now);

        let mut neigh = self
            .neigh_table
            .remove(key)
            .expect("the neighbour should exist");
        neigh.flush(&mut self.timers);

        let timer_keys = [
            neigh.outgoing_hello_timer_key,
            neigh.outgoing_update_timer_key,
            neigh.packet_buf.flush_timer_key,
            neigh.startup.map(|startup| startup.timer_key),
        ];
        for timer_key in timer_keys.into_iter().flatten() {
            self.timers.remove(timer_key);
        }

        self.outputs.retain(|output| match output {
            Output::Packet(to, _) => *to != key,
            Output::RouteSelect(_, via) => *via != key,
            Output::ConflictAlert { from, .. } => *from != key,
            Output::RouteHold(_) | Output::RouteRemove(_) => true,
        });

        let prefixes = self.remove_neigh_routes(key);
        self.route_table.neigh_prefixes.remove(key);
        for prefix in prefixes {
            self.select_route(prefix, Some(key));
        }
    }

    /// Injects a route for a prefix that this node originates, as nonexclusive or not (see
    /// [Duplicate addresses](State#duplicate-addresses)), returning `false` if the route table
    /// already has an entry for it, whether injected or learned.
    ///
    /// No update is sent for it at once: neighbours first learn of it from the next
    /// periodic update. Injected routes are meant to be added when the node starts,
    /// before any neighbour is added, which this does not delay. One added later isn't checked
    /// against the routes already learnt, which it could conflict with.
    ///
    /// The prefix should not be martian (see [`martian_prefix`]), as neighbours would ignore it.
    pub fn inject_route(&mut self, prefix: IpNet, nonexclusive: bool) -> bool {
        self.route_table.inject(prefix.trunc(), nonexclusive)
    }

    /// Shuts the node down, saying goodbye to every neighbour, and removing every route
    /// selected or held. Returns the outputs left to handle: any not yet polled, then
    /// those of the shutdown.
    ///
    /// Each neighbour is sent at once a packet of a wildcard retraction and a Hello with
    /// a far seqno and an interval of 10 ms, and any other buffered TLVs are dropped. On
    /// the retraction, it switches to other routes, or holds the prefixes, rather than
    /// routing through this node until the link fails, and no such route is left to loop
    /// should this node come back soon (see [Reboots](State#reboots)). The seqno has it
    /// flush its entry for this node at once, so that the link fails there and then. It
    /// then counts this node's Hellos as missed every 10 ms, so that even a neighbour that
    /// takes the seqno as new has an empty history after 165 ms, as long as it implements
    /// RFC 8966 Appendix A.1 exactly.
    pub fn shutdown(mut self, now: Instant) -> impl Iterator<Item = Output> {
        self.set_now(now);

        let retraction = self.wildcard_retraction();
        let keys: Vec<_> = self.neigh_table.keys().collect();

        for key in keys {
            let tlvs = [
                retraction.clone(),
                self.neigh_table[key].far_hello(Interval::new(1)),
            ];
            self.send(Some(key), Some(Duration::ZERO), |e| {
                e.clear();
                e.put_tlvs(&tlvs)
            });
        }

        for (&prefix, entry) in &self.route_table.prefix_entries {
            if let PrefixStatus::Selected(..) | PrefixStatus::Held(_) = entry.status {
                self.outputs.push_back(Output::RouteRemove(prefix));
            }
        }

        self.outputs.into_iter()
    }

    /// Returns a view of this router's neighbours and route table at `now`, with each neighbour
    /// identified by what `external` returns for it. Unlike the methods that handle events, this
    /// is not cheap: it copies out the whole route table.
    pub fn snapshot<K>(&self, now: Instant, external: impl Fn(NeighKey) -> K) -> Snapshot<K> {
        let (now, tau) = (timestamp(now), self.params.get_tau());

        let neighbours = (self.neigh_table.iter())
            .map(|(key, neigh)| NeighbourSnapshot {
                key: external(key),
                cost: neigh.cost,
                rtt: neigh.rtt.map(|rtt| Duration::from_secs_f64(rtt / 1e6)),
                rxcost: neigh.rxcost(),
                txcost: neigh.txcost,
                rtt_penalty: neigh.rtt_penalty(),
                hello_history: neigh.hello_history.bits(),
                in_startup: neigh.startup.is_some(),
            })
            .collect();

        let mut prefixes: Vec<_> = (self.route_table.prefix_entries.iter())
            .map(|(&prefix, entry)| {
                let mut routes: Vec<_> = entry.routes.iter().collect();
                routes.sort_unstable_by_key(|&(via, _)| via);

                PrefixSnapshot {
                    prefix,
                    status: match entry.status {
                        PrefixStatus::Injected { nonexclusive } => {
                            snapshot::PrefixStatus::Injected { nonexclusive }
                        }
                        PrefixStatus::Selected(key, _) => {
                            snapshot::PrefixStatus::Selected(external(key))
                        }
                        PrefixStatus::Held(_) => snapshot::PrefixStatus::Held,
                        PrefixStatus::None => snapshot::PrefixStatus::None,
                    },
                    routes: (routes.into_iter())
                        .map(|(via, route)| RouteSnapshot {
                            via: external(via),
                            router_id: route.router_id,
                            seqno: route.seqno,
                            metric: route.metric.get(),
                            smoothed_metric: route.ms_at(now, tau).round() as u16,
                            feasible: route.is_feasible(prefix, &self.source_table),
                            nonexclusive: route.nonexclusive,
                        })
                        .collect(),
                }
            })
            .collect();
        prefixes.sort_unstable_by_key(|entry| entry.prefix);

        Snapshot {
            router_id: self.router_id,
            seqno: self.seqno,
            neighbours,
            prefixes,
        }
    }

    /// Returns a wildcard retraction (RFC 8966 §4.6.9), which retracts every route that
    /// this node has advertised to the neighbour it is sent to.
    fn wildcard_retraction(&self) -> Tlv {
        Tlv::Update {
            ae: Ae::Wildcard,
            flags: UpdateFlags {
                prefix: false,
                router_id: false,
            },
            plen: 0,
            omitted: 0,
            interval: self.params.get(IntervalKey::Update),
            seqno: self.seqno,
            metric: METRIC_INFINITY,
            prefix: [0; 16],
            nonexclusive: false,
        }
    }

    /// Returns when [`handle_timeout`] is next to be called, if ever.
    ///
    /// [`handle_timeout`]: Self::handle_timeout
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.timers.next_deadline()
    }

    /// Polls the next output, if any.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// Handles every timer that has expired at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.set_now(now);
        while let Some(timer) = self.timers.pop_expired() {
            self.handle_expired_timer(timer);
        }
    }

    /// Sets the current time, for the timers and as a timestamp. A time earlier than the
    /// current one is ignored.
    fn set_now(&mut self, now: Instant) {
        if now < self.timers.now() {
            return;
        }
        self.timers.set_now(now);
        self.now = timestamp(now);
    }

    /// Sends a neighbour a scheduled Hello, with an IHU every few Hellos.
    fn send_hello(&mut self, to: NeighKey) {
        let neigh = &mut self.neigh_table[to];

        let mut tlvs = [
            neigh.hello(Some(self.params.get(IntervalKey::Hello))),
            Tlv::Pad1,
        ];

        neigh.hellos_until_ihu -= 1;
        let tlvs = if neigh.hellos_until_ihu == 0 {
            neigh.hellos_until_ihu = self.params.get(U8Key::HellosPerIhu);
            tlvs[1] = neigh.ihu(self.params.get(IntervalKey::Ihu));
            &tlvs
        } else {
            &tlvs[..1]
        };

        neigh
            .packet_buf
            .put(to, &mut self.outputs, &mut self.timers, &self.params, |e| {
                e.put_tlvs(tlvs)
            });

        neigh.hello_seqno += 1;
    }

    /// Tells a neighbour at once that this node now hears it, which its link cost needs in order to
    /// become finite. The next scheduled IHU can be several Hellos away, and the last one may have
    /// reported an infinite rxcost. With timestamps to echo, the IHU has to carry them, in a packet
    /// with a timestamped Hello (RFC 9616 §3.2), so that the neighbour gets an RTT sample as well.
    fn send_unscheduled_ihu(&mut self, to: NeighKey) {
        let neigh = &mut self.neigh_table[to];

        let mut tlvs = [Tlv::Pad1, neigh.ihu(self.params.get(IntervalKey::Ihu))];

        let tlvs = if neigh.origin_receive_timestamps.is_some() {
            tlvs[0] = neigh.hello(None);
            neigh.hello_seqno += 1;
            &tlvs[..]
        } else {
            &tlvs[1..]
        };

        self.send(Some(to), Some(Duration::ZERO), |e| e.put_tlvs(tlvs));
    }

    /// Handles a timer that has expired.
    fn handle_expired_timer(&mut self, timer: Timer) {
        match timer {
            Timer::Startup(key) => {
                let max_timeout = self.params.get(DurationKey::HelloInterval);
                let startup = (self.neigh_table[key].startup.as_mut())
                    .expect("the neighbour should be starting up");
                startup.timeout = (startup.timeout * 2).min(max_timeout);
                startup.timer_key = self.timers.insert(Timer::Startup(key), startup.timeout);
                let opaque = startup.opaque;
                self.send_startup_packet(key, opaque);
            }
            Timer::OutgoingHello(key) => {
                self.send_hello(key);

                let timeout = self.params.jittered(DurationKey::HelloInterval);
                self.neigh_table[key].outgoing_hello_timer_key =
                    Some(self.timers.insert(Timer::OutgoingHello(key), timeout));
            }
            Timer::OutgoingUpdate(key) => {
                self.dump_routes(key);

                let timeout = self.params.jittered(DurationKey::UpdateInterval);
                self.neigh_table[key].outgoing_update_timer_key =
                    Some(self.timers.insert(Timer::OutgoingUpdate(key), timeout));
            }
            Timer::IncomingHello(key) => {
                let neigh = &mut self.neigh_table[key];

                if neigh.hello_history.missed() == HelloEffect::Flush {
                    neigh.incoming_hello_timer_key = None;
                    neigh.flush(&mut self.timers);

                    for prefix in self.remove_neigh_routes(key) {
                        self.select_route(prefix, Some(key));
                    }
                } else {
                    let timeout = neigh.last_hello_interval.unwrap().to_duration();
                    neigh.incoming_hello_timer_key =
                        Some(self.timers.insert(Timer::IncomingHello(key), timeout));

                    if neigh.update_cost() {
                        self.neigh_cost_changed(key);
                    }
                }
            }
            Timer::IncomingIhu(key) => {
                let neigh = &mut self.neigh_table[key];

                neigh.incoming_ihu_timer_key = None;
                neigh.txcost = COST_INFINITY;

                if neigh.update_cost() {
                    self.neigh_cost_changed(key);
                }
            }
            Timer::SourceGc(key) => {
                assert!(self.source_table.remove(&key).is_some());
                self.select_route(key.prefix, None);
            }
            Timer::RouteNearExpiry(prefix, key) => {
                let entry = self.route_table.prefix_entries.get_mut(&prefix).unwrap();
                let route = &mut entry.routes[key];

                let multiplier = self.params.get(F64Key::RouteExpiryTimeMultiplier)
                    - self.params.get(F64Key::RouteNearExpiryTimeMultiplier);
                let timeout = route.last_update_interval.to_duration().mul_f64(multiplier);
                route.timer_key = self.timers.insert(Timer::RouteExpiry(prefix, key), timeout);

                // Shortly before a selected route expires, a route request SHOULD be sent
                // to the neighbour that advertised it (RFC 8966 §3.8.2.3).
                if entry.status.selected() == Some(key) {
                    let (ae, plen, prefix) = encode_prefix(prefix, Ae::Ipv4);
                    let tlv = Tlv::RouteRequest { ae, plen, prefix };
                    self.send(Some(key), None, |e| e.put_tlv(&tlv));
                }
            }
            Timer::RouteExpiry(prefix, key) => {
                assert!(self.route_table.remove(&prefix, key).is_some());
                self.select_route(prefix, Some(key));
            }
            Timer::RouteHold(prefix) => {
                let entry = self.route_table.prefix_entries.get_mut(&prefix).unwrap();
                assert_matches!(entry.status, PrefixStatus::Held(_));

                self.outputs.push_back(Output::RouteRemove(prefix));

                if entry.routes.is_empty() {
                    // Nothing is left to keep the entry for.
                    self.route_table.remove_entry(&prefix);
                } else {
                    entry.status = PrefixStatus::None;
                    entry.advert = None;
                }
            }
            Timer::StaleRouteRetraction(prefix) => {
                // The next hop of the selected route can no longer hold a stale route through
                // this node, so full dumps to it leave the prefix out again, by split horizon.
                let entry = self.route_table.prefix_entries.get_mut(&prefix).unwrap();
                let PrefixStatus::Selected(_, ref mut timer_key @ Some(_)) = entry.status else {
                    panic!("the prefix should be retracted from its next hop");
                };
                *timer_key = None;
            }
            Timer::SeqnoRequest(prefix) => {
                let request = self.seqno_request_table.remove(&prefix).unwrap();
                // Only a request that this node originated has resends left, and only
                // until a route is selected (RFC 8966 §3.8.2.1).
                if request.resends_left > 0 {
                    let key = SourceKey {
                        prefix,
                        router_id: request.router_id,
                    };
                    let resends_left = request.resends_left - 1;
                    self.record_seqno_request(key, request.seqno, resends_left);
                    self.send_seqno_request(None, key, request.seqno, None);
                }
            }
            Timer::ConflictAlert(key) => {
                assert!(self.conflict_alerts_sent.remove(&key));
            }
            Timer::BufferFlush(key) => {
                let buf = &mut self.neigh_table[key].packet_buf;
                buf.flush_timer_key = None;
                buf.flush(key, &mut self.outputs);
            }
        }
    }

    /// Handles a Babel packet that arrived at `received_at`.
    pub fn handle_packet(
        &mut self,
        now: Instant,
        received_at: Instant,
        from: NeighKey,
        buf: &[u8],
    ) {
        // Malformed packets, and TLVs that fail to decode or are otherwise
        // ignored, are silently ignored (RFC 8966 §4.2, §4.3, §4.4, §4.6).
        let Some(decoder) = PacketDecoder::new(buf) else {
            return;
        };

        self.set_now(now);
        self.receive_timestamp = timestamp(received_at);

        if let Some(startup) = &self.neigh_table[from].startup {
            self.handle_packet_during_startup(from, startup.opaque, decoder);
            return;
        }

        let was_deaf = self.neigh_table[from].rxcost() == COST_INFINITY;

        for res in decoder {
            let Ok(item) = res else {
                continue;
            };
            match item {
                PacketItem::Tlv(tlv) => self.handle_tlv(from, &tlv),
                PacketItem::Update(update) => self.handle_update(from, &update),
            }
        }

        if was_deaf && self.neigh_table[from].rxcost() != COST_INFINITY {
            self.send_unscheduled_ihu(from);
        }

        // Delay-based metric extension (RFC 9616).
        if let (Some(t2p), Some((t1, t1p))) = (self.hello_timestamp, self.ihu_timestamps) {
            let t2 = self.receive_timestamp;

            let d = t2.wrapping_sub(t1);
            let dp = t2p.wrapping_sub(t1p);

            const T: u32 = 3 * 60_000_000;
            const ALPHA: f64 = 0.836;

            if d <= T && dp <= T {
                let rtt = &mut self.neigh_table[from].rtt;
                let rtt_n = d.saturating_sub(dp) as f64;

                // RTT := α RTT + (1 - α) RTTn, starting from the first sample.
                *rtt = Some(rtt.map_or(rtt_n, |rtt| ALPHA * (rtt - rtt_n) + rtt_n));
            }
        }

        // Route selection waits until the whole packet has been handled, so that it uses
        // the link cost as changed by the packet's Hellos, IHUs and timestamps. It runs
        // first for every route through the sender if the cost has changed, as they all
        // have a new metric now.
        if self.neigh_table[from].update_cost() {
            self.neigh_cost_changed(from);
        }

        // And then for the updated prefixes. Selection may run more than once for a
        // prefix, but running again is harmless: nothing has changed since the last run,
        // so it makes the same choice and outputs nothing. It is also rare: it only
        // happens in a packet that both changes the link cost and carries updates, or one
        // that updates a prefix more than once.
        let mut prefixes = mem::take(&mut self.updated_prefixes);
        for prefix in prefixes.drain(..) {
            self.select_route(prefix, Some(from));
        }
        self.updated_prefixes = prefixes;

        // Requests are handled against the routes as the packet leaves them. A neighbour
        // that loses its selected route normally sends a retraction and a seqno request
        // in one packet. If this node then selects another route, the request is
        // forwarded along it, and if it selects none, not at all, as this node's own
        // request for the lost route covers it.
        let mut requests = mem::take(&mut self.requests);
        for tlv in requests.drain(..) {
            self.handle_request(from, &tlv);
        }
        self.requests = requests;

        // Conflict Alerts follow the selected routes as the packet leaves them too, so that one
        // queued on rejecting an update goes along the route that the rejection kept.
        let mut alerts = mem::take(&mut self.conflict_alerts);
        for (prefix, hops) in alerts.drain(..) {
            self.handle_conflict_alert(from, prefix, hops);
        }
        self.conflict_alerts = alerts;

        self.hello_timestamp = None;
        self.ihu_timestamps = None;
    }

    fn handle_tlv(&mut self, from: NeighKey, tlv: &Tlv) {
        match *tlv {
            Tlv::Pad1 | Tlv::PadN { .. } | Tlv::RouterId { .. } => {}
            Tlv::Update { .. } => unreachable!(),
            Tlv::AcknowledgementRequest { opaque, interval } => {
                let timeout = interval.to_duration();
                let tlv = Tlv::Acknowledgement { opaque };
                self.send(Some(from), Some(timeout), |e| e.put_tlv(&tlv));
            }
            Tlv::Acknowledgement { .. } => {
                // Ignore it, as it is late: a startup packet can be sent again before the
                // acknowledgement of the one before arrives.
            }
            Tlv::Hello {
                seqno,
                interval,
                transmit_timestamp,
            } => {
                let neigh = &mut self.neigh_table[from];

                // A Hello seqno far from the expected one means that the neighbour has
                // probably rebooted, and its whole entry is flushed (RFC 8966 Appendix
                // A.1), routes included (see below).
                let rebooted = neigh.hello_history.received(seqno) == HelloEffect::Flush;
                if rebooted {
                    neigh.flush(&mut self.timers);
                }

                if let Some(interval) = interval {
                    neigh.last_hello_interval = Some(interval);

                    // Reset the neighbour's hello timer to 1.5 times the advertised
                    // Interval (the extra margin allows for delay due to jitter)
                    // (RFC 8966 Appendix A.1). See also `PacketBuf::put`.
                    let timeout = interval.to_duration().mul_f64(1.5);

                    if let Some(timer_key) = &mut neigh.incoming_hello_timer_key {
                        self.timers.reset(timer_key, timeout);
                    } else {
                        neigh.incoming_hello_timer_key =
                            Some(self.timers.insert(Timer::IncomingHello(from), timeout));
                    }
                }

                if let Some(t) = transmit_timestamp {
                    neigh.origin_receive_timestamps = Some((t, self.receive_timestamp));
                    self.hello_timestamp = Some(t);
                }

                // Remove the routes learnt from the neighbour before it rebooted. It has
                // lost its feasibility distances, so they could form loops with the ones
                // it learns now (see Reboots in the doc of `State`). Routes refreshed by
                // updates earlier in this packet are kept, as they come from after the
                // reboot. The prefixes of the others are recorded for route selection at
                // the end of the packet.
                if rebooted {
                    let refreshed: HashSet<_> = self.updated_prefixes.iter().copied().collect();
                    let stale: Vec<_> = (self.route_table.neigh_prefixes[from].iter())
                        .filter(|prefix| !refreshed.contains(prefix))
                        .copied()
                        .collect();
                    for prefix in stale {
                        assert!(self.remove_route(prefix, from));
                    }
                }
            }
            Tlv::Ihu {
                ae: _,
                rxcost,
                interval,
                address: _,
                origin_receive_timestamps,
            } => {
                let neigh = &mut self.neigh_table[from];

                let timeout = interval
                    .to_duration()
                    .mul_f64(self.params.get(F64Key::IhuHoldTimeMultiplier));

                if let Some(timer_key) = &mut neigh.incoming_ihu_timer_key {
                    self.timers.reset(timer_key, timeout);
                } else {
                    neigh.incoming_ihu_timer_key =
                        Some(self.timers.insert(Timer::IncomingIhu(from), timeout));
                }

                if let Some(ts) = origin_receive_timestamps {
                    self.ihu_timestamps = Some(ts);
                }

                neigh.txcost = rxcost;
            }
            Tlv::RouteRequest { .. } | Tlv::SeqnoRequest { .. } => {
                self.requests.push(tlv.clone());
            }
            Tlv::ConflictAlert {
                ae,
                plen,
                hops_away,
                prefix,
            } => {
                // A Conflict Alert with AE 0 already fails to decode as a TLV.
                let prefix = decode_prefix(ae, plen, prefix).unwrap();
                self.conflict_alerts.push((prefix, Some(hops_away)));
            }
        }
    }

    /// Handles a route or seqno request, once the packet's routes have been selected.
    fn handle_request(&mut self, from: NeighKey, tlv: &Tlv) {
        match *tlv {
            Tlv::RouteRequest { ae, plen, prefix } => {
                self.handle_route_request(from, decode_prefix(ae, plen, prefix));
            }
            Tlv::SeqnoRequest {
                ae,
                plen,
                seqno,
                hop_count,
                router_id,
                prefix,
            } => {
                // A seqno request with AE 0 already fails to decode as a TLV.
                let prefix = decode_prefix(ae, plen, prefix).unwrap();
                self.handle_seqno_request(from, seqno, hop_count, router_id, prefix);
            }
            _ => unreachable!(),
        }
    }

    /// Answers a route request for a prefix, or a wildcard one with `None` (RFC 8966
    /// §3.8.1.1, RFC 9229 §2.3).
    fn handle_route_request(&mut self, from: NeighKey, prefix: Option<IpNet>) {
        let Some(prefix) = prefix else {
            // TODO: Full route table dumps SHOULD be rate-limited.
            self.dump_routes(from);
            return;
        };

        let entry = self.route_table.prefix_entries.get(&prefix);

        // The local router-id and seqno are used for retracting an unknown route.
        let advert = entry
            .and_then(|e| self.advert_for_prefix(e))
            .unwrap_or(Advert {
                router_id: self.router_id,
                seqno: self.seqno,
                metric: METRIC_INFINITY,
                nonexclusive: false,
            });

        self.send_update(Some(from), None, false, prefix, advert);
    }

    /// Answers a seqno request (RFC 8966 §3.8.1.2).
    fn handle_seqno_request(
        &mut self,
        from: NeighKey,
        seqno: Seqno,
        hop_count: NonZeroU8,
        router_id: RouterId,
        prefix: IpNet,
    ) {
        let Some(entry) = self.route_table.prefix_entries.get(&prefix) else {
            return;
        };

        let Some(mut advert) = self.advert_for_prefix(entry) else {
            return;
        };

        if advert.metric == METRIC_INFINITY {
            return;
        }

        if advert.router_id != router_id || !advert.seqno.lt(seqno) {
            self.send_update(Some(from), None, true, prefix, advert);
            return;
        } else if self.router_id == router_id {
            // A request whose seqno exceeds this node's by more than `MAX_SEQNO_GAP` is
            // ignored. Raising the seqno by 1 would not satisfy it, but only cost an
            // urgent update, and keep the requester sending requests when it does not
            // impose a similar limit on the gap.
            if seqno - advert.seqno > MAX_SEQNO_GAP {
                return;
            }

            self.seqno += 1;
            advert.seqno = self.seqno;

            self.send_update(Some(from), None, true, prefix, advert);
            return;
        }

        let Some(hop_count) = NonZeroU8::new(hop_count.get() - 1) else {
            return;
        };

        // A node SHOULD compare every incoming seqno request against its list of recently
        // forwarded seqno requests and avoid forwarding the request if it is redundant
        // (RFC 8966 §3.8.1.2).
        let key = SourceKey { prefix, router_id };
        if self.seqno_request_redundant(key, seqno) {
            return;
        }

        // Forward the request to the next hop of the selected route, or if that is the
        // requester, to the next hop of another route with a finite metric, a feasible
        // one if there is any, with the smallest metric.
        //
        // The selected route comes first because a reply over it is forwarded on as an
        // urgent TLV. However, the selected route can be through the requester, mostly
        // when the requester's retraction was lost. For example, take this network, where
        // node 0 originates P, and the link between nodes 0 and 2 is slow, so that node 2
        // routes P through node 1:
        //
        //     0 --- 1
        //      \   /
        //       \ /
        //        2
        //
        // Should the link between nodes 0 and 1 fail, node 1 normally sends a retraction
        // and a seqno request in one packet to node 2. If the packet is lost, the
        // request's first resend, 2 s later, usually reaches node 2 before the retraction
        // is repeated, while node 2 still routes P through node 1. Node 2 then forwards
        // it to node 0, whose reply gives node 2's route through node 0 the new seqno.
        // Once node 2 learns of the loss and switches to that route, the new
        // advertisement satisfies the forwarded request, so node 2 sends it to node 1 as
        // an urgent TLV, and with the new seqno, node 1 accepts it at once.
        //
        // So the other route is the one that selection would pick next: the reply updates
        // it, and is forwarded on once it is selected. Unlike in selection, the route may
        // be unfeasible, which the reply can fix, but its metric must be finite:
        // feasibility ignores the link cost, so a route over a failed link would
        // otherwise come first.
        let feasible = |r: &RouteEntry| r.is_feasible(prefix, &self.source_table);
        let to = entry.status.selected().filter(|&k| k != from).or_else(|| {
            entry
                .routes
                .iter()
                .filter(|&(k, r)| k != from && r.metric.get() != METRIC_INFINITY)
                .min_by_key(|&(k, r)| (!feasible(r), r.metric.get(), k))
                .map(|(k, _)| k)
        });
        let Some(to) = to else {
            return;
        };

        self.record_seqno_request(key, seqno, 0);
        self.send_seqno_request(Some(to), key, seqno, Some(hop_count));
    }

    /// Records a seqno request that this node sends: to resend it up to `resends_left`
    /// times while no route to its prefix is selected, to tell redundant requests, and
    /// to send an update that satisfies it as an urgent TLV (RFC 8966 §3.8.1.2).
    fn record_seqno_request(&mut self, key: SourceKey, seqno: Seqno, resends_left: u8) {
        let request = SeqnoRequestEntry {
            router_id: key.router_id,
            seqno,
            resends_left,
            sent_at: self.now,
            timer_key: self.timers.insert(
                Timer::SeqnoRequest(key.prefix),
                self.params.seqno_request_timeout(resends_left),
            ),
        };

        // A request replaces any pending one for the same prefix, which has the same
        // router-id (see `SeqnoRequestEntry`). One with a seqno no smaller covers the
        // replaced one, as any reply to it satisfies both. One with a smaller seqno is
        // only forwarded once the replaced one is past the redundancy window, unanswered
        // and most likely lost, and its requester's resend asks again.
        //
        // A request with resends left is never replaced: it is pending only while no
        // route is selected, when no request is forwarded, and requests for unfeasible
        // routes are not recorded.
        if let Some(old) = self.seqno_request_table.insert(key.prefix, request) {
            debug_assert_eq!(old.router_id, key.router_id);
            debug_assert_eq!(old.resends_left, 0);
            self.timers.remove(old.timer_key);
        }
    }

    /// Sends the neighbour that advertised an unfeasible route, with `advertised_seqno`,
    /// a seqno request for a feasible update (RFC 8966 §3.8.2.2), with the seqno in the
    /// source table plus 1, which has an entry as the route is unfeasible. For the
    /// selected route, whose unfeasible updates are ignored, the reply also keeps the
    /// route from expiring.
    ///
    /// The request is not recorded, as it would replace any request for a lost route that
    /// is still to be resent, and no neighbour asked for its reply.
    ///
    /// It is only sent if its seqno exceeds `advertised_seqno` by at most
    /// `MAX_SEQNO_GAP`, as the source may otherwise ignore it.
    fn request_feasible_update(
        &mut self,
        neigh_key: NeighKey,
        source_key: SourceKey,
        advertised_seqno: Seqno,
    ) {
        let seqno = self.source_table[&source_key].seqno + 1;
        if seqno - advertised_seqno <= MAX_SEQNO_GAP {
            self.send_seqno_request(Some(neigh_key), source_key, seqno, None);
        }
    }

    /// Sends a seqno request, to the given neighbour or to every one.
    ///
    /// A forwarded request has its decremented `hop_count`, and a request that this node
    /// originates has `None`, for a hop count of 64. Either is sent as an urgent TLV: a
    /// forwarded one SHOULD be (RFC 8966 §3.8.1.2), and an originated one is too, since
    /// the delay before a non-urgent TLV is sent would make up most of the time to regain
    /// a lost route.
    fn send_seqno_request(
        &mut self,
        to: Option<NeighKey>,
        key: SourceKey,
        seqno: Seqno,
        hop_count: Option<NonZeroU8>,
    ) {
        const DEFAULT_HOP_COUNT: NonZeroU8 = NonZeroU8::new(64).unwrap();

        let timeout = self.params.get(DurationKey::UrgentTimeout);

        let (ae, plen, prefix) = encode_prefix(key.prefix, Ae::Ipv4);

        let tlv = Tlv::SeqnoRequest {
            ae,
            plen,
            seqno,
            hop_count: hop_count.unwrap_or(DEFAULT_HOP_COUNT),
            router_id: key.router_id,
            prefix,
        };

        self.send(to, Some(timeout), |e| e.put_tlv(&tlv));
    }

    /// Checks whether a seqno request is redundant (RFC 8966 §3.8.1.2): whether this node
    /// has a pending request for the same source, with a seqno no smaller than `seqno`,
    /// sent less than half the initial request timeout ago.
    ///
    /// That window, 1 s by default, is shorter than the time before a requester first
    /// resends a request, so the resend is forwarded too, making up for a lost copy.
    fn seqno_request_redundant(&self, key: SourceKey, seqno: Seqno) -> bool {
        let window = self.params.get(DurationKey::InitialRequestTimeout) / 2;
        self.seqno_request_table
            .get(&key.prefix)
            .is_some_and(|request| {
                debug_assert_eq!(request.router_id, key.router_id);
                !request.seqno.lt(seqno)
                    && self.now.wrapping_sub(request.sent_at) < window.as_micros() as u32
            })
    }

    /// Handles a packet from a neighbour that hasn't acknowledged this node's startup packet yet,
    /// whose packets can only be discarded, whole, even if one has the acknowledgement (see
    /// [Reboots](State#reboots)). A request for an acknowledgement is still answered, or two nodes
    /// starting up together would wait for each other forever.
    fn handle_packet_during_startup(
        &mut self,
        from: NeighKey,
        opaque: u16,
        decoder: PacketDecoder<'_>,
    ) {
        let mut acknowledged = false;
        for res in decoder {
            match res {
                Ok(PacketItem::Tlv(Tlv::Acknowledgement { opaque: other })) => {
                    acknowledged |= other == opaque;
                }
                Ok(PacketItem::Tlv(tlv @ Tlv::AcknowledgementRequest { .. })) => {
                    self.handle_tlv(from, &tlv);
                }
                _ => {}
            }
        }
        if acknowledged {
            self.finish_startup(from);
        }
    }

    /// Handles an update (RFC 8966 §3.5.3), recording the prefix of any route it changes
    /// for route selection at the end of the packet.
    fn handle_update(&mut self, from: NeighKey, update: &Update) {
        let Update {
            ae,
            plen,
            interval,
            seqno,
            metric,
            prefix,
            router_id,
            nonexclusive,
        } = *update;

        let Some(prefix) = decode_prefix(ae, plen, prefix) else {
            // Wildcard retraction.
            assert_eq!(metric, METRIC_INFINITY);

            let prefixes = self.remove_neigh_routes(from);
            self.updated_prefixes.extend(prefixes);
            return;
        };

        // Routes to such prefixes are ignored, so that no node selects or advertises them
        // (RFC 8966 Appendix C allows this filtering).
        if martian_prefix(prefix) {
            return;
        }

        if metric == METRIC_INFINITY {
            self.remove_route(prefix, from);
            return;
        }

        let router_id = router_id.unwrap();

        if router_id == self.router_id {
            // Do not maintain a route supposedly to the node itself.
            return;
        }

        let near_expiry_time = interval
            .to_duration()
            .mul_f64(self.params.get(F64Key::RouteNearExpiryTimeMultiplier));
        let now = self.now;
        let new_route = move |timers: &mut TimerQueue<Timer>| RouteEntry {
            router_id,
            advertised_metric: metric,
            metric: Cell::new(METRIC_INFINITY),
            metric_smoothed: Cell::new(METRIC_INFINITY as f32),
            metric_smoothed_at: Cell::new(now),
            seqno,
            last_update_interval: interval,
            timer_key: timers.insert(Timer::RouteNearExpiry(prefix, from), near_expiry_time),
            nonexclusive,
        };

        let known = self.route_table.get_or_insert_with_known_source(
            prefix,
            from,
            router_id,
            nonexclusive,
            || new_route(&mut self.timers),
        );
        let (status, route) = match known {
            Some(found) => found,
            None => {
                if self.reject_conflicting_update(from, prefix, router_id, nonexclusive) {
                    return;
                }
                (self.route_table).get_or_insert_with(prefix, from, || new_route(&mut self.timers))
            }
        };

        if let Some(route) = route {
            // An unfeasible update for the selected route, with an unchanged router-id,
            // is ignored, as RFC 8966 §3.5.3 allows, rather than applied, which would
            // unselect the route and can turn a mere rise in its metric into a hold. A
            // seqno request is sent instead (§3.8.2.2), and until a feasible update
            // comes, the route keeps its old metric.
            //
            // babeld instead applies the update and keeps the route. That is loop-free as
            // long as the neighbour keeps its feasibility distances, but after it
            // reboots, the update refreshes a stale route through it, so that a loop can
            // last until the metric reaches infinity. An ignored update leaves such a
            // route to expire.
            let key = SourceKey { prefix, router_id };
            if status.selected() == Some(from)
                && route.router_id == router_id
                && !update_feasible(&self.source_table, key, seqno, metric)
            {
                self.request_feasible_update(from, key, seqno);
                return;
            }

            route.router_id = router_id;
            route.advertised_metric = metric;
            route.seqno = seqno;
            route.last_update_interval = interval;
            route.nonexclusive = nonexclusive;

            // Reset the timer to `RouteNearExpiry` as it can be a `RouteExpiry`.
            self.timers
                .set(route.timer_key, Timer::RouteNearExpiry(prefix, from));
            self.timers.reset(&mut route.timer_key, near_expiry_time);
        }

        self.updated_prefixes.push(prefix);
    }

    /// Removes the route to a prefix through neighbour `from`, if there is one, along with its
    /// expiry timer, and records the prefix for route selection at the end of the packet, as a
    /// retraction does. Returns whether there was one.
    fn remove_route(&mut self, prefix: IpNet, from: NeighKey) -> bool {
        let Some(route) = self.route_table.remove(&prefix, from) else {
            return false;
        };
        self.timers.remove(route.timer_key);
        self.updated_prefixes.push(prefix);
        true
    }

    /// Rejects an update for a prefix from neighbour `from` that conflicts with what this node has
    /// (see [Duplicate addresses](State#duplicate-addresses)), returning whether it did. Updates
    /// from a source that the prefix already has a route from conflict with nothing, and don't come
    /// here (see [`RouteTable::get_or_insert_with_known_source`]).
    ///
    /// The update still replaces the route through `from` for its prefix, if any, which `from` no
    /// longer advertises, so that route is removed as if retracted. This node reports the conflict
    /// over each prefix whose source blocks the update. For each but those that it injects, a
    /// Conflict Alert is then sent along the selected route, once the packet's routes have been
    /// selected, towards the prefix's origin.
    fn reject_conflicting_update(
        &mut self,
        from: NeighKey,
        prefix: IpNet,
        router_id: RouterId,
        nonexclusive: bool,
    ) -> bool {
        let update = Source {
            prefix,
            router_id,
            nonexclusive,
        };
        let conflicting = self.route_table.conflicting(from, update, self.router_id);
        if conflicting.is_empty() {
            return false;
        }

        self.remove_route(prefix, from);

        for blocked in conflicting {
            self.outputs.push_back(Output::ConflictAlert {
                prefix: blocked,
                from,
                kind: ConflictAlertKind::Rejected,
            });
            let status = self.route_table.prefix_entries[&blocked].status;
            if !matches!(status, PrefixStatus::Injected { .. }) {
                self.conflict_alerts.push((blocked, None));
            }
        }
        true
    }

    /// Handles a Conflict Alert for a prefix from neighbour `from`, which says that the node that
    /// rejected an update is `hops_away`, or with none, one that this node queued on rejecting an
    /// update from `from`, once the packet's routes have been selected (see
    /// [Duplicate addresses](State#duplicate-addresses)).
    ///
    /// A node on a side of the conflict reports a received alert, with how far away it says the
    /// rejecting node is: the originator of the prefix, or a node whose selected route doesn't go
    /// through `from`. Any but the originator then sends the alert on to the next hop of that
    /// route, one hop further away, unless it has come 255 hops. An alert with no route to follow
    /// is dropped unreported.
    fn handle_conflict_alert(
        &mut self,
        from: NeighKey,
        prefix: IpNet,
        hops_away: Option<NonZeroU8>,
    ) {
        let Some(entry) = self.route_table.prefix_entries.get(&prefix) else {
            return;
        };

        let injected = matches!(entry.status, PrefixStatus::Injected { .. });
        let to = entry.status.selected().filter(|&key| key != from);

        if let Some(hops) = hops_away
            && (injected || to.is_some())
        {
            self.outputs.push_back(Output::ConflictAlert {
                prefix,
                from,
                kind: ConflictAlertKind::Alerted { hops },
            });
        }

        let Some(to) = to else {
            return;
        };

        // An alert isn't sent on past 255 hops, which bounds one that goes round a loop, should one
        // last. Loops end long before an alert gets round them, as what ends them goes urgently,
        // and alerts don't, and the Conflict Alert interval holds one back on its second lap,
        // unless the first took longer.
        let Some(hops_away) = hops_away.map_or(Some(NonZeroU8::MIN), |hops| hops.checked_add(1))
        else {
            return;
        };

        // At most one alert per prefix and next hop goes out per interval. Rejections recur at
        // the period of full dumps, so an interval shorter than that lets each one's alert
        // through, and only collapses bursts, such as those of several rejecting nodes.
        let key = (prefix, to);
        if !self.conflict_alerts_sent.insert(key) {
            return;
        }
        let interval = self.params.get(DurationKey::ConflictAlertInterval);
        self.timers.insert(Timer::ConflictAlert(key), interval);

        let (ae, plen, prefix) = encode_prefix(prefix, Ae::Ipv4);
        let tlv = Tlv::ConflictAlert {
            ae,
            plen,
            hops_away,
            prefix,
        };
        self.send(Some(to), None, |e| e.put_tlv(&tlv));
    }

    /// Removes the routes through a neighbour along with their expiry timers,
    /// returning their prefixes.
    fn remove_neigh_routes(&mut self, key: NeighKey) -> HashSet<IpNet> {
        let prefixes = mem::take(&mut self.route_table.neigh_prefixes[key]);
        for prefix in &prefixes {
            let entry = self.route_table.prefix_entries.get_mut(prefix).unwrap();
            let route = entry.routes.remove(key).unwrap();
            self.timers.remove(route.timer_key);
        }
        prefixes
    }

    fn neigh_cost_changed(&mut self, key: NeighKey) {
        let prefixes = mem::take(&mut self.route_table.neigh_prefixes[key]);
        for prefix in &prefixes {
            self.select_route(*prefix, Some(key));
        }
        self.route_table.neigh_prefixes[key] = prefixes;
    }

    /// Runs route selection (RFC 8966 §3.6) for a prefix, after its route through the
    /// `changed` neighbour has been added, modified, or removed, or that neighbour's link
    /// cost has changed, or, with no `changed` neighbour, after a source table entry for
    /// the prefix has expired.
    ///
    /// Selection is incremental. While the selected route or the changed one is usable,
    /// only these two are compared, with hysteresis. All routes are considered only when
    /// the selected route changes and becomes unusable, or when a source table entry
    /// expires while nothing is selected. A better route that has not changed is only
    /// switched to when it is next updated, which its neighbour does about once per
    /// Update interval.
    fn select_route(&mut self, prefix: IpNet, changed: Option<NeighKey>) {
        // A prefix may have no entry: a source table entry can outlive it, and selection
        // may have already removed it for a prefix recorded more than once in a packet.
        let Some(entry) = self.route_table.prefix_entries.get_mut(&prefix) else {
            return;
        };

        // The route through the changed neighbour, with its key, if it is not removed.
        let changed_route = changed.and_then(|k| entry.routes.get(k).map(|r| (k, r)));

        if let Some((key, route)) = changed_route {
            let cost = self.neigh_table[key].cost;
            let metric = route.advertised_metric.saturating_add(cost);
            route.set_metric(metric, self.now, self.params.get_tau());
        }

        if let PrefixStatus::Injected { .. } = entry.status {
            return;
        }

        let best_usable = || {
            // If no route to a given destination is selected, then select the route with
            // the smallest metric, ignoring the smoothed metric.
            entry
                .routes
                .iter()
                .filter(|(_, r)| r.is_usable(prefix, &self.source_table))
                .min_by_key(|&(k, r)| (r.metric.get(), k))
        };

        // The route through the changed neighbour, if it is still there with a finite
        // metric, and whether it is also feasible, and so usable.
        let candidate = changed_route.filter(|(_, r)| r.metric.get() != METRIC_INFINITY);
        let candidate_feasible =
            candidate.is_some_and(|(_, r)| r.is_feasible(prefix, &self.source_table));

        // The route to select, and the candidate if it is selected, or would be selected
        // if it were feasible. In the latter case, a node SHOULD send a seqno request to
        // the neighbour that advertised it (RFC 8966 §3.8.2.2, with Erratum 7373).
        let (selection, wanted) = match entry.status {
            PrefixStatus::Injected { .. } => unreachable!(),
            // The selected route has not changed, so it is still usable. Its metric is
            // still finite, and it is still feasible: only advertising tightens
            // feasibility, and advertising the selected route keeps it feasible.
            // This includes a source table entry expiring, with no changed route.
            PrefixStatus::Selected(key, _) if changed != Some(key) => {
                let selected = &entry.routes[key];
                debug_assert!(selected.is_usable(prefix, &self.source_table));

                let ms = |r: &RouteEntry| r.ms_at(self.now, self.params.get_tau());

                // If a route R is selected, then switch to a route R' only when both
                // m(R') < m(R) and ms(R') < ms(R).
                let better =
                    candidate.filter(|(_, r)| r.metric < selected.metric && ms(r) < ms(selected));
                let selection = better
                    .filter(|_| candidate_feasible)
                    .or(Some((key, selected)));
                (selection, better)
            }
            // The selected route has changed. Keep it if it is still usable, or else
            // select the best usable route. An unfeasible update for it with an unchanged
            // router-id was ignored (see `handle_update`), so it is unfeasible here only
            // if its router-id has changed, making it a route for another source, or if
            // an update added it anew after a retraction in the same packet. Either way,
            // it is unselected, as RFC 8966 requires (§3.5.3, §3.6).
            PrefixStatus::Selected(..) => {
                let kept = candidate.filter(|_| candidate_feasible);
                (kept.or_else(best_usable), candidate)
            }
            // Nothing is selected, so no route is usable: one only becomes usable without
            // changing as its source table entry expires. So select the changed route if
            // it is usable, or after such an expiry, the best usable route.
            PrefixStatus::Held(_) | PrefixStatus::None => match changed {
                Some(_) => (candidate.filter(|_| candidate_feasible), candidate),
                None => (best_usable(), None),
            },
        };

        // The wanted candidate's neighbour, router-id, and seqno, if it is unfeasible.
        let unfeasible_wanted = wanted
            .filter(|_| !candidate_feasible)
            .map(|(k, r)| (k, r.router_id, r.seqno));

        // Whether to send a triggered update, which always goes out as an urgent TLV.
        // RFC 8966 requires urgency only when the selected router-id changes (§3.7.2),
        // and recommends it only for the reply to a forwarded seqno request (§3.8.1.2).
        // A retraction or the update for a newly reachable prefix is sent urgently too,
        // saving about 0.9 s per hop by default when they spread.
        let mut trigger_update = false;

        // The router-id of the lost route, if any.
        let mut lost_router_id = None;

        // Whether to retract the prefix from the next hop of the selected route, which may hold
        // a stale route through this node.
        let mut retract = false;

        if let Some((key, route)) = selection {
            // The timer until which full dumps retract the prefix from the next hop, if any.
            let mut retraction_timer_key = None;

            match entry.status {
                PrefixStatus::Injected { .. } => unreachable!(),
                // The prefix is still reachable, possibly with another router-id.
                PrefixStatus::Selected(old_key, timer_key) => {
                    trigger_update = route.router_id != entry.advert.unwrap().router_id;

                    // A neighbour that the selected route now goes through, with another
                    // router-id, is sent a retraction, and every full dump to it retracts the
                    // prefix too for a while. Split horizon (RFC 8966 §3.7.4) leaves it out of
                    // the update for the new route, so it would otherwise keep the route through
                    // this node that it learnt before, which is now stale. Feasibility can't make
                    // up for that, as it only holds for one router-id at a time. For example,
                    // take the network of RFC 8966 §2.7, where nodes S and S' both originate P,
                    // so that node A routes P through node S, and node B through node S', each
                    // with a fallback route through the other:
                    //
                    //     S --- A --- B --- S'
                    //
                    // Should the link between nodes S and A fail, node A switches to its route
                    // through node B, with the router-id of node S', and tells every neighbour
                    // but node B. Node B keeps its route through node A, with the router-id of
                    // node S, which is feasible, as node B has never advertised that router-id.
                    // Should the link between nodes B and S' then fail too, node B switches to
                    // that route, and packets for P go back and forth between nodes A and B.
                    //
                    // §2.7 expects such a loop, which it describes with both links failing at
                    // once, to break as soon as an update has gone around it: node A's update
                    // for its new route would replace the stale route through node A at node B
                    // with one that is unfeasible there, as it goes through node B. By split
                    // horizon, though, neither node advertises its new route to the other, so
                    // the loop lasts until the stale routes expire.
                    //
                    // With the same router-id, the stale route can't make a loop: this node
                    // selected the neighbour's route because it was feasible, which puts the
                    // neighbour's own feasibility distance below the metric that this node had
                    // advertised to it. Nor does a change of router-id through the same
                    // neighbour as before need a retraction: whatever the neighbour learnt from
                    // this node, it learnt before this node switched to it, a switch that one of
                    // the cases here covers, so any retraction from it then goes on until its
                    // timer expires.
                    //
                    // The retraction may be lost, so full dumps to the neighbour retract the
                    // prefix too, until a timer expires, for as long as a held prefix is
                    // retracted. By then, the neighbour will have expired the stale route anyway
                    // (see `PrefixStatus::Held`). With both links failing at once, as in §2.7,
                    // nodes A and B retract the prefix from each other, and both hold it.
                    if old_key == key {
                        retraction_timer_key = timer_key;
                    } else {
                        if let Some(timer_key) = timer_key {
                            self.timers.remove(timer_key);
                        }
                        retract = trigger_update;
                        if retract {
                            retraction_timer_key = Some(self.timers.insert(
                                Timer::StaleRouteRetraction(prefix),
                                self.params.get(DurationKey::RouteHoldTime),
                            ));
                        }
                    }
                }
                // The prefix is newly reachable after a retraction.
                PrefixStatus::Held(timer_key) => {
                    trigger_update = true;

                    // The retraction of the lost route went to every neighbour, but it may have
                    // been lost, and a new route through the neighbour, with another router-id,
                    // stops full dumps to it from retracting the prefix, by split horizon. So it
                    // is retracted again, as above, but only until the hold would have ended,
                    // as the neighbour learnt any stale route before the hold began. The hold
                    // timer becomes the retraction timer.
                    retract = route.router_id != entry.advert.unwrap().router_id;
                    if retract {
                        self.timers
                            .set(timer_key, Timer::StaleRouteRetraction(prefix));
                        retraction_timer_key = Some(timer_key);
                    } else {
                        self.timers.remove(timer_key);
                    }
                }
                // The prefix is newly reachable.
                PrefixStatus::None => trigger_update = true,
            }

            // A route is selected for a prefix that had none, so this node no longer
            // needs a new seqno, and stops resending any request that it originated for
            // the lost route (RFC 8966 §3.8.2.1). The request is kept as long as if its
            // last send had been its last resend, to tell redundant requests and to
            // forward a reply (§3.8.1.2). Its timer was set at that send.
            if !matches!(entry.status, PrefixStatus::Selected(..))
                && let Some(request) = self.seqno_request_table.get_mut(&prefix)
            {
                let new_deadline = self.timers.deadline(request.timer_key)
                    + self.params.seqno_request_timeout(0)
                    - self.params.seqno_request_timeout(request.resends_left);
                request.resends_left = 0;
                self.timers.reset_at(&mut request.timer_key, new_deadline);
            }

            if entry.status.selected() != Some(key) {
                self.outputs.push_back(Output::RouteSelect(prefix, key));
            }

            entry.status = PrefixStatus::Selected(key, retraction_timer_key);

            let advert = Advert {
                router_id: route.router_id,
                seqno: route.seqno,
                metric: route.metric.get(),
                nonexclusive: route.nonexclusive,
            };

            // The reply to a pending seqno request is forwarded as a triggered update.
            // As this node only advertises its selected route, it forwards a reply by
            // advertising the route that the reply updated, once that route is selected,
            // so a triggered update goes out whenever the advertisement satisfies the
            // pending request. A request that this node originated is treated the same,
            // as it may have replaced a forwarded one.
            //
            // An update with a finite metric satisfies a request if the router-ids differ
            // or the update's seqno is no less (§4.6.11).
            if let Some(request) = self.seqno_request_table.get(&prefix)
                && (request.router_id != advert.router_id || !advert.seqno.lt(request.seqno))
            {
                let request = self.seqno_request_table.remove(&prefix).unwrap();
                self.timers.remove(request.timer_key);
                trigger_update = true;
            }

            entry.advert = Some(advert);
        } else if let PrefixStatus::Selected(_, timer_key) = entry.status {
            // The prefix is retracted and no longer reachable.
            trigger_update = true;

            // The retraction goes to every neighbour, the next hop included, which ends any
            // retraction from the next hop alone.
            if let Some(timer_key) = timer_key {
                self.timers.remove(timer_key);
            }

            self.outputs.push_back(Output::RouteHold(prefix));

            entry.status = PrefixStatus::Held(self.timers.insert(
                Timer::RouteHold(prefix),
                self.params.get(DurationKey::RouteHoldTime),
            ));

            let advert = entry.advert.as_mut().unwrap();
            advert.metric = METRIC_INFINITY;
            lost_router_id = Some(advert.router_id);
        }

        let triggered_update =
            trigger_update.then(|| (entry.status.selected(), entry.advert.unwrap()));
        let retraction = retract.then(|| {
            let retraction = Advert {
                metric: METRIC_INFINITY,
                ..entry.advert.unwrap()
            };
            (entry.status.selected().unwrap(), retraction)
        });

        if entry.is_empty() {
            // Nothing is left to keep the entry for.
            self.route_table.remove_entry(&prefix);
        }

        if let Some((not_to, advert)) = triggered_update {
            self.send_update(None, not_to, true, prefix, advert);
        }

        if let Some((key, retraction)) = retraction {
            self.send_update(Some(key), None, true, prefix, retraction);
        }

        // A node that has lost all feasible routes to a given destination but still has
        // unexpired unfeasible routes to that destination MUST send a seqno request; if
        // it doesn't have any such routes, it MAY still send a seqno request. The
        // router-id of the request is set to the router-id of the route that it has just
        // lost, and the requested seqno is the value contained in the source table plus 1
        // (RFC 8966 §3.8.2.1). The lost route has been advertised, so the source table
        // has an entry.
        if let Some(router_id) = lost_router_id {
            let key = SourceKey { prefix, router_id };
            let seqno = self.source_table[&key].seqno + 1;
            let resends_left = self.params.get(U8Key::RequestMaxResends);

            // It MUST be sent to at least one of the neighbours that advertised the
            // unfeasible routes, and SHOULD be sent to all of them. Sending it to every
            // neighbour does so.
            self.record_seqno_request(key, seqno, resends_left);
            self.send_seqno_request(None, key, seqno, None);
        }

        // Request a new seqno from the neighbour that advertised an unfeasible route
        // that would be selected if it were feasible.
        if let Some((neigh_key, router_id, seqno)) = unfeasible_wanted {
            let source_key = SourceKey { prefix, router_id };
            self.request_feasible_update(neigh_key, source_key, seqno);
        }
    }

    /// Sends a neighbour a full dump of the routes that this node advertises, leaving out
    /// those through it for split horizon (RFC 8966 §3.7.4), unless it may hold a stale route
    /// through this node, which is retracted instead (see [`Self::select_route`]).
    fn dump_routes(&mut self, to: NeighKey) {
        let mut updates: Vec<_> = (self.route_table.prefix_entries.iter())
            .filter_map(|(&prefix, entry)| {
                let mut advert = self.advert_for_prefix(entry)?;
                let mut not_to = entry.status.selected();
                // The next hop, if it may hold a stale route through this node, is sent a
                // retraction in place of the route (see `select_route`).
                if let PrefixStatus::Selected(key, Some(_)) = entry.status
                    && key == to
                {
                    advert.metric = METRIC_INFINITY;
                    not_to = None;
                }
                Some((prefix, advert, not_to))
            })
            .collect();

        // By router-id, those with the router-id omitted first, then by prefix, whose
        // derived order is IPv4 first, then by address, then by length.
        updates.sort_unstable_by_key(|&(prefix, advert, _)| {
            let bits = match prefix.addr() {
                IpAddr::V4(addr) => u64::from(addr.to_bits()),
                IpAddr::V6(addr) => addr.to_bits() as u64,
            };
            let omitted = advert.router_id.get() == bits;
            (advert.router_id, !omitted, prefix)
        });

        // An update for a route through `to` is not sent, but still updates the source
        // table, since a seqno request for the route, once lost, takes its seqno from
        // there (see `select_route`). A retraction sent in its place doesn't need to: it
        // only goes out for a while after a triggered update for the route, which updated
        // the source table, and that while, with the wait for the next full dump after it,
        // is well within the source GC time.
        for (prefix, advert, not_to) in updates {
            self.send_update(Some(to), not_to, false, prefix, advert);
        }
    }

    /// Sends an update to the given neighbour or to every one, except `not_to` for split
    /// horizon (RFC 8966 §3.7.4), as an urgent TLV if `urgent`, or else as usual.
    fn send_update(
        &mut self,
        to: Option<NeighKey>,
        not_to: Option<NeighKey>,
        urgent: bool,
        prefix: IpNet,
        advert: Advert,
    ) {
        self.update_source_table(prefix, advert);

        let timeout = urgent.then(|| self.params.get(DurationKey::UrgentTimeout));

        let (ae, plen, prefix) = encode_prefix(prefix, Ae::V4ViaV6);

        let update = Update {
            ae,
            plen,
            interval: self.params.get(IntervalKey::Update),
            seqno: advert.seqno,
            metric: advert.metric,
            prefix,
            router_id: Some(advert.router_id),
            nonexclusive: advert.nonexclusive && advert.metric != METRIC_INFINITY,
        };

        self.send_except(to, not_to, timeout, |e| e.put_update(&update));
    }

    /// Puts what `f` encodes in the packet buffer of the given neighbour or of every one,
    /// to be sent within `timeout` if any, or else as usual.
    ///
    /// If `timeout` is zero, the buffer will be flushed immediately.
    ///
    /// `f` returns whether what it encodes fits in the buffer. If not, it must have
    /// encoded nothing, and is called again once the buffer is flushed. So it must encode
    /// several TLVs all at once or not at all, as [`PacketEncoder::put_tlvs`] does.
    fn send(
        &mut self,
        to: Option<NeighKey>,
        timeout: Option<Duration>,
        f: impl Fn(&mut PacketEncoder) -> bool,
    ) {
        self.send_except(to, None, timeout, f);
    }

    /// Does what [`Self::send`] does, leaving out `not_to`, if any. Sending to every neighbour
    /// leaves out those starting up as well, which would discard it, and which the next startup
    /// packet would retract it from.
    fn send_except(
        &mut self,
        to: Option<NeighKey>,
        not_to: Option<NeighKey>,
        timeout: Option<Duration>,
        f: impl Fn(&mut PacketEncoder) -> bool,
    ) {
        let mut send = |key, neigh: &mut NeighEntry| {
            if not_to == Some(key) {
                return;
            }
            let buf = &mut neigh.packet_buf;
            buf.put(key, &mut self.outputs, &mut self.timers, &self.params, &f);
            if let Some(timeout) = timeout {
                if timeout.is_zero() {
                    self.timers.remove(buf.flush_timer_key.take().unwrap());
                    buf.flush(key, &mut self.outputs);
                } else {
                    buf.schedule_flush(&mut self.timers, timeout);
                }
            }
        };

        if let Some(key) = to {
            send(key, &mut self.neigh_table[key]);
        } else {
            for (key, neigh) in &mut self.neigh_table {
                if neigh.startup.is_none() {
                    send(key, neigh);
                }
            }
        }
    }

    /// Returns the router-id, seqno, and metric to advertise for the prefix,
    /// or the local router-id, seqno, and a zero metric for an injected route,
    /// or the last advertised router-id, seqno, and an infinite metric for a held prefix,
    /// or `None` when no route to the prefix is selected.
    fn advert_for_prefix(&self, entry: &PrefixEntry) -> Option<Advert> {
        match entry.status {
            // A route injected by this node (RFC 8966 §3.7).
            PrefixStatus::Injected { nonexclusive } => Some(Advert {
                router_id: self.router_id,
                seqno: self.seqno,
                metric: 0,
                nonexclusive,
            }),
            _ => entry.advert,
        }
    }

    fn update_source_table(&mut self, prefix: IpNet, advert: Advert) {
        let Advert {
            router_id,
            seqno,
            metric,
            nonexclusive: _,
        } = advert;

        // Only updates with a finite metric, not retractions, are recorded
        // (RFC 8966 §3.7.3).
        if metric == METRIC_INFINITY {
            return;
        }

        let key = SourceKey { prefix, router_id };
        let gc_time = self.params.get(DurationKey::SourceGcTime);

        match self.source_table.entry(key) {
            hash_map::Entry::Occupied(e) => {
                let source = e.into_mut();
                if source.seqno.lt(seqno) {
                    source.seqno = seqno;
                    source.metric = metric;
                } else if source.seqno == seqno && source.metric > metric {
                    source.metric = metric;
                }
                self.timers.reset(&mut source.gc_timer_key, gc_time);
            }
            hash_map::Entry::Vacant(e) => {
                e.insert(SourceEntry {
                    seqno,
                    metric,
                    gc_timer_key: self.timers.insert(Timer::SourceGc(key), gc_time),
                });
            }
        }
    }
}
