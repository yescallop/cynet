//! Runs a node: the WireGuard device, the Babel driver, and everything between them.

#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap}, hash::Hash, net::SocketAddr, sync::Arc, thread, time::Duration,
};

use eyre::{Context, bail};
use futures::future::join_all;
use gotatun::{
    device::{Device, DeviceBuilder, DeviceTransports, Peer},
    tun::{IpRecv, IpSend, tun_async_device::TunDevice},
    udp::UdpTransportFactory,
    x25519::PublicKey,
};
use parking_lot::Mutex;
use tokio::{
    net::lookup_host,
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval, timeout},
};

use crate::{
    babel::{
        Output, Params, RouterId,
        driver::{self, Input},
        snapshot::Snapshot,
    },
    config::{Config, Endpoint, encode_key},
    conflicts::ConflictLog,
    netconf,
    router::{Router, RouterConfig, local_prefixes},
    show::{ShowServer, Status},
};

/// The capacity of the channel into the driver. A full route table dump from every neighbour at
/// once takes about d × N / 42 packets, which comes to 360 at N = 1,000 and d = 15, and 670 at
/// N = 14,000 and d = 2.
const INPUT_CAPACITY: usize = 1024;

/// The capacity of the channel out of the driver, which waits when it is full.
const OUTPUT_CAPACITY: usize = 1024;

/// How long to wait for endpoints to resolve before saying hello to the peers. Those not resolved
/// by then join in later, once a startup packet finds their endpoint.
const INITIAL_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for the driver to say goodbye to every neighbour.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// How often to look for conflicts over prefixes that have ended, to log their end. `cynet show`
/// leaves them out as soon as they end, whenever it looks.
const CONFLICT_EXPIRY_CHECK: Duration = Duration::from_secs(5);

/// Generates a random router-id, new on every start: the feasibility distances that other nodes
/// keep for this node's earlier router-ids can't get in the way.
fn random_router_id() -> RouterId {
    loop {
        if let Some(router_id) = RouterId::new(rand::random()) {
            return router_id;
        }
    }
}

/// A peer whose endpoint is a hostname.
struct HostPeer {
    public_key: PublicKey,
    host: String,
    port: u16,
    /// What had been received from it at the last look, if any.
    last_rx_bytes: Option<usize>,
}

/// BiMap for peer name
pub struct PeerNames<K, V> {
    forward: HashMap<K, V>,
    reverse: HashMap<V, K>,
}

impl<K, V> PeerNames<K, V>
where
    K: Eq + Hash + Clone,
    V: Eq + Hash + Clone,
{
    fn new() -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    fn insert(&mut self, key: K, value: V) {
        self.remove_by_key(&key);
        self.remove_by_value(&value);

        self.forward.insert(key.clone(), value.clone());
        self.reverse.insert(value, key);
    }

    /// Get value by key
    pub fn get_by_key(&self, key: &K) -> Option<&V> {
        self.forward.get(key)
    }

    /// Get key by value
    pub fn get_by_value(&self, value: &V) -> Option<&K> {
        self.reverse.get(value)
    }

    fn remove_by_key(&mut self, key: &K) {
        if let Some(value) = self.forward.remove(key) {
            self.reverse.remove(&value);
        }
    }

    fn remove_by_value(&mut self, value: &V) {
        if let Some(key) = self.reverse.remove(value) {
            self.forward.remove(&key);
        }
    }
}

/// A running node, on some transports.
pub struct Node<T: DeviceTransports> {
    device: Arc<Device<T>>,
    inputs: mpsc::Sender<Input<PublicKey>>,
    router_id: RouterId,
    public_key: PublicKey,
    started: Instant,
    conflicts: Arc<Mutex<ConflictLog>>,
    driver: thread::JoinHandle<()>,
    outputs_task: JoinHandle<()>,
    endpoints_task: Option<JoinHandle<()>>,
    peer_names: Arc<PeerNames<String, PublicKey>>,
}

impl<Udp, TunTx, TunRx> Node<(Udp, TunTx, TunRx)>
where
    Udp: UdpTransportFactory,
    TunTx: IpSend,
    TunRx: IpRecv,
{
    /// Starts a node over the transports of `builder`, with the Babel parameters in `params`,
    /// apart from the MTU, which comes from `config`.
    pub async fn start(
        config: &Config,
        mut params: Params,
        builder: DeviceBuilder<Udp, TunTx, TunRx>,
    ) -> eyre::Result<Self> {
        let public_key = PublicKey::from(&config.private_key);
        let router_id = random_router_id();

        params.set_mtu(config.mtu);
        let conflicts = Arc::new(Mutex::new(ConflictLog::new(params.get_conflict_expiry())));

        let (inputs, inputs_rx) = mpsc::channel(INPUT_CAPACITY);
        let (outputs_tx, outputs) = mpsc::channel(OUTPUT_CAPACITY);

        let router = Arc::new(Router::new(
            RouterConfig {
                public_key,
                addresses: &config.addresses,
                attached: &config.attached,
                mesh: &config.mesh,
                router_id,
            },
            inputs.clone(),
        ));

        let mut host_peers = Vec::new();
        let mut peer_names = PeerNames::new();
        let device_peers = config.peers.iter().map(|peer| {
            let mut device_peer = Peer::new(peer.public_key);
            device_peer.preshared_key = peer.preshared_key;
            match &peer.endpoint {
                Some(Endpoint::Address(addr)) => device_peer.endpoint = Some(*addr),
                Some(Endpoint::Host { host, port }) => host_peers.push(HostPeer {
                    public_key: peer.public_key,
                    host: host.clone(),
                    port: *port,
                    last_rx_bytes: None,
                }),
                None => {}
            }
            if let Some(peer_name) = &peer.peer_name {
                peer_names.insert(peer_name.clone(), peer.public_key);
            }
            device_peer
        });
        let device_peers: Vec<_> = device_peers.collect();

        let device = builder
            .with_private_key(config.private_key.clone())
            .with_listen_port(config.listen_port)
            .with_peers(device_peers)
            .with_router(router.clone())
            .build()
            .await
            .wrap_err("failed to start the WireGuard device")?;
        let device = Arc::new(device);

        let prefixes = local_prefixes(&config.addresses, &config.attached)
            .map(|prefix| (prefix, config.nonexclusive.contains(&prefix)))
            .collect();
        let driver = driver::spawn(params, router_id, prefixes, inputs_rx, outputs_tx)
            .wrap_err("failed to start the Babel driver")?;

        let outputs_task = tokio::spawn(handle_outputs(
            outputs,
            device.clone(),
            router,
            conflicts.clone(),
        ));

        // Endpoints are looked up before saying hello to their peers. The first startup packet to
        // a peer starts a handshake, and is lost as it has no session yet, and the next one goes
        // over that session if it is up by then.
        if timeout(
            INITIAL_LOOKUP_TIMEOUT,
            refresh_endpoints(&device, &mut host_peers),
        )
        .await
        .is_err()
        {
            tracing::warn!("some endpoints are still being looked up");
        }

        for peer in &config.peers {
            let _ = inputs.send(Input::AddNeighbour(peer.public_key)).await;
        }

        let endpoints_task = config
            .reresolve_interval
            .filter(|_| !host_peers.is_empty())
            .map(|period| {
                let device = device.clone();
                tokio::spawn(async move {
                    let mut ticks = interval(period);
                    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    // The first tick is immediate, and the initial lookup has just been done.
                    ticks.tick().await;
                    loop {
                        ticks.tick().await;
                        refresh_endpoints(&device, &mut host_peers).await;
                    }
                })
            });

        Ok(Self {
            device,
            inputs,
            router_id,
            public_key,
            started: Instant::now(),
            conflicts,
            driver,
            outputs_task,
            endpoints_task,
            peer_names: Arc::new(peer_names),
        })
    }
}

impl<T: DeviceTransports> Node<T> {
    /// Returns a handle for getting the node's status.
    pub fn status(&self) -> Status<T> {
        Status {
            device: self.device.clone(),
            inputs: self.inputs.clone(),
            public_key: self.public_key,
            started: self.started,
            peer_names: self.peer_names.clone(),
            conflicts: self.conflicts.clone(),
        }
    }

    /// Returns the router-id of this node.
    pub fn router_id(&self) -> RouterId {
        self.router_id
    }

    /// Returns the device of this node.
    pub fn device(&self) -> &Arc<Device<T>> {
        &self.device
    }

    /// Asks the driver for a view of the router's state, or returns `None` if it has stopped.
    pub async fn snapshot(&self) -> Option<Snapshot<PublicKey>> {
        driver::snapshot(&self.inputs).await
    }

    /// Waits until the node can't go on: its device has failed, or its driver has stopped.
    pub async fn failed(&mut self) -> eyre::Result<()> {
        tokio::select! {
            () = self.device.wait() => bail!("the WireGuard device failed"),
            _ = &mut self.outputs_task => bail!("the Babel driver stopped"),
        }
    }

    /// Says goodbye to the neighbours and stops.
    pub async fn stop(mut self) {
        if let Some(task) = self.endpoints_task.take() {
            task.abort();
        }

        // The consumer ends with the driver, having sent everything the driver gave it. It has
        // already ended if the driver failed, and a finished task must not be polled again.
        if !self.outputs_task.is_finished() {
            let goodbye = async {
                let _ = self.inputs.send(Input::Shutdown).await;
                let _ = (&mut self.outputs_task).await;
            };
            if timeout(SHUTDOWN_TIMEOUT, goodbye).await.is_err() {
                tracing::warn!("timed out saying goodbye to the neighbours");
                self.outputs_task.abort();
            }
        }

        // The driver's output channel has closed by now, so its thread is ending, unless the
        // goodbye timed out, in which case it isn't worth waiting for.
        if self.outputs_task.is_finished() {
            let _ = tokio::task::spawn_blocking(move || self.driver.join()).await;
        }

        self.device.stop().await;
    }
}

/// Carries out what the driver asks for, until it stops, and logs its reports of conflicts.
async fn handle_outputs<T: DeviceTransports>(
    mut outputs: mpsc::Receiver<Output<PublicKey>>,
    device: Arc<Device<T>>,
    router: Arc<Router>,
    conflicts: Arc<Mutex<ConflictLog>>,
) {
    let mut expiry_checks = interval(CONFLICT_EXPIRY_CHECK);
    expiry_checks.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let output = tokio::select! {
            output = outputs.recv() => match output {
                Some(output) => output,
                None => break,
            },
            _ = expiry_checks.tick() => {
                let ended = conflicts.lock().expire(driver::now());
                for line in ended {
                    line.log();
                }
                continue;
            }
        };

        match output {
            Output::Packet(peer, mut packet) => {
                let packet = router.babel_packet_to(&peer, packet.timestamp(driver::now()));
                if let Err(error) = device.send_to_peer(&peer, packet).await {
                    tracing::debug!("failed to send a Babel packet: {error}");
                }
            }
            Output::RouteSelect(prefix, peer) => {
                tracing::debug!("route to {prefix} through {}", encode_key(peer.as_bytes()));
                router.select_route(prefix, peer);
            }
            Output::RouteHold(prefix) => {
                tracing::debug!("route to {prefix} held");
                router.hold_route(prefix);
            }
            Output::RouteRemove(prefix) => {
                tracing::debug!("route to {prefix} removed");
                router.remove_route(prefix);
            }
            Output::ConflictAlert { prefix, from, kind } => {
                let line = conflicts.lock().record(prefix, kind, from, driver::now());
                if let Some(line) = line {
                    line.log();
                }
            }
        }
    }
}

/// Checks whether a peer's endpoint is worth looking up: unless its received bytes have grown,
/// which only authenticated packets make them do. If they have, its current address is already
/// in use by roaming, and evidently working.
fn needs_lookup(last_rx_bytes: Option<usize>, rx_bytes: usize) -> bool {
    last_rx_bytes.is_none_or(|last| rx_bytes <= last)
}

/// Returns the endpoint to set after looking up a quiet peer's hostname, if any: the first result,
/// when the current endpoint is not among them. That includes the right address on another port,
/// such as one that NAT gave it: a working one would not have let the peer go quiet (see
/// [`needs_lookup`]), and if the peer is only away, its next packet puts the endpoint right.
fn endpoint_to_set(current: Option<SocketAddr>, resolved: &[SocketAddr]) -> Option<SocketAddr> {
    let first = resolved.first()?;
    let known = current.is_some_and(|current| {
        (resolved.iter()).any(|addr| {
            addr.ip().to_canonical() == current.ip().to_canonical() && addr.port() == current.port()
        })
    });
    (!known).then_some(*first)
}

/// Looks up the endpoints of the peers that have gone quiet, and updates those that have changed.
async fn refresh_endpoints<T: DeviceTransports>(device: &Device<T>, peers: &mut [HostPeer]) {
    let stats = device.peers().await;

    let refreshes = peers.iter_mut().filter_map(|peer| {
        let stats = (stats.iter()).find(|stats| stats.peer.public_key == peer.public_key)?;
        let rx_bytes = stats.stats.rx_bytes;
        let last = peer.last_rx_bytes.replace(rx_bytes);
        needs_lookup(last, rx_bytes).then(|| refresh_endpoint(device, peer, stats.peer.endpoint))
    });

    join_all(refreshes).await;
}

/// Looks up a peer's hostname, and updates its endpoint if it has changed.
async fn refresh_endpoint<T: DeviceTransports>(
    device: &Device<T>,
    peer: &HostPeer,
    current: Option<SocketAddr>,
) {
    let resolved: Vec<_> = match lookup_host((peer.host.as_str(), peer.port)).await {
        Ok(resolved) => resolved.collect(),
        Err(error) => {
            tracing::warn!("failed to look up {}: {error}", peer.host);
            return;
        }
    };

    if let Some(endpoint) = endpoint_to_set(current, &resolved) {
        tracing::info!("the endpoint of {} is now {endpoint}", peer.host);
        let set = device.write(async |device| {
            device
                .modify_peer(&peer.public_key, |peer| peer.set_endpoint(Some(endpoint)))
                .await
        });
        if let Err(error) = set.await {
            tracing::warn!("failed to update the endpoint of {}: {error}", peer.host);
        }
    }
}

/// Runs the daemon until a signal or a failure.
pub async fn run(config: Config) -> eyre::Result<()> {
    let tun = netconf::create_tun(&config)?;
    netconf::set_up(&config).await?;
    let tun = TunDevice::from_tun_device(tun).wrap_err("failed to use the TUN device")?;

    let builder = DeviceBuilder::new().with_default_udp().with_ip(tun);
    let mut node = Node::start(&config, Params::new(), builder).await?;

    netconf::warn_if_not_forwarding(&config);

    let server = ShowServer::start(&config.name, node.status());
    if let Err(error) = &server {
        tracing::warn!("`cynet show` won't work: {error:#}");
    }

    let mut interrupt = signal(SignalKind::interrupt()).wrap_err("failed to handle signals")?;
    let mut terminate = signal(SignalKind::terminate()).wrap_err("failed to handle signals")?;

    tracing::info!(
        "{} is up, with router-id {:016x}",
        config.name,
        node.router_id().get()
    );

    let result = tokio::select! {
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
        result = node.failed() => result,
    };

    drop(server);
    // This closes the TUN device, which takes the interface with it.
    node.stop().await;

    result
}
