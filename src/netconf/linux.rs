//! Sets up the interface, as `wg-quick` does, but through netlink rather than `ip`.
//!
//! Everything set here belongs to the interface, which goes away when its TUN device is closed.

use std::{fs, io, net::IpAddr};

use eyre::{Context, ContextCompat};
use futures::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::{
    Handle, LinkUnspec, RouteMessageBuilder, new_connection,
    packet_route::{
        address::{AddressAttribute, AddressFlags},
        route::RouteScope,
    },
};

use crate::config::Config;

/// `IN6_ADDR_GEN_MODE_NONE`: don't generate a link-local address.
const ADDR_GEN_MODE_NONE: &str = "1";

/// Adds the interface's addresses, brings it up, and adds its routes.
pub async fn set_up(config: &Config) -> eyre::Result<()> {
    let name = &config.name;
    let (connection, handle, _) = new_connection().wrap_err("failed to open netlink")?;
    tokio::spawn(connection);

    let link = (handle.link().get())
        .match_name(name.clone())
        .execute()
        .try_next()
        .await
        .wrap_err_with(|| format!("failed to look up the interface {name}"))?
        .wrap_err_with(|| format!("no interface named {name}"))?;
    let index = link.header.index;

    // Before it comes up, or the kernel may assign a link-local address of its own.
    write_interface_sysctl(
        &format!("ipv6/conf/{name}/addr_gen_mode"),
        ADDR_GEN_MODE_NONE,
    )?;
    // cynet writes ICMP errors for this host's own traffic to the TUN, with the interface's
    // address as their source, which the kernel otherwise takes for a spoof. Its router drops
    // packets from peers with such a source.
    write_interface_sysctl(&format!("ipv4/conf/{name}/accept_local"), "1")?;

    for address in &config.addresses {
        add_address(&handle, index, *address)
            .await
            .wrap_err_with(|| format!("failed to add the address {address}"))?;
    }

    (handle
        .link()
        .set(LinkUnspec::new_with_index(index).up().build()))
    .execute()
    .await
    .wrap_err_with(|| format!("failed to bring up {name}"))?;

    let (routes, skipped) = config.kernel_route_prefixes();
    for prefix in &skipped {
        tracing::warn!(
            "skipping the kernel route for {prefix}, as this node has no address or attached \
             network of its family"
        );
    }
    for route in &routes {
        add_route(&handle, index, route)
            .await
            .wrap_err_with(|| format!("failed to add the route {route}"))?;
    }

    Ok(())
}

/// Adds an address as a host route, which only makes it this host's: an IPv6 address would
/// otherwise add a route to the main table as well.
async fn add_address(handle: &Handle, index: u32, address: IpAddr) -> Result<(), rtnetlink::Error> {
    let prefix_len = IpNet::from(address).prefix_len();
    let mut request = handle.address().add(index, address, prefix_len);
    (request.message_mut().attributes).push(AddressAttribute::Flags(AddressFlags::Noprefixroute));
    request.execute().await
}

async fn add_route(handle: &Handle, index: u32, route: &IpNet) -> Result<(), rtnetlink::Error> {
    let builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(route.addr(), route.prefix_len())
        .expect("the prefix should be valid")
        .output_interface(index);
    // As `ip route add` does for a route with no gateway.
    let builder = match route {
        IpNet::V4(_) => builder.scope(RouteScope::Link),
        IpNet::V6(_) => builder,
    };

    match handle.route().add(builder.build()).execute().await {
        // A directly attached network can already have this route, on its own interface.
        Err(rtnetlink::Error::NetlinkError(error))
            if error.to_io().kind() == io::ErrorKind::AlreadyExists =>
        {
            Ok(())
        }
        result => result,
    }
}

/// Writes a sysctl under `/proc/sys/net`, unless it doesn't exist, which is the case for IPv6
/// settings where IPv6 is disabled.
fn write_interface_sysctl(path: &str, value: &str) -> eyre::Result<()> {
    let path = format!("/proc/sys/net/{path}");
    match fs::write(&path, value) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result.wrap_err_with(|| format!("failed to write {path}")),
    }
}

/// Warns if the kernel won't forward traffic for the attached networks, which it has to do, as
/// cynet has no socket on them.
pub fn warn_if_not_forwarding(config: &Config) {
    let enabled = |path: &str| {
        fs::read_to_string(format!("/proc/sys/net/{path}")).is_ok_and(|value| value.trim() != "0")
    };

    if config
        .attached
        .iter()
        .any(|prefix| matches!(prefix, IpNet::V4(_)))
        && !enabled("ipv4/ip_forward")
    {
        tracing::warn!(
            "net.ipv4.ip_forward is off, so the attached IPv4 networks can't be reached"
        );
    }
    if config
        .attached
        .iter()
        .any(|prefix| matches!(prefix, IpNet::V6(_)))
        && !enabled("ipv6/conf/all/forwarding")
    {
        tracing::warn!(
            "net.ipv6.conf.all.forwarding is off, so the attached IPv6 networks can't be reached"
        );
    }
}
