//! Configures Wintun through IP Helper, without invoking a shell or changing persistent routes.

use std::{collections::HashSet, io, net::IpAddr, ptr};

use ::windows::Win32::{
    Foundation::{ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR},
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
            FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
            InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
            SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
        IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, MIB_IPPROTO_NETMGMT,
        RouterDiscoveryDisabled, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};
use ::windows::core::PCWSTR;
use eyre::Context;
use ipnet::IpNet;

use crate::config::Config;

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code.is_ok() {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.0 as i32))
    }
}

fn interface_luid(name: &str) -> io::Result<NET_LUID_LH> {
    let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH::default();
    // SAFETY: name is NUL-terminated and luid is writable for the duration of the call.
    check(unsafe { ConvertInterfaceAliasToLuid(PCWSTR(name.as_ptr()), &mut luid) })?;
    Ok(luid)
}

fn socket_address(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                ..Default::default()
            },
        },
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                ..Default::default()
            },
        },
    }
}

fn existing_route_prefixes() -> io::Result<HashSet<IpNet>> {
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            // SAFETY: this table was allocated by GetIpForwardTable2.
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    let mut table = ptr::null_mut();
    // SAFETY: table is a writable output pointer. The returned allocation owns all its rows.
    check(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) })?;
    let table = Table(table);
    let mut prefixes = HashSet::new();
    // SAFETY: the API's trailing array contains exactly NumEntries initialized rows.
    unsafe {
        let rows = std::slice::from_raw_parts(
            ptr::addr_of!((*table.0).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table.0).NumEntries as usize,
        );
        for row in rows {
            let prefix = &row.DestinationPrefix;
            let address = match prefix.Prefix.si_family {
                AF_INET => IpAddr::from(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()),
                AF_INET6 => IpAddr::from(prefix.Prefix.Ipv6.sin6_addr.u.Byte),
                _ => continue,
            };
            if let Ok(prefix) = IpNet::new(address, prefix.PrefixLength) {
                prefixes.insert(prefix.trunc());
            }
        }
    }
    Ok(prefixes)
}

/// Adds host addresses and active-store mesh routes to the Wintun interface.
pub async fn set_up(config: &Config) -> eyre::Result<()> {
    let luid = interface_luid(&config.name).wrap_err("failed to find the Wintun interface")?;
    let (routes, skipped) = config.kernel_route_prefixes();

    for (family, needed) in [
        (
            AF_INET,
            config.addresses.iter().any(IpAddr::is_ipv4)
                || config.attached.iter().any(|prefix| prefix.addr().is_ipv4()),
        ),
        (
            AF_INET6,
            config.addresses.iter().any(IpAddr::is_ipv6)
                || config.attached.iter().any(|prefix| prefix.addr().is_ipv6()),
        ),
    ] {
        if !needed {
            continue;
        }
        let mut row = MIB_IPINTERFACE_ROW::default();
        // SAFETY: IP Helper receives initialized, correctly sized rows; no pointers are retained.
        unsafe {
            InitializeIpInterfaceEntry(&mut row);
            row.Family = family;
            row.InterfaceLuid = luid;
            check(GetIpInterfaceEntry(&mut row))
                .wrap_err("failed to read IP interface settings")?;
            row.NlMtu = config.mtu.into();
            row.SitePrefixLength = 0;
            row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
            row.DadTransmits = 0;
            // ICMP errors injected by cynet may have one of this host's own source addresses.
            row.WeakHostReceive = true;
            // Forward to attached LANs when the operator enables forwarding on their interfaces.
            row.ForwardingEnabled = !config.attached.is_empty();
            check(SetIpInterfaceEntry(&mut row))
                .wrap_err("failed to configure the IP interface")?;
        }
    }

    for address in &config.addresses {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        // SAFETY: all fields required by CreateUnicastIpAddressEntry are initialized below.
        let code = unsafe {
            InitializeUnicastIpAddressEntry(&mut row);
            row.InterfaceLuid = luid;
            row.Address = socket_address(*address);
            row.OnLinkPrefixLength = IpNet::from(*address).prefix_len();
            row.PrefixOrigin = IpPrefixOriginManual;
            row.SuffixOrigin = IpSuffixOriginManual;
            row.DadState = IpDadStatePreferred;
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
            CreateUnicastIpAddressEntry(&row)
        };
        if code != ERROR_OBJECT_ALREADY_EXISTS {
            check(code).wrap_err_with(|| format!("failed to add the address {address}"))?;
        }
    }

    for prefix in skipped {
        tracing::warn!(
            "skipping the kernel route for {prefix}, as this node has no address or attached network of its family"
        );
    }
    // Unlike Linux, Windows permits an equal prefix on another interface. Preserve that route,
    // especially an attached LAN's on-link route, instead of drawing its traffic into the TUN.
    let existing = if routes.is_empty() {
        HashSet::new()
    } else {
        existing_route_prefixes().wrap_err("failed to read existing IP routes")?
    };
    for route in routes {
        if existing.contains(&route.trunc()) {
            continue;
        }
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: the route row and both socket addresses are initialized for the same family.
        let code = unsafe {
            InitializeIpForwardEntry(&mut row);
            row.InterfaceLuid = luid;
            row.DestinationPrefix.Prefix = socket_address(route.network());
            row.DestinationPrefix.PrefixLength = route.prefix_len();
            row.NextHop = socket_address(match route {
                IpNet::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
                IpNet::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
            });
            row.Protocol = MIB_IPPROTO_NETMGMT;
            row.Metric = 0;
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
            CreateIpForwardEntry2(&row)
        };
        if code != ERROR_OBJECT_ALREADY_EXISTS {
            check(code).wrap_err_with(|| format!("failed to add the route {route}"))?;
        }
    }
    Ok(())
}

/// Attached LAN interfaces still need forwarding enabled by their administrator.
pub fn warn_if_not_forwarding(config: &Config) {
    if !config.attached.is_empty() {
        tracing::warn!(
            "attached networks require IP forwarding on their Windows LAN interfaces; \
             enable it with Set-NetIPInterface -InterfaceAlias <LAN> -Forwarding Enabled"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses_preserve_network_byte_order() {
        let v4 = socket_address("192.0.2.7".parse().unwrap());
        let v6 = socket_address("2001:db8::7".parse().unwrap());
        // SAFETY: each union is read with the variant used to initialize it.
        unsafe {
            assert_eq!(v4.si_family, AF_INET);
            assert_eq!(v4.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(), [192, 0, 2, 7]);
            assert_eq!(v6.si_family, AF_INET6);
            assert_eq!(
                v6.Ipv6.sin6_addr.u.Byte,
                "2001:db8::7"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            );
        }
    }

    #[test]
    fn windows_route_table_can_be_read_without_elevation() {
        let prefixes = existing_route_prefixes().unwrap();
        assert!(
            prefixes
                .iter()
                .any(|prefix| prefix.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()))
        );
    }

    /// Opt in from an elevated terminal; never change the host network during ordinary tests.
    #[tokio::test]
    #[ignore = "requires Administrator privileges and CYNET_WINTUN_DLL pointing to the matching DLL"]
    async fn wintun_interface_addresses_routes_and_cleanup() {
        use ::windows::Win32::NetworkManagement::IpHelper::{
            GetIpForwardEntry2, GetUnicastIpAddressEntry,
        };

        let mut config = Config::parse(include_str!("../../examples/cyn0.toml"), None).unwrap();
        config.name = format!("cytest{:x}", std::process::id());
        assert!(
            interface_luid(&config.name).is_err(),
            "test interface already exists"
        );
        let subnet = std::process::id() % 256;
        config.addresses = vec![
            format!("198.18.{subnet}.1").parse().unwrap(),
            format!("fdc7:79e7:{subnet:x}::1").parse().unwrap(),
        ];
        config.mesh = vec![
            format!("198.18.{subnet}.0/24").parse().unwrap(),
            format!("fdc7:79e7:{subnet:x}::/64").parse().unwrap(),
        ];
        config.attached.clear();
        let existing = existing_route_prefixes().unwrap();
        assert!(
            config.mesh.iter().all(|prefix| !existing.contains(prefix)),
            "test prefixes already have routes"
        );
        let tun = crate::netconf::create_tun(&config).unwrap();
        set_up(&config).await.unwrap();
        // Reapplying configuration must leave already-created addresses and routes usable.
        set_up(&config).await.unwrap();
        let luid = interface_luid(&config.name).unwrap();
        // SAFETY: each lookup has its required interface identifier, family and address/prefix.
        unsafe {
            for address in &config.addresses {
                let mut row = MIB_UNICASTIPADDRESS_ROW {
                    InterfaceLuid: luid,
                    Address: socket_address(*address),
                    ..Default::default()
                };
                check(GetUnicastIpAddressEntry(&mut row)).unwrap();
                assert_eq!(row.OnLinkPrefixLength, IpNet::from(*address).prefix_len());
                let mut ip = MIB_IPINTERFACE_ROW {
                    Family: row.Address.si_family,
                    InterfaceLuid: luid,
                    ..Default::default()
                };
                check(GetIpInterfaceEntry(&mut ip)).unwrap();
                assert_eq!(ip.NlMtu, u32::from(config.mtu));
            }
            for prefix in &config.mesh {
                let mut row = MIB_IPFORWARD_ROW2 {
                    InterfaceLuid: luid,
                    ..Default::default()
                };
                row.DestinationPrefix.Prefix = socket_address(prefix.network());
                row.DestinationPrefix.PrefixLength = prefix.prefix_len();
                row.NextHop = socket_address(
                    if prefix.addr().is_ipv4() {
                        "0.0.0.0"
                    } else {
                        "::"
                    }
                    .parse()
                    .unwrap(),
                );
                check(GetIpForwardEntry2(&mut row)).unwrap();
            }
        }
        drop(tun);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while interface_luid(&config.name).is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("closing Wintun should remove the interface and its routes");
    }
}
