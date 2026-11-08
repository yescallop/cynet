use std::{path::Path, time::Duration};

use gotatun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;

#[cfg(unix)]
use super::modes_allow_others;
use super::{Config, Endpoint, decode_key, encode_key, world_accessible};
#[cfg(unix)]
use std::{
    fs::{self, Permissions},
    os::unix::fs::{PermissionsExt, symlink},
};

/// Returns a private key and its public key, both in base64.
fn keys(n: u8) -> (String, String) {
    let secret = StaticSecret::from([n; 32]);
    (
        encode_key(secret.as_bytes()),
        encode_key(PublicKey::from(&secret).as_bytes()),
    )
}

/// A minimal valid config, with one peer, and the given lines added to each section.
fn config_with(interface: &str, wireguard: &str, routing: &str) -> String {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    format!(
        r#"
        [interface]
        {interface}

        [wireguard]
        private_key = "{private}"
        {wireguard}

        [routing]
        mesh = ["10.42.0.0/16"]
        {routing}

        [[peer]]
        public_key = "{peer}"
        "#
    )
}

fn error_of(text: &str) -> String {
    match Config::parse(text, Some("cyn0")) {
        Ok(_) => panic!("the config should be rejected"),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn full_config() {
    let (private, _) = keys(1);
    let (_, peer_a) = keys(2);
    let (_, peer_b) = keys(3);
    let (psk, _) = keys(4);

    let config = Config::parse(
        &format!(
            r#"
            [interface]
            name = "mesh0"
            mtu = 1420
            addresses = ["10.42.0.1", "fd42::1"]

            [wireguard]
            private_key = "{private}"
            listen_port = 51820
            reresolve_secs = 30

            [routing]
            mesh = ["10.42.0.5/16", "fd42::/48", "0.0.0.0/0"]
            attached = ["192.168.7.9/24"]
            kernel_routes = false

            [[peer]]
            public_key = "{peer_a}"
            preshared_key = "{psk}"
            endpoint = "vpn.example.com:51820"

            [[peer]]
            public_key = "{peer_b}"
            endpoint = "[2001:db8::1]:51820"
            "#
        ),
        Some("ignored"),
    )
    .unwrap();

    assert_eq!(config.name, "mesh0");
    assert_eq!(config.mtu, 1420);
    assert_eq!(
        config.addresses,
        [
            "10.42.0.1".parse::<std::net::IpAddr>().unwrap(),
            "fd42::1".parse().unwrap()
        ]
    );
    assert_eq!(config.listen_port, 51820);
    assert_eq!(config.reresolve_interval, Some(Duration::from_secs(30)));
    assert!(!config.kernel_routes);
    // Host bits are cleared from prefixes.
    assert_eq!(config.mesh[0], "10.42.0.0/16".parse().unwrap());
    assert_eq!(config.attached[0], "192.168.7.0/24".parse().unwrap());
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].preshared_key, Some([4; 32]));
    assert_eq!(
        config.peers[0].endpoint,
        Some(Endpoint::Host {
            host: "vpn.example.com".to_owned(),
            port: 51820
        })
    );
    assert_eq!(
        config.peers[1].endpoint,
        Some(Endpoint::Address("[2001:db8::1]:51820".parse().unwrap()))
    );
}

#[test]
fn defaults() {
    let config = Config::parse(&config_with("", "", ""), Some("cyn0")).unwrap();

    assert_eq!(config.name, "cyn0");
    assert_eq!(config.mtu, 1400);
    assert!(config.addresses.is_empty());
    assert_eq!(config.listen_port, 0);
    assert_eq!(config.reresolve_interval, Some(Duration::from_secs(60)));
    assert!(config.kernel_routes);
    assert!(config.attached.is_empty());
    assert_eq!(config.peers[0].endpoint, None);
    assert_eq!(config.peers[0].preshared_key, None);
}

#[test]
fn interface_section_is_optional() {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    let config = Config::parse(
        &format!(
            r#"
            [wireguard]
            private_key = "{private}"

            [routing]
            mesh = []

            [[peer]]
            public_key = "{peer}"
            "#
        ),
        Some("cyn0"),
    )
    .unwrap();

    assert_eq!(config.name, "cyn0");
    assert_eq!(config.mtu, 1400);
}

#[test]
fn zero_disables_reresolution() {
    let config = Config::parse(&config_with("", "reresolve_secs = 0", ""), Some("cyn0")).unwrap();
    assert_eq!(config.reresolve_interval, None);
}

#[test]
fn interface_name_comes_from_the_file_unless_given() {
    assert!(error_of_without_name().contains("name is required"));
    for name in ["", ".", "..", "a/b", "sixteen-letters1", "with space"] {
        let error = error_of(&config_with(&format!("name = {name:?}"), "", ""));
        assert!(error.contains("invalid interface name"), "{name}: {error}");
    }
}

fn error_of_without_name() -> String {
    match Config::parse(&config_with("", "", ""), None) {
        Ok(_) => panic!("the config should be rejected"),
        Err(e) => format!("{e:#}"),
    }
}

/// A prefix length would look like it advertises the prefix, or adds a route to it.
#[test]
fn addresses_have_no_prefix_length() {
    for address in ["10.42.0.1/16", "10.42.0.1/32", "fd42::1/64", "fd42::1/128"] {
        let error = error_of(&config_with(&format!("addresses = [{address:?}]"), "", ""));
        assert!(error.contains("line"), "{address}: {error}");
    }
}

#[test]
fn link_local_and_other_martian_prefixes_are_rejected() {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    let config = |addresses: &str, attached: &str, mesh: &str| {
        format!(
            r#"
            [interface]
            addresses = [{addresses}]

            [wireguard]
            private_key = "{private}"

            [routing]
            attached = [{attached}]
            mesh = [{mesh}]
            kernel_routes = false

            [[peer]]
            public_key = "{peer}"
            "#
        )
    };

    for address in ["\"fe80::1\"", "\"ff02::1\"", "\"127.0.0.1\""] {
        let error = error_of(&config(address, "", ""));
        assert!(error.contains("interface.addresses"), "{address}: {error}");
    }
    for attached in ["\"fe80::/64\"", "\"fe80::1/128\"", "\"224.0.0.0/4\""] {
        let error = error_of(&config("", attached, ""));
        assert!(error.contains("routing.attached"), "{attached}: {error}");
    }
    for mesh in ["\"fe80::/10\"", "\"fe80::1/128\"", "\"ff00::/8\""] {
        let error = error_of(&config("", "", mesh));
        assert!(error.contains("routing.mesh"), "{mesh}: {error}");
    }

    // Prefixes merely covering link-local addresses are fine.
    assert!(Config::parse(&config("", "\"::/0\"", "\"::/0\""), Some("cyn0")).is_ok());
    // Nor does a prefix need any relation to the others.
    assert!(
        Config::parse(
            &config("\"10.1.0.1\"", "\"192.168.7.0/24\"", "\"fd42::/48\""),
            Some("cyn0")
        )
        .is_ok()
    );
}

#[test]
fn default_route_is_rejected_with_kernel_routes() {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    let config = |mesh: &str, kernel_routes: &str| {
        format!(
            r#"
            [wireguard]
            private_key = "{private}"

            [routing]
            mesh = ["{mesh}"]
            {kernel_routes}

            [[peer]]
            public_key = "{peer}"
            "#
        )
    };

    for mesh in ["0.0.0.0/0", "::/0"] {
        assert!(error_of(&config(mesh, "")).contains("kernel_routes"));
        assert!(error_of(&config(mesh, "kernel_routes = true")).contains("kernel_routes"));
        assert!(Config::parse(&config(mesh, "kernel_routes = false"), Some("cyn0")).is_ok());
    }
    assert!(Config::parse(&config("0.0.0.0/1", ""), Some("cyn0")).is_ok());
}

#[test]
fn kernel_routes_need_a_local_prefix_of_the_family() {
    let routes = |interface: &str, routing: &str| {
        let text = config_with(interface, "", routing).replace(
            "mesh = [\"10.42.0.0/16\"]",
            "mesh = [\"10.0.0.0/8\", \"fd42::/48\"]",
        );
        let config = Config::parse(&text, Some("cyn0")).unwrap();
        config.kernel_route_prefixes()
    };
    let v4: IpNet = "10.0.0.0/8".parse().unwrap();
    let v6: IpNet = "fd42::/48".parse().unwrap();

    // With no local prefixes, every route is skipped.
    assert_eq!(routes("", ""), (vec![], vec![v4, v6]));

    // From an address.
    let v4_address = "addresses = [\"10.42.0.1\"]";
    let v6_address = "addresses = [\"fd42::1\"]";
    assert_eq!(routes(v4_address, ""), (vec![v4], vec![v6]));
    assert_eq!(routes(v6_address, ""), (vec![v6], vec![v4]));
    let both = "addresses = [\"10.42.0.1\", \"fd42::1\"]";
    assert_eq!(routes(both, ""), (vec![v4, v6], vec![]));

    // From an attached network, whose traffic the kernel forwards into the mesh.
    let v4_attached = "attached = [\"192.168.7.0/24\"]";
    let v6_attached = "attached = [\"fd43::/64\"]";
    assert_eq!(routes("", v4_attached), (vec![v4], vec![v6]));
    assert_eq!(routes("", v6_attached), (vec![v6], vec![v4]));

    // From one of each.
    assert_eq!(routes(v6_address, v4_attached), (vec![v4, v6], vec![]));

    // With none asked for, none are skipped.
    let off = "kernel_routes = false";
    assert_eq!(routes(both, off), (vec![], vec![]));
    assert_eq!(routes("", off), (vec![], vec![]));
}

/// The check doesn't depend on the local prefixes, so that adding an address to a valid config
/// can't make it invalid.
#[test]
fn default_route_is_rejected_with_no_local_prefix_too() {
    let text = config_with("", "", "").replace("10.42.0.0/16", "0.0.0.0/0");
    assert!(error_of(&text).contains("kernel_routes"));
}

#[test]
fn kernel_routes_is_a_boolean() {
    for value in ["\"auto\"", "\"off\"", "\"true\"", "51820"] {
        let error = error_of(&config_with("", "", &format!("kernel_routes = {value}")));
        assert!(error.contains("line"), "{value}: {error}");
    }
}

#[test]
fn removed_keys_are_rejected() {
    for key in [
        "fwmark = 1",
        "dns = [\"10.0.0.1\"]",
        "pre_up = []",
        "post_up = []",
        "pre_down = []",
        "post_down = []",
        "persistent_keepalive = 25",
        "table = \"auto\"",
    ] {
        let error = error_of(&config_with(key, "", ""));
        assert!(error.contains("unknown field"), "{key}: {error}");
    }
}

#[test]
fn keys_belong_to_their_sections() {
    // Each key, with the index of the one section in which it belongs.
    for (key, section) in [
        ("mtu = 1400", 0),
        ("addresses = []", 0),
        ("listen_port = 51820", 1),
        ("reresolve_secs = 60", 1),
        ("attached = []", 2),
        ("kernel_routes = true", 2),
    ] {
        let placements = [(key, "", ""), ("", key, ""), ("", "", key)];
        for (i, (interface, wireguard, routing)) in placements.into_iter().enumerate() {
            let text = config_with(interface, wireguard, routing);
            if i == section {
                assert!(Config::parse(&text, Some("cyn0")).is_ok(), "{key} in {i}");
            } else {
                assert!(error_of(&text).contains("unknown field"), "{key} in {i}");
            }
        }
    }
}

#[test]
fn reresolution_cannot_outpace_hellos() {
    for secs in [1, 4, 14] {
        let text = config_with("", &format!("reresolve_secs = {secs}"), "");
        assert!(error_of(&text).contains("reresolve_secs"), "{secs}");
    }
    let config = Config::parse(&config_with("", "reresolve_secs = 15", ""), Some("cyn0")).unwrap();
    assert_eq!(config.reresolve_interval, Some(Duration::from_secs(15)));
}

#[test]
fn mtu_must_fit_ipv6() {
    assert!(error_of(&config_with("mtu = 1279", "", "")).contains("mtu"));
    assert!(Config::parse(&config_with("mtu = 1280", "", ""), Some("cyn0")).is_ok());
}

#[test]
fn private_key_is_required_once() {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    let config = |wireguard: &str| {
        format!(
            r#"
            [wireguard]
            {wireguard}

            [routing]
            mesh = []

            [[peer]]
            public_key = "{peer}"
            "#
        )
    };

    assert!(error_of(&config("")).contains("private_key"));
    let both = format!("private_key = \"{private}\"\nprivate_key_file = \"/nonexistent\"");
    assert!(error_of(&config(&both)).contains("only one"));
    assert!(error_of(&config("private_key_file = \"/nonexistent\"")).contains("/nonexistent"));
    assert!(error_of(&config("private_key = \"not a key\"")).contains("private_key"));
}

#[test]
fn private_key_can_come_from_a_file() {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    let path = std::env::temp_dir().join(format!("cynet-test-key-{}", std::process::id()));
    std::fs::write(&path, format!("{private}\n")).unwrap();

    let config = Config::parse(
        &format!(
            r#"
            [wireguard]
            private_key_file = {:?}

            [routing]
            mesh = []

            [[peer]]
            public_key = "{peer}"
            "#,
            path.display().to_string()
        ),
        Some("cyn0"),
    );
    std::fs::remove_file(&path).unwrap();

    assert_eq!(config.unwrap().private_key.to_bytes(), [1; 32]);
}

#[test]
fn peers_are_checked() {
    let (private, public) = keys(1);
    let (_, peer) = keys(2);
    let config = |peers: &str| {
        format!(
            r#"
            [wireguard]
            private_key = "{private}"

            [routing]
            mesh = []

            {peers}
            "#
        )
    };
    let table = |key: &str| format!("[[peer]]\npublic_key = \"{key}\"\n");

    assert!(error_of(&config("")).contains("at least one"));
    assert!(error_of(&config(&table(&public))).contains("own key"));
    assert!(error_of(&config(&(table(&peer) + &table(&peer)))).contains("twice"));
    assert!(error_of(&config(&table("short"))).contains("public key"));
}

#[test]
fn endpoints_are_parsed() {
    let (private, _) = keys(1);
    let (_, peer) = keys(2);
    let endpoint_of = |endpoint: &str| {
        let text = format!(
            r#"
            [wireguard]
            private_key = "{private}"

            [routing]
            mesh = []

            [[peer]]
            public_key = "{peer}"
            endpoint = "{endpoint}"
            "#
        );
        Config::parse(&text, Some("cyn0")).map(|config| config.peers[0].endpoint.clone())
    };

    assert_eq!(
        endpoint_of("203.0.113.5:51820").unwrap(),
        Some(Endpoint::Address("203.0.113.5:51820".parse().unwrap()))
    );
    assert_eq!(
        endpoint_of("example.org:1").unwrap(),
        Some(Endpoint::Host {
            host: "example.org".to_owned(),
            port: 1
        })
    );
    for endpoint in ["example.org", "example.org:port", ":51820", "fd00::1:51820"] {
        assert!(endpoint_of(endpoint).is_err(), "{endpoint}");
    }
}

#[test]
fn unknown_keys_and_missing_sections_are_rejected() {
    assert!(error_of(&config_with("nonsense = 1", "", "")).contains("unknown field"));
    assert!(error_of("[routing]\nmesh = []\n").contains("wireguard"));
    assert!(error_of("[wireguard]\n").contains("routing"));
    assert!(error_of("[wireguard]\n[routing]\n").contains("mesh"));
}

#[test]
fn nonexclusive_entries_are_marked() {
    let config = Config::parse(
        &config_with(
            r#"addresses = ["10.42.0.1", "nonexclusive,10.42.0.9", "nonexclusive,fd42::9"]"#,
            "",
            r#"attached = ["192.168.7.0/24", "nonexclusive,0.0.0.9/0"]"#,
        ),
        Some("cyn0"),
    )
    .unwrap();

    let addresses: Vec<std::net::IpAddr> = ["10.42.0.1", "10.42.0.9", "fd42::9"]
        .map(|addr| addr.parse().unwrap())
        .into();
    let prefixes = |prefixes: &[&str]| -> Vec<IpNet> {
        prefixes
            .iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect()
    };
    assert_eq!(config.addresses, addresses);
    assert_eq!(config.attached, prefixes(&["192.168.7.0/24", "0.0.0.0/0"]));
    // Addresses as host routes, and host bits cleared, as they are advertised.
    assert_eq!(
        config.nonexclusive,
        prefixes(&["10.42.0.9/32", "fd42::9/128", "0.0.0.0/0"])
    );

    // The marking is exact, and the rest must parse as without it.
    for (interface, routing) in [
        (r#"addresses = ["nonexclusive, 10.42.0.9"]"#, ""),
        (r#"addresses = ["unicast,10.42.0.9"]"#, ""),
        (r#"addresses = ["nonexclusive,10.42.0.9/32"]"#, ""),
        ("", r#"attached = ["nonexclusive,192.168.7.0"]"#),
    ] {
        let error = error_of(&config_with(interface, "", routing));
        let line = if interface.is_empty() {
            "line 11"
        } else {
            "line 3"
        };
        assert!(error.contains(line), "{interface}{routing}: {error}");
    }

    // Marked entries are checked as others are.
    let error = error_of(&config_with(
        r#"addresses = ["nonexclusive,fe80::1"]"#,
        "",
        "",
    ));
    assert!(error.contains("interface.addresses"), "{error}");
    let error = error_of(&config_with(
        "",
        "",
        r#"attached = ["nonexclusive,ff02::/16"]"#,
    ));
    assert!(error.contains("routing.attached"), "{error}");
}

/// An error about a misspelt key must not quote the line, which could hold a private key.
#[test]
fn errors_do_not_quote_keys() {
    let secret = "SECRETSECRETSECRETSECRETSECRETSECRETSECRETs=";
    let error = error_of(&format!(
        "[wireguard]\nprivate_keey = \"{secret}\"\n[routing]\nmesh = []\n"
    ));
    assert!(error.contains("line 2"), "{error}");
    assert!(!error.contains(secret), "{error}");
}

#[test]
#[cfg(unix)]
fn others_need_permission_on_the_file_and_every_directory_above_it() {
    const OPEN: [u32; 2] = [0o755, 0o755];

    // On the file: reading or writing, but not executing, and a group isn't others.
    assert!(modes_allow_others(0o644, &OPEN));
    assert!(modes_allow_others(0o602, &OPEN));
    assert!(!modes_allow_others(0o600, &OPEN));
    assert!(!modes_allow_others(0o601, &OPEN));
    assert!(!modes_allow_others(0o640, &OPEN));

    // On any directory above it, not only its parent.
    assert!(!modes_allow_others(0o644, &[0o700, 0o755]));
    assert!(!modes_allow_others(0o644, &[0o755, 0o700]));
    assert!(!modes_allow_others(0o644, &[0o755, 0o750, 0o755]));

    // Search permission is enough for a file known by name, and nothing else will do.
    assert!(modes_allow_others(0o644, &[0o711, 0o755]));
    assert!(!modes_allow_others(0o644, &[0o754, 0o755]));
}

/// These don't depend on where the temporary directory is, as they are private whatever is above.
#[test]
#[cfg(unix)]
fn world_access_is_judged_by_the_real_path() {
    let root = std::env::temp_dir().join(format!("cynet-test-world-{}", std::process::id()));
    let (private, open) = (root.join("private"), root.join("open"));
    fs::create_dir_all(&private).unwrap();
    fs::create_dir_all(&open).unwrap();
    fs::set_permissions(&private, Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&open, Permissions::from_mode(0o755)).unwrap();

    let in_private = private.join("cyn0.toml");
    fs::write(&in_private, "").unwrap();
    fs::set_permissions(&in_private, Permissions::from_mode(0o644)).unwrap();
    let link = open.join("cyn0.toml");
    symlink(&in_private, &link).unwrap();
    let key = open.join("key");
    fs::write(&key, "").unwrap();
    fs::set_permissions(&key, Permissions::from_mode(0o600)).unwrap();

    let results = [
        world_accessible(&in_private).unwrap(),
        world_accessible(&link).unwrap(),
        world_accessible(&key).unwrap(),
    ];
    let missing = world_accessible(&open.join("missing"));
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(results, [false; 3]);
    assert!(missing.is_err());
}

/// A file named with no directory, as in `cynet run cyn0.toml`, has an empty parent path.
#[test]
fn world_access_can_be_judged_for_a_relative_path() {
    assert!(world_accessible(Path::new("Cargo.toml")).is_ok());
}

#[test]
fn keys_round_trip() {
    let key = [7; 32];
    assert_eq!(decode_key(&encode_key(&key)).unwrap(), key);
    assert!(decode_key("not base64!").is_err());
    assert!(decode_key(&encode_key(&key)[..8]).is_err());
}

/// The example in the repository stays valid.
#[test]
fn example_config_is_valid() {
    let config = Config::parse(include_str!("../../examples/cyn0.toml"), None).unwrap();
    assert_eq!(config.name, "cyn0");
    assert_eq!(config.peers.len(), 2);
}
