use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
#[cfg(unix)]
use std::{fs, os::unix::net, path::PathBuf};

use gotatun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(unix)]
use super::read_status;
use super::{
    format_age, format_bytes, format_conflicts, format_neighbour, format_status, read_request,
    short_key, strip_colors,
};
use crate::{
    babel::{
        RouterId, Seqno,
        snapshot::{NeighbourSnapshot, PrefixSnapshot, PrefixStatus, RouteSnapshot, Snapshot},
    },
    config::encode_key,
    conflicts::{ConflictKey, Ongoing, Seen},
};

fn key(n: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([n; 32]))
}

/// Formats the status of an interface up for 61 seconds, with no peers, marking the prefixes in
/// `conflicted`.
fn status(snapshot: &Snapshot<PublicKey>, conflicted: &HashSet<IpNet>) -> String {
    let uptime = Duration::from_secs(61);
    format_status("cyn0", &key(1), 51820, uptime, &[], snapshot, conflicted)
}

#[test]
fn ages_and_sizes_are_readable() {
    let age = |secs| strip_colors(&format_age(Duration::from_secs(secs)));
    assert_eq!(age(1), "1 second");
    assert_eq!(age(42), "42 seconds");
    assert_eq!(age(61), "1 minute, 1 second");
    assert_eq!(age(125), "2 minutes, 5 seconds");
    // As `wg` writes them, with every unit that isn't zero.
    assert_eq!(age(60), "1 minute");
    assert_eq!(age(3_600), "1 hour");
    assert_eq!(age(3_605), "1 hour, 5 seconds");
    assert_eq!(age(3_725), "1 hour, 2 minutes, 5 seconds");
    assert_eq!(age(288_000), "3 days, 8 hours");
    assert_eq!(age(90_061), "1 day, 1 hour, 1 minute, 1 second");
    assert_eq!(age(365 * 86_400 + 1), "1 year, 1 second");
    assert_eq!(age(2 * 365 * 86_400), "2 years");
    // Where `wg` has `Now`, or nothing at all.
    assert_eq!(age(0), "0 seconds");
    assert_eq!(
        strip_colors(&format_age(Duration::from_millis(999))),
        "0 seconds"
    );

    let bytes = |bytes| strip_colors(&format_bytes(bytes));
    assert_eq!(bytes(0), "0 B");
    assert_eq!(bytes(1023), "1023 B");
    assert_eq!(bytes(1024), "1.00 KiB");
    assert_eq!(bytes(1_258_291), "1.20 MiB");
}

#[test]
fn status_has_the_colors_of_wg_show() {
    let snapshot = Snapshot {
        router_id: RouterId::new(1).unwrap(),
        seqno: Seqno::new(1),
        neighbours: vec![],
        prefixes: vec![PrefixSnapshot {
            prefix: "10.42.0.1/32".parse().unwrap(),
            status: PrefixStatus::Injected {
                nonexclusive: false,
            },
            routes: vec![],
        }],
    };
    let text = status(&snapshot, &HashSet::new());

    assert!(
        text.starts_with("\x1b[32m\x1b[1minterface\x1b[0m: \x1b[32mcyn0\x1b[0m\n"),
        "{text:?}"
    );
    assert!(
        text.contains("  \x1b[1mlistening port\x1b[0m: 51820\n"),
        "{text:?}"
    );
    assert!(
        text.contains("  10.42.0.1\x1b[36m/\x1b[0m32  \x1b[32minjected\x1b[0m\n"),
        "{text:?}"
    );
    assert_eq!(
        format_age(Duration::from_secs(42)),
        "42 \x1b[36mseconds\x1b[0m"
    );
    assert_eq!(format_bytes(1024), "1.00 \x1b[36mKiB\x1b[0m");
}

#[test]
fn colors_can_be_removed() {
    assert_eq!(strip_colors(""), "");
    assert_eq!(strip_colors("plain…\n"), "plain…\n");
    assert_eq!(
        strip_colors("\x1b[32m\x1b[1ma\x1b[0m: b…\x1b[0m\n"),
        "a: b…\n"
    );
    // A sequence cut off by the end of the text.
    assert_eq!(strip_colors("a\x1b[3"), "a");
}

/// A node with an injected prefix, and one for each other status, with a route or two.
fn snapshot_with_routes(a: PublicKey, b: PublicKey) -> Snapshot<PublicKey> {
    let route = |via, metric, feasible| RouteSnapshot {
        via,
        router_id: RouterId::new(0x3c7e).unwrap(),
        seqno: Seqno::new(812),
        metric,
        smoothed_metric: metric.saturating_add(2),
        feasible,
        nonexclusive: false,
    };
    Snapshot {
        router_id: RouterId::new(0x8f3a_21c0_7d19_e4b6).unwrap(),
        seqno: Seqno::new(7),
        neighbours: vec![],
        prefixes: vec![
            PrefixSnapshot {
                prefix: "10.42.0.1/32".parse().unwrap(),
                status: PrefixStatus::Injected {
                    nonexclusive: false,
                },
                routes: vec![],
            },
            PrefixSnapshot {
                prefix: "10.42.0.2/32".parse().unwrap(),
                status: PrefixStatus::Selected(b),
                routes: vec![route(a, 342, true), route(b, 96, true)],
            },
            PrefixSnapshot {
                prefix: "10.42.0.9/32".parse().unwrap(),
                status: PrefixStatus::Held,
                routes: vec![route(a, u16::MAX, false)],
            },
            PrefixSnapshot {
                prefix: "fd42::7/128".parse().unwrap(),
                status: PrefixStatus::None,
                routes: vec![route(a, 500, false)],
            },
        ],
    }
}

#[test]
fn routes_are_listed_with_what_their_choice_is_based_on() {
    let (a, b) = (key(2), key(3));
    let snapshot = snapshot_with_routes(a, b);
    let text = strip_colors(&status(&snapshot, &HashSet::new()));
    let (key_a, key_b) = (short_key(&a), short_key(&b));
    let source = "rid 0000000000003c7e, seqno 812";

    // A prefix's status goes beside it, and its routes below it, the selected one first.
    let expected = format!(
        "interface: cyn0\n\
         \x20 public key: {}\n\
         \x20 listening port: 51820\n\
         \x20 router-id: 8f3a21c07d19e4b6, seqno: 7\n\
         \x20 uptime: 1 minute, 1 second\n\
         \n\
         routes:\n\
         \x20 10.42.0.1/32  injected\n\
         \x20 10.42.0.2/32\n\
         \x20   via {key_b}, metric 96 (98), {source}\n\
         \x20   not via {key_a}, metric 342 (344), {source}, feasible\n\
         \x20 10.42.0.9/32  unreachable (held)\n\
         \x20   not via {key_a}, metric infinity (65535), {source}, unfeasible\n\
         \x20 fd42::7/128   no route selected\n\
         \x20   not via {key_a}, metric 500 (502), {source}, unfeasible\n",
        encode_key(key(1).as_bytes())
    );
    assert_eq!(text, expected);
}

#[test]
fn nonexclusive_prefixes_say_so_with_their_routes_below_them() {
    let (a, b) = (key(2), key(3));
    let route = |via, metric| RouteSnapshot {
        via,
        router_id: RouterId::new(0x3c7e).unwrap(),
        seqno: Seqno::new(812),
        metric,
        smoothed_metric: metric,
        feasible: true,
        nonexclusive: true,
    };
    let snapshot = Snapshot {
        router_id: RouterId::new(1).unwrap(),
        seqno: Seqno::new(7),
        neighbours: vec![],
        prefixes: vec![
            // Another origin's route, beside the one this node injects.
            PrefixSnapshot {
                prefix: "0.0.0.0/0".parse().unwrap(),
                status: PrefixStatus::Injected { nonexclusive: true },
                routes: vec![route(a, 200)],
            },
            PrefixSnapshot {
                prefix: "10.42.0.9/32".parse().unwrap(),
                status: PrefixStatus::Selected(b),
                routes: vec![route(a, 342), route(b, 96)],
            },
            PrefixSnapshot {
                prefix: "10.42.0.10/32".parse().unwrap(),
                status: PrefixStatus::Held,
                routes: vec![route(a, u16::MAX)],
            },
        ],
    };
    let colored = status(&snapshot, &HashSet::new());
    let text = strip_colors(&colored);
    let routes = &text[text.find("routes:\n").unwrap()..];

    let (key_a, key_b) = (short_key(&a), short_key(&b));

    let source = "rid 0000000000003c7e, seqno 812";
    assert_eq!(
        routes,
        format!(
            "routes:\n\
             \x20 0.0.0.0/0      injected, nonexclusive\n\
             \x20   not via {key_a}, metric 200 (200), {source}, feasible\n\
             \x20 10.42.0.9/32   nonexclusive\n\
             \x20   via {key_b}, metric 96 (96), {source}\n\
             \x20   not via {key_a}, metric 342 (342), {source}, feasible\n\
             \x20 10.42.0.10/32  unreachable (held), nonexclusive\n\
             \x20   not via {key_a}, metric infinity (65535), {source}, feasible\n"
        )
    );
}

#[test]
fn prefixes_with_conflicts_that_go_on_say_so_last() {
    let (a, b) = (key(2), key(3));
    let mut snapshot = snapshot_with_routes(a, b);
    for route in &mut snapshot.prefixes[1].routes {
        route.nonexclusive = true;
    }
    let conflicted = snapshot.prefixes.iter().map(|entry| entry.prefix).collect();
    let colored = status(&snapshot, &conflicted);
    let text = strip_colors(&colored);
    let prefixes: Vec<_> = (text.lines())
        .filter(|line| line.starts_with("  ") && !line.starts_with("    "))
        .skip_while(|line| !line.starts_with("  10.42.0.1/32"))
        .collect();

    assert_eq!(
        prefixes,
        [
            "  10.42.0.1/32  injected, conflicted",
            "  10.42.0.2/32  nonexclusive, conflicted",
            "  10.42.0.9/32  unreachable (held), conflicted",
            "  fd42::7/128   no route selected, conflicted",
        ]
    );
    assert!(
        colored.contains("  10.42.0.2\x1b[36m/\x1b[0m32  \x1b[35mnonexclusive\x1b[0m, \x1b[31mconflicted\x1b[0m\n"),
        "{colored:?}"
    );
}

/// The labels of a selected route are bold, and an unselected route stays dimmed to the end.
#[test]
fn route_lines_keep_their_colors() {
    let (a, b) = (key(2), key(3));
    let snapshot = snapshot_with_routes(a, b);
    let text = status(&snapshot, &HashSet::new());

    let selected = "\x1b[1mmetric\x1b[0m 96 (98), \
                    \x1b[1mrid\x1b[0m 0000000000003c7e, \x1b[1mseqno\x1b[0m 812\n";
    assert!(text.contains(selected), "{text:?}");

    let unselected = format!(
        "\x1b[2mnot via {}, metric 342 (344), rid 0000000000003c7e, seqno 812, feasible\x1b[0m\n",
        short_key(&a)
    );
    assert!(text.contains(&unselected), "{text:?}");
}

#[test]
fn ongoing_conflicts_are_listed_last() {
    let p = "fd42::/64".parse().unwrap();
    let q = "10.42.0.9/32".parse().unwrap();
    let now = Instant::now() + Duration::from_secs(125);
    let conflict = |prefix, seen, hops, n, secs| Ongoing {
        key: ConflictKey {
            prefix,
            seen,
            from: key(n),
        },
        hops,
        since: now - Duration::from_secs(secs),
    };
    let conflicts = [
        conflict(q, Seen::Learnt, 1, 2, 5),
        conflict(p, Seen::Directly, 0, 2, 125),
        conflict(p, Seen::Learnt, 3, 3, 61),
    ];

    let text = strip_colors(&format_conflicts(&conflicts, now));
    let (k2, k3) = (short_key(&key(2)), short_key(&key(3)));
    assert_eq!(
        text,
        format!(
            "\nconflicts:\n\
             \x20 10.42.0.9/32\n\
             \x20   1 hop away via {k2}, for 5 seconds\n\
             \x20 fd42::/64\n\
             \x20   directly with {k2}, for 2 minutes, 5 seconds\n\
             \x20   3 hops away via {k3}, for 1 minute, 1 second\n"
        )
    );

    // With none, there is no section at all.
    assert_eq!(format_conflicts(&[], now), "");
}

#[test]
fn links_are_shown_with_what_makes_up_their_cost() {
    let neighbour = NeighbourSnapshot {
        key: key(2),
        cost: 99,
        rtt: Some(Duration::from_micros(12_345)),
        rxcost: 96,
        txcost: 96,
        rtt_penalty: 3,
        hello_history: 0b1011,
        in_startup: false,
    };
    let format = |neighbour: &NeighbourSnapshot<PublicKey>| {
        let mut out = String::new();
        format_neighbour(&mut out, neighbour);
        out
    };

    assert_eq!(
        strip_colors(&format(&neighbour)),
        "  link cost: 99, rtt: 12.3 ms\n\
         \x20 rxcost: 96, txcost: 96, rtt penalty: 3\n\
         \x20 hello history: 0000000000001011 (latest last)\n"
    );

    // A link that doesn't work stands out, and a peer that has yet to answer says so.
    let starting = NeighbourSnapshot {
        cost: u16::MAX,
        rtt: None,
        rxcost: u16::MAX,
        txcost: u16::MAX,
        rtt_penalty: 0,
        hello_history: 0,
        in_startup: true,
        ..neighbour
    };
    assert!(
        format(&starting).starts_with("  \x1b[1mlink cost\x1b[0m: \x1b[31minfinity\x1b[0m\n"),
        "{:?}",
        format(&starting)
    );
    assert_eq!(
        strip_colors(&format(&starting)),
        "  link cost: infinity\n\
         \x20 rxcost: infinity, txcost: infinity, rtt penalty: 0\n\
         \x20 hello history: 0000000000000000 (latest last)\n\
         \x20 startup: waiting for an acknowledgement\n"
    );
}

/// Returns a path for a socket of this test process, with nothing there.
#[cfg(unix)]
fn socket_path(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cynet-test-{}-{label}", std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

#[tokio::test]
#[cfg(unix)]
async fn status_comes_from_a_running_daemon() {
    let path = socket_path("running");
    let listener = UnixListener::bind(&path).unwrap();
    let daemon = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream.write_all(b"status\n").await.unwrap();
    });

    let text = read_status(&path).await;
    daemon.await.unwrap();
    fs::remove_file(&path).unwrap();

    assert_eq!(text.unwrap().unwrap(), "status\n");
}

/// Whatever a client says, it gets the status, including an older one asking for the verbose one.
#[tokio::test]
async fn every_request_gets_the_status() {
    for request in [&b"verbose\n"[..], b"nonsense\n", &[b'x'; 64]] {
        let (mut daemon, mut client) = tokio::io::duplex(64);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        read_request(&mut daemon).await;
        daemon.write_all(b"status\n").await.unwrap();
        drop(daemon);

        let mut text = String::new();
        client.read_to_string(&mut text).await.unwrap();
        assert_eq!(text, "status\n", "{request:?}");
    }
}

/// So does a client that keeps quiet without closing its side, such as `socat`, in the end.
#[tokio::test(start_paused = true)]
async fn silent_clients_get_the_status_in_the_end() {
    let (mut daemon, _client) = tokio::io::duplex(64);
    read_request(&mut daemon).await;
}

/// A crash leaves the socket behind, with nothing listening on it.
#[tokio::test]
#[cfg(unix)]
async fn socket_left_by_a_crash_means_not_running() {
    let path = socket_path("left");
    drop(net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());

    let text = read_status(&path).await;
    fs::remove_file(&path).unwrap();

    assert_eq!(text.unwrap(), None);
}

#[tokio::test]
#[cfg(unix)]
async fn missing_socket_means_not_running() {
    let text = read_status(&socket_path("missing")).await;
    assert_eq!(text.unwrap(), None);
}

/// A daemon that is there but doesn't answer is a problem to report, not one to skip.
#[tokio::test(start_paused = true)]
#[cfg(unix)]
async fn silent_daemon_is_an_error() {
    let path = socket_path("silent");
    let listener = UnixListener::bind(&path).unwrap();

    let text = read_status(&path).await;
    drop(listener);
    fs::remove_file(&path).unwrap();

    assert!(format!("{:#}", text.unwrap_err()).contains("timed out"));
}

/// So is any other failure to connect.
#[tokio::test]
#[cfg(unix)]
async fn unusable_path_is_an_error() {
    let file = socket_path("file");
    fs::write(&file, "").unwrap();

    let text = read_status(&file.join("cyn0.sock")).await;
    fs::remove_file(&file).unwrap();

    assert!(format!("{:#}", text.unwrap_err()).contains("failed to read"));
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::show::{read_status, socket_paths};
    use tokio::net::windows::named_pipe::ServerOptions;

    fn pipe_path(label: &str) -> std::path::PathBuf {
        crate::show::socket_path(&format!("test-{}-{label}", std::process::id()))
    }

    #[tokio::test]
    async fn named_pipe_status_is_framed_and_acknowledged() {
        let path = pipe_path("reply");
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        assert!(socket_paths().unwrap().contains(&path));
        let daemon = tokio::spawn(async move {
            server.connect().await.unwrap();
            read_request(&mut server).await;
            let text = "status\n";
            server.write_u32_le(text.len() as u32).await.unwrap();
            server.write_all(text.as_bytes()).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 0);
        });
        let text = read_status(&path).await.unwrap().unwrap();
        daemon.await.unwrap();
        assert_eq!(text, "status\n");
        assert!(!socket_paths().unwrap().contains(&path));
        assert!(read_status(&path).await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_named_pipe_is_an_error() {
        let path = pipe_path("silent");
        let _server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let result = read_status(&path).await;
        assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
    }

    #[tokio::test]
    async fn truncated_named_pipe_reply_is_an_error() {
        let path = pipe_path("truncated");
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let daemon = tokio::spawn(async move {
            server.connect().await.unwrap();
            let _ = read_request(&mut server).await;
            server.write_u32_le(100).await.unwrap();
            server.write_all(b"short").await.unwrap();
        });
        assert!(read_status(&path).await.is_err());
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_interface_names_cannot_select_other_pipes() {
        assert!(crate::show::show(Some(r"..\another")).await.is_err());
    }
}
