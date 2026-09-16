//! Two engines, one process: pairing, messaging and a file transfer over a
//! real TCP connection with a real Noise handshake.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use syncmob::config::{Config, Paths};
use syncmob::engine::{Engine, EngineEvent};
use syncmob::proto::TransferId;
use syncmob::security::{DeviceId, Identity, TrustStore};

const TIMEOUT: Duration = Duration::from_secs(20);

struct Node {
    engine: Engine,
    _dir: tempfile::TempDir,
    downloads: PathBuf,
}

fn node(name: &str) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let downloads = dir.path().join("downloads");
    let cfg = Config {
        device_name: name.into(),
        tcp_port: 0,
        discovery_enabled: false,
        accept_incoming: true,
        download_dir: downloads.clone(),
        max_file_size: 0,
        lan_only: true,
        allow_new_pairings: true,
    };
    let paths = Paths {
        root: dir.path().to_path_buf(),
    };
    let engine =
        Engine::start(Identity::generate().unwrap(), cfg, paths, TrustStore::new()).unwrap();
    Node {
        engine,
        _dir: dir,
        downloads,
    }
}

/// Wait for an event matching `f`, ignoring everything else.
fn wait<T>(n: &Node, what: &str, mut f: impl FnMut(&EngineEvent) -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "timed out waiting for {what}");
        match n.engine.events.recv_timeout(left) {
            Ok(ev) => {
                if let Some(v) = f(&ev) {
                    return v;
                }
            }
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

fn pair(a: &Node, b: &Node) -> (DeviceId, DeviceId) {
    let a_id = a.engine.device_id();
    let b_id = b.engine.device_id();

    b.engine.dial(
        format!("127.0.0.1:{}", a.engine.port()).parse().unwrap(),
        Some(a.engine.public_key()),
    );

    let sas_b = wait(b, "pairing prompt on B", |e| match e {
        EngineEvent::PairingRequired { device, sas, .. } if *device == a_id => Some(sas.clone()),
        _ => None,
    });
    let sas_a = wait(a, "pairing prompt on A", |e| match e {
        EngineEvent::PairingRequired { device, sas, .. } if *device == b_id => Some(sas.clone()),
        _ => None,
    });
    // Both users see the same code; this is what makes the comparison
    // meaningful against a machine-in-the-middle.
    assert_eq!(
        sas_a, sas_b,
        "both sides must display the same pairing code"
    );
    assert_eq!(sas_a.len(), 9);

    a.engine.respond_pairing(b_id, true);
    b.engine.respond_pairing(a_id, true);

    for (n, peer, who) in [(a, b_id, "A"), (b, a_id, "B")] {
        let ok = wait(n, "pairing result", |e| match e {
            EngineEvent::PairingFinished { device, accepted } if *device == peer => Some(*accepted),
            _ => None,
        });
        assert!(ok, "pairing must succeed on {who}");
    }

    assert_eq!(a.engine.trusted().len(), 1);
    assert_eq!(b.engine.trusted().len(), 1);
    (a_id, b_id)
}

#[test]
fn pair_then_exchange_text_and_a_file() {
    let a = node("PC");
    let b = node("Phone");
    let (a_id, b_id) = pair(&a, &b);

    // --- text ---------------------------------------------------------
    a.engine.send_text(b_id, "привет с ПК");
    let got = wait(&b, "text on B", |e| match e {
        EngineEvent::TextReceived { from, text, .. } if *from == a_id => Some(text.clone()),
        _ => None,
    });
    assert_eq!(got, "привет с ПК");

    b.engine.send_text(a_id, "ответ с телефона");
    let got = wait(&a, "text on A", |e| match e {
        EngineEvent::TextReceived { from, text, .. } if *from == b_id => Some(text.clone()),
        _ => None,
    });
    assert_eq!(got, "ответ с телефона");

    // --- file ---------------------------------------------------------
    // Larger than one chunk so the chunking path is exercised.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let src = a._dir.path().join("отчёт.bin");
    std::fs::write(&src, &payload).unwrap();

    a.engine.send_file(b_id, src.clone());
    let (transfer, name, size) = wait(&b, "offer on B", |e| match e {
        EngineEvent::OfferReceived {
            from,
            transfer,
            name,
            size,
        } if *from == a_id => Some((*transfer, name.clone(), *size)),
        _ => None,
    });
    assert_eq!(name, "отчёт.bin");
    assert_eq!(size, payload.len() as u64);

    b.engine.respond_offer(transfer, true);
    let path = wait(&b, "transfer finished on B", |e| match e {
        EngineEvent::TransferFinished {
            transfer: t,
            incoming: true,
            path,
            error,
            ..
        } if *t == transfer => {
            assert!(error.is_none(), "transfer failed: {error:?}");
            Some(path.clone().expect("path"))
        }
        _ => None,
    });
    assert_eq!(path.parent().unwrap(), b.downloads);
    assert_eq!(std::fs::read(&path).unwrap(), payload);
}

#[test]
fn rejected_offer_leaves_nothing_behind() {
    let a = node("PC");
    let b = node("Phone");
    let (a_id, b_id) = pair(&a, &b);

    let src = a._dir.path().join("secret.bin");
    std::fs::write(&src, vec![1u8; 50_000]).unwrap();
    a.engine.send_file(b_id, src);

    let transfer = wait(&b, "offer on B", |e| match e {
        EngineEvent::OfferReceived { from, transfer, .. } if *from == a_id => Some(*transfer),
        _ => None,
    });
    b.engine.respond_offer(transfer, false);

    let err = wait(&a, "rejection on A", |e| match e {
        EngineEvent::TransferFinished {
            incoming: false,
            error,
            ..
        } => Some(error.clone()),
        _ => None,
    });
    assert!(err.is_some(), "sender must be told the offer was refused");
    assert!(!b.downloads.exists() || std::fs::read_dir(&b.downloads).unwrap().count() == 0);
}

#[test]
fn unpaired_peer_cannot_send_anything() {
    let a = node("PC");
    let b = node("Stranger");
    let a_id = a.engine.device_id();

    b.engine.dial(
        format!("127.0.0.1:{}", a.engine.port()).parse().unwrap(),
        None,
    );
    wait(&b, "pairing prompt", |e| match e {
        EngineEvent::PairingRequired { device, .. } if *device == a_id => Some(()),
        _ => None,
    });

    // The connection exists, but nothing may flow across it.
    b.engine.send_text(a_id, "should not arrive");
    let err = wait(&b, "refusal", |e| match e {
        EngineEvent::Error(m) => Some(m.clone()),
        _ => None,
    });
    assert!(err.contains("сопряжено"), "unexpected error: {err}");
    assert!(a.engine.trusted().is_empty());
}

#[test]
fn declining_pairing_closes_the_connection() {
    let a = node("PC");
    let b = node("Phone");
    let a_id = a.engine.device_id();
    let b_id = b.engine.device_id();

    b.engine.dial(
        format!("127.0.0.1:{}", a.engine.port()).parse().unwrap(),
        None,
    );
    wait(&a, "pairing prompt on A", |e| match e {
        EngineEvent::PairingRequired { device, .. } if *device == b_id => Some(()),
        _ => None,
    });
    a.engine.respond_pairing(b_id, false);

    wait(&b, "disconnect on B", |e| match e {
        EngineEvent::Disconnected { device, .. } if *device == a_id => Some(()),
        _ => None,
    });
    assert!(a.engine.trusted().is_empty());
    assert!(b.engine.trusted().is_empty());
}

#[test]
fn a_substituted_key_aborts_the_connection() {
    let a = node("PC");
    let b = node("Phone");

    // Simulates scanning a QR code for device A but reaching an impostor:
    // the key proved in the handshake is not the key we were promised.
    b.engine.dial(
        format!("127.0.0.1:{}", a.engine.port()).parse().unwrap(),
        Some(vec![0xAAu8; 32]),
    );

    let msg = wait(&b, "MITM warning", |e| match e {
        EngineEvent::Error(m) if m.contains("другой ключ") => Some(m.clone()),
        _ => None,
    });
    assert!(msg.contains("разорвано"));
    assert!(b.engine.trusted().is_empty());
    assert!(b.engine.connections().is_empty());
}

#[test]
fn forgetting_a_device_revokes_access() {
    let a = node("PC");
    let b = node("Phone");
    let (a_id, b_id) = pair(&a, &b);

    a.engine.forget(b_id);
    assert!(a.engine.trusted().is_empty());

    wait(&b, "disconnect after revocation", |e| match e {
        EngineEvent::Disconnected { device, .. } if *device == a_id => Some(()),
        _ => None,
    });

    // Reconnecting now requires a fresh pairing on A's side.
    b.engine.dial(
        format!("127.0.0.1:{}", a.engine.port()).parse().unwrap(),
        None,
    );
    wait(&a, "pairing prompt after revocation", |e| match e {
        EngineEvent::PairingRequired { device, .. } if *device == b_id => Some(()),
        _ => None,
    });
}

#[test]
fn unknown_transfer_ids_are_ignored() {
    let a = node("PC");
    let b = node("Phone");
    let (_a_id, b_id) = pair(&a, &b);
    // Responding to an id that was never offered must be a no-op, not a panic.
    a.engine.respond_offer(TransferId::random(), true);
    a.engine.cancel_transfer(TransferId::random());
    a.engine.send_text(b_id, "still alive");
    wait(&b, "text still flows", |e| match e {
        EngineEvent::TextReceived { text, .. } => {
            assert_eq!(text, "still alive");
            Some(())
        }
        _ => None,
    });
}
