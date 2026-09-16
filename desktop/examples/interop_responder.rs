//! Interop harness: run a bare SyncMob responder and print what it negotiated.
//!
//! Used to check a non-Rust client (the Android module, or a future port)
//! against the reference implementation without installing either app:
//!
//! ```text
//! cargo run --example interop_responder -- 45999
//! ```
//!
//! It accepts one connection, completes the Noise XX handshake, prints the
//! peer's static key, the handshake hash and the pairing code, then echoes one
//! text message back. Two implementations agree when the printed handshake hash
//! and pairing code match on both sides.

use std::net::TcpListener;

use syncmob::net::session::handshake_responder;
use syncmob::proto::{Message, TextMsg, TransferId};
use syncmob::security::{fingerprint, sas_code, Identity};

fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "45999".into())
        .parse()?;

    let identity = Identity::generate()?;
    println!("LOCAL_PK={}", hex::encode(identity.public_key()));
    println!("LOCAL_FINGERPRINT={}", fingerprint(identity.public_key()));

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("LISTENING={}", listener.local_addr()?);

    let (socket, peer) = listener.accept()?;
    println!("PEER={peer}");

    let hs = handshake_responder(socket, &identity)?;
    println!("REMOTE_PK={}", hex::encode(&hs.remote_static));
    println!("REMOTE_FINGERPRINT={}", fingerprint(&hs.remote_static));
    println!("HANDSHAKE_HASH={}", hex::encode(&hs.handshake_hash));
    println!("SAS={}", sas_code(&hs.handshake_hash));

    let (mut reader, sender) = hs.channel.split();
    for _ in 0..8 {
        match reader.recv() {
            Ok(Message::Text(t)) => {
                println!("GOT_TEXT={}", t.text);
                sender.send(&Message::Text(TextMsg {
                    id: TransferId::random(),
                    ts: 0,
                    text: format!("echo:{}", t.text),
                }))?;
                println!("SENT_ECHO=1");
                break;
            }
            Ok(Message::Ping) => {
                println!("GOT_PING=1");
                sender.send(&Message::Pong)?;
            }
            Ok(other) => println!("GOT_OTHER={:?}", other.type_byte()),
            Err(e) => {
                println!("RECV_ERROR={e}");
                break;
            }
        }
    }
    Ok(())
}
