//! Interop harness, dialling side. See `interop_responder.rs`.
//!
//! ```text
//! cargo run --example interop_initiator -- 127.0.0.1:45999
//! ```

use std::net::TcpStream;

use syncmob::net::session::handshake_initiator;
use syncmob::proto::{Message, TextMsg, TransferId};
use syncmob::security::{fingerprint, sas_code, Identity};

fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:45999".into());

    let identity = Identity::generate()?;
    println!("LOCAL_PK={}", hex::encode(identity.public_key()));
    println!("LOCAL_FINGERPRINT={}", fingerprint(identity.public_key()));

    let socket = TcpStream::connect(&addr)?;
    let hs = handshake_initiator(socket, &identity)?;
    println!("REMOTE_PK={}", hex::encode(&hs.remote_static));
    println!("HANDSHAKE_HASH={}", hex::encode(&hs.handshake_hash));
    println!("SAS={}", sas_code(&hs.handshake_hash));

    let (mut reader, sender) = hs.channel.split();
    sender.send(&Message::Text(TextMsg {
        id: TransferId::random(),
        ts: 0,
        text: "привет из Rust".into(),
    }))?;
    match reader.recv() {
        Ok(Message::Text(t)) => println!("ECHO={}", t.text),
        Ok(other) => println!("GOT_OTHER={:02x}", other.type_byte()),
        Err(e) => println!("RECV_ERROR={e}"),
    }
    Ok(())
}
