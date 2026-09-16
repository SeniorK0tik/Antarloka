//! A from-scratch Noise_XX_25519_ChaChaPoly_BLAKE2s implementation, checked
//! against `snow` over a real socket.
//!
//! Why this exists: the Android module cannot use `snow`, so its handshake is
//! hand written from the Noise specification. This file is that same algorithm,
//! step for step, expressed in Rust — the Kotlin in
//! `mobile/app/src/main/java/org/syncmob/mobile/crypto/Noise.kt` is a literal
//! translation of it. If this interoperates with `snow`, the translation has a
//! verified reference; if a step were wrong, these tests would fail here rather
//! than silently on a phone.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

const PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"SyncMob/1";

// ---- primitives ---------------------------------------------------------

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s-256, written out by hand (RFC 2104).
///
/// Spelled out rather than pulled from a crate so that the Kotlin side can be a
/// line-by-line translation with no library-behaviour differences to reason
/// about. BLAKE2s has a 64 byte block.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&hash(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = hash(&[&ipad, data]);
    hash(&[&opad, &inner])
}

/// HKDF as Noise defines it: two outputs, chained HMACs.
fn hkdf2(ck: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(ck, ikm);
    let o1 = hmac(&temp, &[1u8]);
    let mut second = o1.to_vec();
    second.push(2u8);
    let o2 = hmac(&temp, &second);
    (o1, o2)
}

fn dh(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*private);
    s.diffie_hellman(&PublicKey::from(*public)).to_bytes()
}

// ---- CipherState --------------------------------------------------------

struct CipherState {
    k: Option<[u8; 32]>,
    n: u64,
}

impl CipherState {
    fn new() -> Self {
        Self { k: None, n: 0 }
    }
    fn initialize_key(&mut self, key: Option<[u8; 32]>) {
        self.k = key;
        self.n = 0;
    }
    /// 96-bit nonce: 32 zero bits, then the counter little-endian.
    fn nonce(&self) -> Nonce {
        let mut b = [0u8; 12];
        b[4..].copy_from_slice(&self.n.to_le_bytes());
        *Nonce::from_slice(&b)
    }
    fn encrypt_with_ad(&mut self, ad: &[u8], pt: &[u8]) -> Vec<u8> {
        let Some(k) = self.k else {
            return pt.to_vec();
        };
        let c = ChaCha20Poly1305::new(Key::from_slice(&k));
        let ct = c
            .encrypt(&self.nonce(), Payload { msg: pt, aad: ad })
            .expect("encrypt");
        self.n += 1;
        ct
    }
    fn decrypt_with_ad(&mut self, ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        let Some(k) = self.k else {
            return Ok(ct.to_vec());
        };
        let c = ChaCha20Poly1305::new(Key::from_slice(&k));
        let pt = c
            .decrypt(&self.nonce(), Payload { msg: ct, aad: ad })
            .map_err(|_| "decryption failed".to_string())?;
        self.n += 1;
        Ok(pt)
    }
}

// ---- SymmetricState -----------------------------------------------------

struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn new(protocol_name: &str) -> Self {
        let name = protocol_name.as_bytes();
        // The name is 33 bytes, i.e. longer than HASHLEN, so it is hashed.
        let h: [u8; 32] = if name.len() <= 32 {
            let mut p = [0u8; 32];
            p[..name.len()].copy_from_slice(name);
            p
        } else {
            hash(&[name])
        };
        Self {
            h,
            ck: h,
            cipher: CipherState::new(),
        }
    }
    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }
    fn mix_key(&mut self, input: &[u8]) {
        let (ck, temp_k) = hkdf2(&self.ck, input);
        self.ck = ck;
        self.cipher.initialize_key(Some(temp_k));
    }
    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Vec<u8> {
        let ct = self.cipher.encrypt_with_ad(&self.h, pt);
        self.mix_hash(&ct);
        ct
    }
    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, String> {
        let pt = self.cipher.decrypt_with_ad(&self.h, ct)?;
        self.mix_hash(ct);
        Ok(pt)
    }
    fn split(&self) -> (CipherState, CipherState) {
        let (t1, t2) = hkdf2(&self.ck, &[]);
        let mut c1 = CipherState::new();
        c1.initialize_key(Some(t1));
        let mut c2 = CipherState::new();
        c2.initialize_key(Some(t2));
        (c1, c2)
    }
}

// ---- HandshakeState (XX only) ------------------------------------------

struct NoiseXX {
    initiator: bool,
    sym: SymmetricState,
    s_priv: [u8; 32],
    s_pub: [u8; 32],
    e_priv: Option<[u8; 32]>,
    e_pub: Option<[u8; 32]>,
    re: Option<[u8; 32]>,
    rs: Option<[u8; 32]>,
    step: usize,
}

struct Transport {
    send: CipherState,
    recv: CipherState,
}

impl NoiseXX {
    fn new(initiator: bool, s_priv: [u8; 32], s_pub: [u8; 32]) -> Self {
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(PROLOGUE);
        Self {
            initiator,
            sym,
            s_priv,
            s_pub,
            e_priv: None,
            e_pub: None,
            re: None,
            rs: None,
            step: 0,
        }
    }

    fn gen_ephemeral(&mut self) {
        // Deterministic-free: a fresh random scalar each handshake.
        let secret = random_secret();
        let pubk = PublicKey::from(&secret);
        self.e_priv = Some(secret.to_bytes());
        self.e_pub = Some(pubk.to_bytes());
    }

    fn write_message(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.initiator && self.step == 0 {
            // -> e
            self.gen_ephemeral();
            let e_pub = self.e_pub.unwrap();
            self.sym.mix_hash(&e_pub);
            out.extend_from_slice(&e_pub);
            out.extend_from_slice(&self.sym.encrypt_and_hash(payload));
        } else if !self.initiator && self.step == 1 {
            // <- e, ee, s, es
            self.gen_ephemeral();
            let e_pub = self.e_pub.unwrap();
            self.sym.mix_hash(&e_pub);
            out.extend_from_slice(&e_pub);
            let ee = dh(&self.e_priv.unwrap(), &self.re.unwrap());
            self.sym.mix_key(&ee);
            let s_pub = self.s_pub;
            out.extend_from_slice(&self.sym.encrypt_and_hash(&s_pub));
            // responder's `es` is DH(s, re)
            let es = dh(&self.s_priv, &self.re.unwrap());
            self.sym.mix_key(&es);
            out.extend_from_slice(&self.sym.encrypt_and_hash(payload));
        } else if self.initiator && self.step == 2 {
            // -> s, se
            let s_pub = self.s_pub;
            out.extend_from_slice(&self.sym.encrypt_and_hash(&s_pub));
            // initiator's `se` is DH(s, re)
            let se = dh(&self.s_priv, &self.re.unwrap());
            self.sym.mix_key(&se);
            out.extend_from_slice(&self.sym.encrypt_and_hash(payload));
        } else {
            panic!("write_message called out of order (step {})", self.step);
        }
        self.step += 1;
        out
    }

    fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, String> {
        // Late-initialised on purpose: each branch below is a line-for-line
        // mirror of the Kotlin implementation, and folding them into one
        // `let payload = if ...` expression would obscure that correspondence.
        #[allow(clippy::needless_late_init)]
        let payload;
        if !self.initiator && self.step == 0 {
            // -> e
            if msg.len() < 32 {
                return Err("short message 1".into());
            }
            let mut re = [0u8; 32];
            re.copy_from_slice(&msg[..32]);
            self.sym.mix_hash(&re);
            self.re = Some(re);
            payload = self.sym.decrypt_and_hash(&msg[32..])?;
        } else if self.initiator && self.step == 1 {
            // <- e, ee, s, es
            if msg.len() < 32 + 48 {
                return Err("short message 2".into());
            }
            let mut re = [0u8; 32];
            re.copy_from_slice(&msg[..32]);
            self.sym.mix_hash(&re);
            self.re = Some(re);
            let ee = dh(&self.e_priv.unwrap(), &re);
            self.sym.mix_key(&ee);
            let rs_bytes = self.sym.decrypt_and_hash(&msg[32..80])?;
            let mut rs = [0u8; 32];
            rs.copy_from_slice(&rs_bytes);
            self.rs = Some(rs);
            // initiator's `es` is DH(e, rs)
            let es = dh(&self.e_priv.unwrap(), &rs);
            self.sym.mix_key(&es);
            payload = self.sym.decrypt_and_hash(&msg[80..])?;
        } else if !self.initiator && self.step == 2 {
            // -> s, se
            if msg.len() < 48 {
                return Err("short message 3".into());
            }
            let rs_bytes = self.sym.decrypt_and_hash(&msg[..48])?;
            let mut rs = [0u8; 32];
            rs.copy_from_slice(&rs_bytes);
            self.rs = Some(rs);
            // responder's `se` is DH(e, rs)
            let se = dh(&self.e_priv.unwrap(), &rs);
            self.sym.mix_key(&se);
            payload = self.sym.decrypt_and_hash(&msg[48..])?;
        } else {
            return Err(format!(
                "read_message called out of order (step {})",
                self.step
            ));
        }
        self.step += 1;
        Ok(payload)
    }

    fn handshake_hash(&self) -> [u8; 32] {
        self.sym.h
    }

    fn split(&self) -> Transport {
        let (c1, c2) = self.sym.split();
        if self.initiator {
            Transport { send: c1, recv: c2 }
        } else {
            Transport { send: c2, recv: c1 }
        }
    }
}

/// Fresh X25519 secret from the OS CSPRNG.
fn random_secret() -> StaticSecret {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    StaticSecret::from(b)
}

// ---- framing shared with the real implementation ------------------------

fn write_frame(s: &mut TcpStream, data: &[u8]) {
    s.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
    s.write_all(data).unwrap();
    s.flush().unwrap();
}

fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let n = u32::from_be_bytes(len) as usize;
    assert!(n <= 65535, "frame too large");
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).unwrap();
    buf
}

// ---- tests --------------------------------------------------------------

/// The reference implementation talks to itself: sanity check before we point
/// it at `snow`.
#[test]
fn reference_talks_to_itself() {
    let a_priv = random_secret();
    let a_pub = PublicKey::from(&a_priv);
    let b_priv = random_secret();
    let b_pub = PublicKey::from(&b_priv);

    let mut i = NoiseXX::new(true, a_priv.to_bytes(), a_pub.to_bytes());
    let mut r = NoiseXX::new(false, b_priv.to_bytes(), b_pub.to_bytes());

    let m1 = i.write_message(&[]);
    assert_eq!(m1.len(), 32, "message 1 is a bare ephemeral key");
    r.read_message(&m1).unwrap();

    let m2 = r.write_message(&[]);
    assert_eq!(m2.len(), 96, "message 2 is e + encrypted s + tag");
    i.read_message(&m2).unwrap();

    let m3 = i.write_message(&[]);
    assert_eq!(m3.len(), 64, "message 3 is encrypted s + tag");
    r.read_message(&m3).unwrap();

    assert_eq!(i.handshake_hash(), r.handshake_hash());
    assert_eq!(i.rs.unwrap(), b_pub.to_bytes());
    assert_eq!(r.rs.unwrap(), a_pub.to_bytes());

    let mut it = i.split();
    let mut rt = r.split();
    let ct = it.send.encrypt_with_ad(&[], b"ping");
    assert_eq!(rt.recv.decrypt_with_ad(&[], &ct).unwrap(), b"ping");
    let ct = rt.send.encrypt_with_ad(&[], b"pong");
    assert_eq!(it.recv.decrypt_with_ad(&[], &ct).unwrap(), b"pong");
}

/// The reference implementation as the *initiator* against `snow` as responder.
#[test]
fn reference_initiator_interoperates_with_snow() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_identity = syncmob::security::Identity::generate().unwrap();
    let server_pub = server_identity.public_key().to_vec();

    let t = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let hs = syncmob::net::session::handshake_responder(sock, &server_identity).unwrap();
        let hash = hs.handshake_hash.clone();
        let rs = hs.remote_static.clone();
        let (mut reader, sender) = hs.channel.split();
        let msg = reader.recv().unwrap();
        sender.send(&syncmob::proto::Message::Pong).unwrap();
        (hash, rs, format!("{msg:?}"))
    });

    let priv_bytes = random_secret();
    let pub_bytes = PublicKey::from(&priv_bytes);
    let mut i = NoiseXX::new(true, priv_bytes.to_bytes(), pub_bytes.to_bytes());

    let mut sock = TcpStream::connect(addr).unwrap();
    write_frame(&mut sock, &i.write_message(&[]));
    let m2 = read_frame(&mut sock);
    i.read_message(&m2).unwrap();
    write_frame(&mut sock, &i.write_message(&[]));

    let mut transport = i.split();

    // Speak the real application protocol across the hand-rolled transport.
    let ping = syncmob::proto::Message::Ping.encode().unwrap();
    write_frame(&mut sock, &transport.send.encrypt_with_ad(&[], &ping));
    let reply = read_frame(&mut sock);
    let pt = transport.recv.decrypt_with_ad(&[], &reply).unwrap();
    assert!(matches!(
        syncmob::proto::Message::decode(&pt).unwrap(),
        syncmob::proto::Message::Pong
    ));

    let (snow_hash, snow_saw_rs, snow_saw_msg) = t.join().unwrap();
    assert_eq!(
        i.handshake_hash().to_vec(),
        snow_hash,
        "handshake hashes must match, otherwise the pairing codes differ"
    );
    assert_eq!(i.rs.unwrap().to_vec(), server_pub);
    assert_eq!(snow_saw_rs, pub_bytes.to_bytes().to_vec());
    assert!(snow_saw_msg.contains("Ping"));
}

/// The reference implementation as the *responder* against `snow` as initiator.
#[test]
fn reference_responder_interoperates_with_snow() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let priv_bytes = random_secret();
    let pub_bytes = PublicKey::from(&priv_bytes);
    let our_pub = pub_bytes.to_bytes();

    let client_identity = syncmob::security::Identity::generate().unwrap();
    let client_pub = client_identity.public_key().to_vec();
    let t = std::thread::spawn(move || {
        let sock = TcpStream::connect(addr).unwrap();
        let hs = syncmob::net::session::handshake_initiator(sock, &client_identity).unwrap();
        let hash = hs.handshake_hash.clone();
        let rs = hs.remote_static.clone();
        let (mut reader, sender) = hs.channel.split();
        sender.send(&syncmob::proto::Message::Ping).unwrap();
        let reply = reader.recv().unwrap();
        (hash, rs, format!("{reply:?}"))
    });

    let (mut sock, _) = listener.accept().unwrap();
    let mut r = NoiseXX::new(false, priv_bytes.to_bytes(), our_pub);
    let m1 = read_frame(&mut sock);
    r.read_message(&m1).unwrap();
    write_frame(&mut sock, &r.write_message(&[]));
    let m3 = read_frame(&mut sock);
    r.read_message(&m3).unwrap();

    let mut transport = r.split();
    let ct = read_frame(&mut sock);
    let pt = transport.recv.decrypt_with_ad(&[], &ct).unwrap();
    assert!(matches!(
        syncmob::proto::Message::decode(&pt).unwrap(),
        syncmob::proto::Message::Ping
    ));
    let pong = syncmob::proto::Message::Pong.encode().unwrap();
    write_frame(&mut sock, &transport.send.encrypt_with_ad(&[], &pong));

    let (snow_hash, snow_saw_rs, snow_saw_msg) = t.join().unwrap();
    assert_eq!(r.handshake_hash().to_vec(), snow_hash);
    assert_eq!(r.rs.unwrap().to_vec(), client_pub);
    assert_eq!(snow_saw_rs, our_pub.to_vec());
    assert!(snow_saw_msg.contains("Pong"));
}

/// The pairing code the two sides show must be identical, and it must come out
/// the same whichever implementation computed the handshake hash.
#[test]
fn pairing_code_matches_across_implementations() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_identity = syncmob::security::Identity::generate().unwrap();
    let t = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let hs = syncmob::net::session::handshake_responder(sock, &server_identity).unwrap();
        syncmob::security::sas_code(&hs.handshake_hash)
    });

    let priv_bytes = random_secret();
    let pub_bytes = PublicKey::from(&priv_bytes);
    let mut i = NoiseXX::new(true, priv_bytes.to_bytes(), pub_bytes.to_bytes());
    let mut sock = TcpStream::connect(addr).unwrap();
    write_frame(&mut sock, &i.write_message(&[]));
    let m2 = read_frame(&mut sock);
    i.read_message(&m2).unwrap();
    write_frame(&mut sock, &i.write_message(&[]));

    assert_eq!(
        syncmob::security::sas_code(&i.handshake_hash()),
        t.join().unwrap()
    );
}
/// Regenerate the constants pinned in
/// `mobile/app/src/test/java/org/syncmob/mobile/CrossImplementationVectorsTest.kt`.
///
/// Ignored by default; run with
/// `cargo test --test noise_reference --no-default-features print_vectors -- --ignored --nocapture`.
#[test]
#[ignore = "prints vectors for the Android test suite"]
fn print_vectors() {
    use blake2::{Blake2s256, Digest};
    fn hash(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Blake2s256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK: usize = 64;
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            k[..32].copy_from_slice(&hash(&[key]));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let inner = hash(&[&ipad, data]);
        hash(&[&opad, &inner])
    }
    fn hkdf2(ck: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
        let temp = hmac(ck, ikm);
        let o1 = hmac(&temp, &[1u8]);
        let mut second = o1.to_vec();
        second.push(2u8);
        (o1, hmac(&temp, &second))
    }
    let pk7 = [7u8; 32];
    println!("BLAKE2S_EMPTY={}", hex::encode(hash(&[b""])));
    println!("BLAKE2S_ABC={}", hex::encode(hash(&[b"abc"])));
    println!("DEVICE_ID_PK7={}", syncmob::security::device_id(&pk7));
    println!("FINGERPRINT_PK7={}", syncmob::security::fingerprint(&pk7));
    println!("SAS_HH11={}", syncmob::security::sas_code(&[0x11u8; 32]));
    println!("HMAC_K1_D2={}", hex::encode(hmac(&[1u8; 32], &[2u8; 16])));
    println!("HKDF_O1={}", hex::encode(hkdf2(&[3u8; 32], &[4u8; 32]).0));
    println!("HKDF_O2={}", hex::encode(hkdf2(&[3u8; 32], &[4u8; 32]).1));
    println!(
        "PROTOCOL_H0={}",
        hex::encode(hash(&[b"Noise_XX_25519_ChaChaPoly_BLAKE2s"]))
    );

    // X25519 with fixed scalars.
    use x25519_dalek::{PublicKey, StaticSecret};
    let a = StaticSecret::from([5u8; 32]);
    let b = StaticSecret::from([6u8; 32]);
    println!(
        "X25519_PUB_A={}",
        hex::encode(PublicKey::from(&a).to_bytes())
    );
    println!(
        "X25519_PUB_B={}",
        hex::encode(PublicKey::from(&b).to_bytes())
    );
    println!(
        "X25519_SHARED={}",
        hex::encode(a.diffie_hellman(&PublicKey::from(&b)).to_bytes())
    );
}
