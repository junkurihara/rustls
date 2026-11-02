//! Tests for the ECH split-mode backend role (RFC 9849 section 7.2).
//!
//! A minimal, test-only ECH client-facing server decrypts the client's
//! ClientHelloOuter and forwards the reconstructed ClientHelloInner to a rustls
//! server with `ServerConfig::ech_backend` enabled. All other records are
//! forwarded unchanged, as a split-mode client-facing server does.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use core::ops::Range;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use rustls::client::{EchConfig, EchMode, EchStatus};
use rustls::crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey};
use rustls::crypto::{CryptoProvider, SelectedCredential};
use rustls::enums::{ContentType, HandshakeType, ProtocolVersion};
use rustls::error::{Error, PeerMisbehaved};
use rustls::pki_types::EchConfigListBytes;
use rustls::quic::{self, Connection as _};
use rustls::server::{Acceptor, ClientHello, ServerCredentialResolver};
use rustls::{
    ClientConfig, ClientConnection, Connection as _, HandshakeKind, ServerConfig, ServerConnection,
};
use rustls_aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls_test::{
    ClientConfigExt, ErrorFromPeer, KeyType, ServerConfigExt, encoding, make_server_config,
    server_name, transfer,
};

use super::provider;

#[test]
fn split_backend_accepts_inner_client_hello() {
    let key = EchKey::generate(0x42);
    let seen_ech_inner = Arc::new(Mutex::new(Vec::new()));
    let mut backend_config = backend_config(provider::DEFAULT_TLS13_PROVIDER);
    backend_config.cert_resolver = Arc::new(RecordingResolver {
        inner: backend_config.cert_resolver.clone(),
        seen_ech_inner: seen_ech_inner.clone(),
        reject_ech_inner: false,
    });

    let mut client = connect(&key.client_config(provider::DEFAULT_TLS13_PROVIDER));
    let mut backend = ServerConnection::new(Arc::new(backend_config)).unwrap();
    let mut frontend = SplitModeFrontend::new(&key);
    do_split_handshake(&mut client, &mut frontend, &mut backend).unwrap();

    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert!(backend.ech_backend_accepted());
    // The backend did not decrypt ECH itself.
    assert!(backend.ech_accepted().is_none());
    // The backend sees the inner (real) server name, not the public name.
    assert_eq!(
        backend
            .server_name()
            .map(|name| name.as_ref()),
        Some("localhost")
    );
    assert_eq!(*seen_ech_inner.lock().unwrap(), [true]);
}

#[test]
fn split_backend_with_hello_retry_request() {
    let key = EchKey::generate(0x42);
    // The backend only supports P-384, while the client sends a key share for
    // its most preferred group, which forces a HelloRetryRequest.
    let backend_provider = CryptoProvider {
        kx_groups: Cow::Owned(vec![provider::kx_group::SECP384R1]),
        ..provider::DEFAULT_TLS13_PROVIDER.clone()
    };

    let mut client = connect(&key.client_config(provider::DEFAULT_TLS13_PROVIDER));
    let mut backend = ServerConnection::new(Arc::new(backend_config(backend_provider))).unwrap();
    let mut frontend = SplitModeFrontend::new(&key);
    do_split_handshake(&mut client, &mut frontend, &mut backend).unwrap();

    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert!(backend.ech_backend_accepted());
}

#[test]
fn split_backend_resumption() {
    let key = EchKey::generate(0x42);
    let client_config = key.client_config(provider::DEFAULT_TLS13_PROVIDER);
    let backend_config = Arc::new(backend_config(provider::DEFAULT_TLS13_PROVIDER));

    for expected_kind in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let mut client = connect(&client_config);
        let mut backend = ServerConnection::new(backend_config.clone()).unwrap();
        let mut frontend = SplitModeFrontend::new(&key);
        do_split_handshake(&mut client, &mut frontend, &mut backend).unwrap();

        assert_eq!(client.ech_status(), EchStatus::Accepted);
        assert_eq!(client.handshake_kind(), Some(expected_kind));
        assert!(backend.ech_backend_accepted());
    }
}

#[test]
fn split_backend_disabled_rejects_inner_client_hello() {
    let key = EchKey::generate(0x42);
    let mut backend_config = backend_config(provider::DEFAULT_TLS13_PROVIDER);
    backend_config.ech_backend = false;

    let mut client = connect(&key.client_config(provider::DEFAULT_TLS13_PROVIDER));
    let mut backend = ServerConnection::new(Arc::new(backend_config)).unwrap();
    let mut frontend = SplitModeFrontend::new(&key);

    assert_eq!(
        do_split_handshake(&mut client, &mut frontend, &mut backend),
        Err(ErrorFromPeer::Server(
            PeerMisbehaved::InvalidEchClientHelloInner.into()
        ))
    );
    assert!(!backend.ech_backend_accepted());
}

#[test]
fn split_backend_rejects_outer_client_hello_after_hello_retry_request() {
    let key = EchKey::generate(0x42);
    let backend_provider = CryptoProvider {
        kx_groups: Cow::Owned(vec![provider::kx_group::SECP384R1]),
        ..provider::DEFAULT_TLS13_PROVIDER.clone()
    };

    let mut client = connect(&key.client_config(provider::DEFAULT_TLS13_PROVIDER));
    let mut backend = ServerConnection::new(Arc::new(backend_config(backend_provider))).unwrap();
    let mut frontend = SplitModeFrontend::new(&key);
    frontend.forward_outer_on_retry = true;

    assert_eq!(
        do_split_handshake(&mut client, &mut frontend, &mut backend),
        Err(ErrorFromPeer::Server(
            PeerMisbehaved::InvalidEchClientHelloInner.into()
        ))
    );
}

#[test]
fn split_backend_cert_resolver_error_does_not_rewind() {
    let key = EchKey::generate(0x42);
    let seen_ech_inner = Arc::new(Mutex::new(Vec::new()));
    let mut backend_config = backend_config(provider::DEFAULT_TLS13_PROVIDER);
    backend_config.cert_resolver = Arc::new(RecordingResolver {
        inner: backend_config.cert_resolver.clone(),
        seen_ech_inner: seen_ech_inner.clone(),
        reject_ech_inner: true,
    });

    let mut client = connect(&key.client_config(provider::DEFAULT_TLS13_PROVIDER));
    let mut backend = ServerConnection::new(Arc::new(backend_config)).unwrap();
    let mut frontend = SplitModeFrontend::new(&key);

    // There is no outer ClientHello to fall back to, so the error is returned
    // after a single resolution attempt.
    assert_eq!(
        do_split_handshake(&mut client, &mut frontend, &mut backend),
        Err(ErrorFromPeer::Server(Error::NoSuitableCertificate))
    );
    assert_eq!(*seen_ech_inner.lock().unwrap(), [true]);
}

#[test]
fn split_backend_via_acceptor() {
    let key = EchKey::generate(0x42);
    let mut client = connect(&key.client_config(provider::DEFAULT_TLS13_PROVIDER));
    let mut frontend = SplitModeFrontend::new(&key);

    let mut acceptor = Acceptor::default();
    let records = frontend.take_records(&mut client);
    let mut rd = &records[..];
    while !rd.is_empty() {
        acceptor.read_tls(&mut rd).unwrap();
    }
    let accepted = acceptor.accept().unwrap().unwrap();
    assert!(accepted.client_hello().is_ech_inner());
    assert_eq!(
        accepted
            .client_hello()
            .server_name()
            .map(|name| name.as_ref()),
        Some("localhost")
    );

    let mut backend = accepted
        .into_connection(Arc::new(backend_config(provider::DEFAULT_TLS13_PROVIDER)))
        .unwrap();
    assert!(backend.ech_backend_accepted());

    // The client verifies the ECH confirmation in the ServerHello.
    //
    // The handshake is not driven to completion here: at this base, connections
    // created via the `Acceptor` do not drop the client's middlebox compatibility
    // ChangeCipherSpec, independently of ECH (fixed upstream by 5d1179cd,
    // "Preserve negotiated TLS version after server Acceptor").
    transfer(&mut backend, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.ech_status(), EchStatus::Accepted);
}

#[test]
fn split_backend_tls12_keeps_downgrade_sentinel() {
    let seen_ech_inner = Arc::new(Mutex::new(Vec::new()));
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    server_config.ech_backend = true;
    server_config.cert_resolver = Arc::new(RecordingResolver {
        inner: server_config.cert_resolver.clone(),
        seen_ech_inner: seen_ech_inner.clone(),
        reject_ech_inner: false,
    });
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    // An inner ClientHello without a supported_versions extension, so that
    // TLS 1.2 is negotiated.
    let client_hello = encoding::client_hello_with_extensions(vec![
        encoding::Extension::new_sig_algs(),
        encoding::Extension::new_kx_groups(),
        encoding::Extension {
            typ: EXTENDED_MAIN_SECRET_EXTENSION,
            body: Vec::new(),
        },
        encoding::Extension {
            typ: ECH_EXTENSION,
            body: vec![ECH_CLIENT_HELLO_TYPE_INNER],
        },
    ]);
    server
        .read_tls(
            &mut &encoding::message_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                client_hello,
            )[..],
        )
        .unwrap();
    server.process_new_packets().unwrap();

    let mut server_flight = Vec::new();
    server
        .write_tls(&mut server_flight)
        .unwrap();
    // record header (5) || handshake header (4) || legacy_version (2) || random (32)
    assert_eq!(server_flight[5], u8::from(HandshakeType::ServerHello));
    // RFC 9849 section 7.2: the ECH confirmation must not overwrite the TLS 1.3
    // downgrade signal (RFC 8446 section 4.1.3).
    assert_eq!(&server_flight[35..43], b"DOWNGRD\x01");
    assert!(!server.ech_backend_accepted());
    assert_eq!(*seen_ech_inner.lock().unwrap(), [false]);
}

#[test]
fn split_backend_over_quic() {
    let key = EchKey::generate(0x42);
    let mut client = quic::ClientConnection::new(
        key.client_config(provider::DEFAULT_TLS13_PROVIDER),
        quic::Version::V1,
        server_name("localhost"),
        b"client params".to_vec(),
    )
    .unwrap();
    let mut backend = quic::ServerConnection::new(
        Arc::new(backend_config(provider::DEFAULT_TLS13_PROVIDER)),
        quic::Version::V1,
        b"server params".to_vec(),
    )
    .unwrap();
    let mut frontend = SplitModeFrontend::new(&key);

    while client.is_handshaking() || backend.is_handshaking() {
        let mut to_backend = take_quic_handshake(&mut client);
        if to_backend.first() == Some(&u8::from(HandshakeType::ClientHello)) {
            to_backend = frontend.decrypt(&to_backend);
        }
        backend.read_hs(&to_backend).unwrap();
        client
            .read_hs(&take_quic_handshake(&mut backend))
            .unwrap();
    }

    assert!(backend.ech_backend_accepted());
    assert!(backend.ech_accepted().is_none());
}

fn backend_config(provider: CryptoProvider) -> ServerConfig {
    let mut config = ServerConfig::builder(Arc::new(provider)).finish(KeyType::EcdsaP256);
    config.ech_backend = true;
    config
}

fn connect(client_config: &Arc<ClientConfig>) -> ClientConnection {
    client_config
        .connect(server_name("localhost"))
        .build()
        .unwrap()
}

/// Run the handshake through `frontend` until it completes or a peer fails.
fn do_split_handshake(
    client: &mut ClientConnection,
    frontend: &mut SplitModeFrontend<'_>,
    backend: &mut ServerConnection,
) -> Result<(), ErrorFromPeer> {
    while client.is_handshaking() || backend.is_handshaking() {
        let records = frontend.take_records(client);
        let mut rd = &records[..];
        while !rd.is_empty() {
            backend.read_tls(&mut rd).unwrap();
        }
        backend
            .process_new_packets()
            .map_err(ErrorFromPeer::Server)?;

        transfer(backend, client);
        client
            .process_new_packets()
            .map_err(ErrorFromPeer::Client)?;
    }

    Ok(())
}

/// Take all pending handshake bytes from a QUIC connection, across key changes.
fn take_quic_handshake(conn: &mut impl quic::Connection) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let prev = buf.len();
        if conn.write_hs(&mut buf).is_none() && prev == buf.len() {
            return buf;
        }
    }
}

/// An ECH key pair together with its published ECHConfig.
struct EchKey {
    hpke: &'static dyn Hpke,
    /// A single wire-encoded ECHConfig.
    config: Vec<u8>,
    private_key: HpkePrivateKey,
}

impl EchKey {
    fn generate(config_id: u8) -> Self {
        let hpke = ALL_SUPPORTED_SUITES[0];
        let (public_key, private_key) = hpke.generate_key_pair().unwrap();
        let suite = hpke.suite();

        // ECHConfigContents (RFC 9849 section 4).
        let mut contents = vec![config_id];
        contents.extend_from_slice(&suite.kem.0.to_be_bytes());
        contents.extend_from_slice(&encoding::len_u16(public_key.0));
        contents.extend_from_slice(&encoding::len_u16(
            [
                suite.sym.kdf_id.0.to_be_bytes(),
                suite.sym.aead_id.0.to_be_bytes(),
            ]
            .concat(),
        ));
        contents.push(128); // maximum_name_length
        contents.extend_from_slice(&encoding::len_u8(b"public.example.com".to_vec()));
        contents.extend_from_slice(&encoding::len_u16(Vec::new())); // extensions

        let mut config = ECH_EXTENSION.to_be_bytes().to_vec(); // version
        config.extend_from_slice(&encoding::len_u16(contents));

        Self {
            hpke,
            config,
            private_key,
        }
    }

    fn client_config(&self, provider: CryptoProvider) -> Arc<ClientConfig> {
        let config_list = encoding::len_u16(self.config.clone());
        let ech_config =
            EchConfig::new(EchConfigListBytes::from(config_list), &[self.hpke]).unwrap();
        Arc::new(
            ClientConfig::builder(Arc::new(provider))
                .with_ech(EchMode::Enable(ech_config))
                .finish(KeyType::EcdsaP256),
        )
    }
}

/// A minimal ECH client-facing server in split mode.
///
/// Decrypts each ClientHelloOuter and forwards the reconstructed
/// ClientHelloInner, reusing the HPKE context for the ClientHello sent after a
/// HelloRetryRequest (RFC 9849 section 7.1.1).
struct SplitModeFrontend<'a> {
    key: &'a EchKey,
    opener: Option<Box<dyn HpkeOpener>>,
    /// Forward the ClientHello sent after a HelloRetryRequest without
    /// decrypting it, to model a misbehaving client-facing server.
    forward_outer_on_retry: bool,
}

impl<'a> SplitModeFrontend<'a> {
    fn new(key: &'a EchKey) -> Self {
        Self {
            key,
            opener: None,
            forward_outer_on_retry: false,
        }
    }

    /// Take all pending TLS records from `client`, replacing any
    /// ClientHelloOuter with the corresponding ClientHelloInner.
    fn take_records(&mut self, client: &mut ClientConnection) -> Vec<u8> {
        let mut data = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut data).unwrap();
        }

        let mut out = Vec::new();
        let mut rest = &data[..];
        while !rest.is_empty() {
            let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
            let (record, tail) = rest.split_at(5 + len);
            rest = tail;

            let payload = &record[5..];
            let is_client_hello = ContentType::from(record[0]) == ContentType::Handshake
                && payload[0] == u8::from(HandshakeType::ClientHello);
            let is_retry = self.opener.is_some();
            if !is_client_hello || (is_retry && self.forward_outer_on_retry) {
                out.extend_from_slice(record);
                continue;
            }

            let version = ProtocolVersion::from(u16::from_be_bytes([record[1], record[2]]));
            out.extend(encoding::message_framing(
                ContentType::Handshake,
                version,
                self.decrypt(payload),
            ));
        }
        out
    }

    /// Decrypt a handshake-framed ClientHelloOuter and return the
    /// handshake-framed ClientHelloInner (RFC 9849 sections 5 and 7.1).
    fn decrypt(&mut self, client_hello_outer: &[u8]) -> Vec<u8> {
        let body = &client_hello_outer[4..];
        let outer = RawHello::parse(body);
        let ech = outer.extension_range(ECH_EXTENSION);

        // ECHClientHello: type(1) || cipher_suite(4) || config_id(1) ||
        //                 enc<0..2^16-1> || payload<1..2^16-1>
        let ech_data = &body[ech.start + 4..ech.end];
        assert_eq!(ech_data[0], ECH_CLIENT_HELLO_TYPE_OUTER);
        assert_eq!(ech_data[5], self.key.config[4], "unexpected config_id");
        let enc_len = u16::from_be_bytes([ech_data[6], ech_data[7]]) as usize;
        let enc = &ech_data[8..8 + enc_len];
        let payload = &ech_data[8 + enc_len + 2..];

        // ClientHelloOuterAAD is the ClientHelloOuter with the payload zeroed.
        let mut aad = body.to_vec();
        aad[ech.end - payload.len()..ech.end].fill(0);

        // The ClientHello sent after a HelloRetryRequest has an empty enc and
        // reuses the HPKE context.
        assert_eq!(enc.is_empty(), self.opener.is_some());
        if self.opener.is_none() {
            let mut info = b"tls ech\0".to_vec();
            info.extend_from_slice(&self.key.config);
            self.opener = Some(
                self.key
                    .hpke
                    .setup_opener(
                        &EncapsulatedSecret(enc.to_vec()),
                        &info,
                        &self.key.private_key,
                    )
                    .unwrap(),
            );
        }
        let encoded_inner = self
            .opener
            .as_mut()
            .unwrap()
            .open(&aad, payload)
            .unwrap();

        reconstruct_client_hello_inner(&encoded_inner, &outer)
    }
}

/// Reconstruct the handshake-framed ClientHelloInner from the decrypted
/// EncodedClientHelloInner and the ClientHelloOuter (RFC 9849 section 5.1).
fn reconstruct_client_hello_inner(encoded_inner: &[u8], outer: &RawHello<'_>) -> Vec<u8> {
    let inner = RawHello::parse(encoded_inner);
    assert!(
        encoded_inner[inner.extensions_end..]
            .iter()
            .all(|&b| b == 0),
        "padding must be zero"
    );

    let mut extensions = Vec::new();
    for (typ, range) in &inner.extensions {
        let extension = &encoded_inner[range.clone()];
        if *typ != ECH_OUTER_EXTENSIONS {
            extensions.extend_from_slice(extension);
            continue;
        }

        // OuterExtensions: ExtensionType<2..254>, referencing outer extensions.
        for referenced in extension[5..].chunks(2) {
            let range = outer.extension_range(u16::from_be_bytes([referenced[0], referenced[1]]));
            extensions.extend_from_slice(&outer.body[range]);
        }
    }

    let mut body = inner.body[..inner.session_id.start].to_vec();
    // The legacy_session_id is taken from the ClientHelloOuter.
    body.extend_from_slice(&outer.body[outer.session_id.clone()]);
    body.extend_from_slice(&inner.body[inner.session_id.end..inner.extensions_start]);
    body.extend_from_slice(&encoding::len_u16(extensions));
    encoding::handshake_framing(HandshakeType::ClientHello, body)
}

/// Byte ranges of the parts of a ClientHello body needed for ECH processing.
struct RawHello<'a> {
    body: &'a [u8],
    /// The length-prefixed legacy_session_id.
    session_id: Range<usize>,
    /// Start of the length-prefixed extensions block.
    extensions_start: usize,
    /// End of the extensions block (any following bytes are padding).
    extensions_end: usize,
    /// Each extension's type and byte range, including its header.
    extensions: Vec<(u16, Range<usize>)>,
}

impl<'a> RawHello<'a> {
    fn parse(body: &'a [u8]) -> Self {
        let u16_at = |pos: usize| u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;

        // legacy_version (2) || random (32)
        let mut pos = 34;
        let session_id = pos..pos + 1 + body[pos] as usize;
        pos = session_id.end;
        pos += 2 + u16_at(pos); // cipher_suites
        pos += 1 + body[pos] as usize; // legacy_compression_methods

        let extensions_start = pos;
        let extensions_end = pos + 2 + u16_at(pos);
        pos += 2;
        let mut extensions = Vec::new();
        while pos < extensions_end {
            let end = pos + 4 + u16_at(pos + 2);
            extensions.push((u16_at(pos) as u16, pos..end));
            pos = end;
        }

        Self {
            body,
            session_id,
            extensions_start,
            extensions_end,
            extensions,
        }
    }

    fn extension_range(&self, typ: u16) -> Range<usize> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, range)| range.clone())
            .unwrap_or_else(|| panic!("missing extension {typ:#06x}"))
    }
}

/// Records whether each resolved `ClientHello` is an ECH inner hello.
#[derive(Debug)]
struct RecordingResolver {
    inner: Arc<dyn ServerCredentialResolver>,
    seen_ech_inner: Arc<Mutex<Vec<bool>>>,
    reject_ech_inner: bool,
}

impl ServerCredentialResolver for RecordingResolver {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        self.seen_ech_inner
            .lock()
            .unwrap()
            .push(client_hello.is_ech_inner());
        if self.reject_ech_inner && client_hello.is_ech_inner() {
            return Err(Error::NoSuitableCertificate);
        }
        self.inner.resolve(client_hello)
    }
}

const ECH_EXTENSION: u16 = 0xfe0d;
const ECH_OUTER_EXTENSIONS: u16 = 0xfd00;
const EXTENDED_MAIN_SECRET_EXTENSION: u16 = 0x0017;
const ECH_CLIENT_HELLO_TYPE_OUTER: u8 = 0;
const ECH_CLIENT_HELLO_TYPE_INNER: u8 = 1;
