use tls_server_fixture::SERVER_DOMAIN;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::CA_CERT_DER;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, warn};

mod utils;
use utils::{finish_prover, run_prover_mpc, run_prover_proxy, run_verifier};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_mpc() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    // Maximum number of bytes that can be sent from prover to server
    const MAX_SENT_DATA: usize = 1 << 12;
    // Maximum number of application records sent from prover to server
    const MAX_SENT_RECORDS: usize = 4;
    // Maximum number of bytes that can be received by prover from server
    const MAX_RECV_DATA: usize = 1 << 14;
    // Maximum number of application records received by prover from server
    const MAX_RECV_RECORDS: usize = 6;

    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_mpc(config, prover, Some(client_socket)).await;
        finish_prover(prover).await
    };

    let ((_full_transcript, _prover_output), verifier_output) =
        tokio::join!(prover_fut, run_verifier(verifier, None));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();
    let partial_transcript = verifier_output.transcript.unwrap();
    let ServerName::Dns(server_name) = verifier_output.server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
        0..10
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    let config = ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_proxy(config, prover).await;
        finish_prover(prover).await
    };

    let ((_full_transcript, _prover_output), verifier_output) =
        tokio::join!(prover_fut, run_verifier(verifier, Some(client_socket)));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();
    let partial_transcript = verifier_output.transcript.unwrap();
    let ServerName::Dns(server_name) = verifier_output.server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
        0..10
    );
}

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, NewAead, Payload, generic_array::GenericArray},
};
use tlsn::transcript::{ContentType, Record};

/// AES-128-GCM decrypt of a single TLS 1.2 application data record using the
/// prover's locally-read key + IV. Reconstructs the GCM nonce
/// (`implicit_iv || explicit_nonce`, 12 bytes) and the TLS 1.2 AEAD AAD
/// (`seq || type || version || cipher_len`, 13 bytes) per RFC 5246/5288, then
/// verifies the resulting plaintext matches the transcript's authoritative
/// plaintext. `records` is either `transcript.recv()` (for server_write_key)
/// or `transcript.sent()` (for client_write_key).
fn decrypt_first_app_record_from(key: [u8; 16], iv: [u8; 4], records: &[Record]) -> Vec<u8> {
    let record: &Record = records
        .iter()
        .find(|r| r.typ == ContentType::ApplicationData)
        .expect("transcript should contain at least one application-data record");

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&iv);
    nonce[4..].copy_from_slice(&record.explicit_nonce);

    let tag = record
        .tag
        .as_ref()
        .expect("application data record should carry a 16-byte GCM tag");

    let mut payload = record.ciphertext.clone();
    payload.extend_from_slice(tag);

    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&record.seq.to_be_bytes());
    aad.push(0x17); // ContentType::ApplicationData
    aad.push(0x03); // TLS 1.2 major
    aad.push(0x03); // TLS 1.2 minor
    aad.extend_from_slice(&(record.ciphertext.len() as u16).to_be_bytes());

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    cipher
        .decrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .expect("AES-128-GCM decrypt must succeed with the prover's local key + IV")
}

/// Verifies that in MPC mode the prover can use the locally-read key + IV to
/// AES-GCM-decrypt the first received application data record back to the
/// same plaintext that the transcript authoritatively committed to. The
/// verifier never participates in this read so it learns nothing extra.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_mpc_session_keys_exposed() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    const MAX_SENT_DATA: usize = 1 << 12;
    const MAX_SENT_RECORDS: usize = 4;
    const MAX_RECV_DATA: usize = 1 << 14;
    const MAX_RECV_RECORDS: usize = 6;

    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_mpc(config, prover, Some(client_socket)).await;
        let server_key = prover
            .server_write_key()
            .expect("server_write_key must be available after transcript commit");
        let server_iv = prover
            .server_write_iv()
            .expect("server_write_iv must be available after transcript commit");
        let client_key = prover
            .client_write_key()
            .expect("client_write_key must be available after transcript commit");
        let client_iv = prover
            .client_write_iv()
            .expect("client_write_iv must be available after transcript commit");
        let tls_transcript = prover.tls_transcript().clone();
        finish_prover(prover).await;
        (server_key, server_iv, client_key, client_iv, tls_transcript)
    };

    let ((server_key, server_iv, client_key, client_iv, tls_transcript), _verifier_output) =
        tokio::join!(prover_fut, run_verifier(verifier, None));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();

    assert_ne!(
        server_key, [0u8; 16],
        "MPC: server_write_key must be a real session key, not zeros"
    );
    assert_ne!(
        server_iv, [0u8; 4],
        "MPC: server_write_iv must be a real implicit nonce, not zeros"
    );
    assert_ne!(
        client_key, [0u8; 16],
        "MPC: client_write_key must be a real session key, not zeros"
    );
    assert_ne!(
        client_iv, [0u8; 4],
        "MPC: client_write_iv must be a real implicit nonce, not zeros"
    );
    assert_ne!(
        server_key, client_key,
        "MPC: client and server write keys must differ"
    );

    // Server side: decrypt first recv record with server_write_key.
    let recv_plaintext =
        decrypt_first_app_record_from(server_key, server_iv, tls_transcript.recv());
    let expected_recv = tls_transcript
        .recv()
        .iter()
        .find(|r| r.typ == ContentType::ApplicationData)
        .and_then(|r| r.plaintext.as_ref())
        .expect("first recv application data record must carry committed plaintext");
    assert_eq!(
        &recv_plaintext, expected_recv,
        "MPC: AES-GCM decrypt with server_write_key must match recv plaintext"
    );

    // Client side: decrypt first sent record with client_write_key.
    let sent_plaintext =
        decrypt_first_app_record_from(client_key, client_iv, tls_transcript.sent());
    let expected_sent = tls_transcript
        .sent()
        .iter()
        .find(|r| r.typ == ContentType::ApplicationData)
        .and_then(|r| r.plaintext.as_ref())
        .expect("first sent application data record must carry committed plaintext");
    assert_eq!(
        &sent_plaintext, expected_sent,
        "MPC: AES-GCM decrypt with client_write_key must match sent plaintext"
    );
}

/// Verifies that in proxy mode the prover can use the locally-read key + IV
/// to AES-GCM-decrypt the first received application data record back to the
/// same plaintext as the transcript. The notary (verifier) never sees the
/// key — proxy mode's "notary cannot decrypt" property is preserved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy_session_keys_exposed() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    let config = ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_proxy(config, prover).await;
        let server_key = prover
            .server_write_key()
            .expect("server_write_key must be available after transcript commit");
        let server_iv = prover
            .server_write_iv()
            .expect("server_write_iv must be available after transcript commit");
        let client_key = prover
            .client_write_key()
            .expect("client_write_key must be available after transcript commit");
        let client_iv = prover
            .client_write_iv()
            .expect("client_write_iv must be available after transcript commit");
        let tls_transcript = prover.tls_transcript().clone();
        finish_prover(prover).await;
        (server_key, server_iv, client_key, client_iv, tls_transcript)
    };

    let ((server_key, server_iv, client_key, client_iv, tls_transcript), _verifier_output) =
        tokio::join!(prover_fut, run_verifier(verifier, Some(client_socket)));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();

    assert_ne!(
        server_key, [0u8; 16],
        "Proxy: server_write_key must be a real session key, not zeros"
    );
    assert_ne!(
        server_iv, [0u8; 4],
        "Proxy: server_write_iv must be a real implicit nonce, not zeros"
    );
    assert_ne!(
        client_key, [0u8; 16],
        "Proxy: client_write_key must be a real session key, not zeros"
    );
    assert_ne!(
        client_iv, [0u8; 4],
        "Proxy: client_write_iv must be a real implicit nonce, not zeros"
    );
    assert_ne!(
        server_key, client_key,
        "Proxy: client and server write keys must differ"
    );

    let recv_plaintext =
        decrypt_first_app_record_from(server_key, server_iv, tls_transcript.recv());
    let expected_recv = tls_transcript
        .recv()
        .iter()
        .find(|r| r.typ == ContentType::ApplicationData)
        .and_then(|r| r.plaintext.as_ref())
        .expect("first recv application data record must carry committed plaintext");
    assert_eq!(
        &recv_plaintext, expected_recv,
        "Proxy: AES-GCM decrypt with server_write_key must match recv plaintext"
    );

    let sent_plaintext =
        decrypt_first_app_record_from(client_key, client_iv, tls_transcript.sent());
    let expected_sent = tls_transcript
        .sent()
        .iter()
        .find(|r| r.typ == ContentType::ApplicationData)
        .and_then(|r| r.plaintext.as_ref())
        .expect("first sent application data record must carry committed plaintext");
    assert_eq!(
        &sent_plaintext, expected_sent,
        "Proxy: AES-GCM decrypt with client_write_key must match sent plaintext"
    );
}
