//! Shared utilities for TikTok TLSNotary examples.

use std::env;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{info, instrument};

use tlsn::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig, TlsCommitProtocolConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    transcript::PartialTranscript,
    verifier::VerifierOutput,
    webpki::{CertificateDer, RootCertStore},
    Session,
};

const TIKTOK_HOST: &str = "www.tiktok.com";
const MAX_SENT_DATA: usize = 1 << 13; // 8KB
const MAX_RECV_DATA: usize = 1 << 17; // 128KB

/// Load TikTok API path, cookies, and referer from env vars or files.
pub fn load_config(default_referer: &str) -> Result<(String, String, String)> {
    let path = if let Ok(file) = env::var("TIKTOK_PATH_FILE") {
        let content = std::fs::read_to_string(&file)
            .with_context(|| format!("Failed to read {}", file))?;
        fix_query_params(content.trim())
    } else {
        fix_query_params(
            &env::var("TIKTOK_PATH").context("TIKTOK_PATH or TIKTOK_PATH_FILE required")?,
        )
    };

    let cookies = if let Ok(file) = env::var("TIKTOK_COOKIES_FILE") {
        std::fs::read_to_string(&file)
            .with_context(|| format!("Failed to read {}", file))?
            .trim()
            .to_string()
    } else {
        env::var("TIKTOK_COOKIES").context("TIKTOK_COOKIES or TIKTOK_COOKIES_FILE required")?
    };

    let referer = env::var("TIKTOK_REFERER").unwrap_or_else(|_| default_referer.to_string());
    Ok((path, cookies, referer))
}

/// URL-encode special characters in query parameter values.
fn fix_query_params(path: &str) -> String {
    let Some(query_start) = path.find('?') else {
        return path.to_string();
    };
    let (base, query) = path.split_at(query_start + 1);
    let fixed: String = query
        .split('&')
        .map(|param| {
            if let Some(eq) = param.find('=') {
                let (key, val) = param.split_at(eq);
                let fixed_val = val[1..].replace('/', "%2F").replace('=', "%3D");
                format!("{}={}", key, fixed_val)
            } else {
                param.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{}{}", base, fixed)
}

/// Remove HTTP chunked transfer encoding markers from body.
fn remove_chunk_markers(body: &str) -> String {
    let mut result = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
            let mut hex = String::new();
            while hex.len() < 8 {
                match chars.peek() {
                    Some(&c) if c.is_ascii_hexdigit() => hex.push(chars.next().unwrap()),
                    _ => break,
                }
            }
            if !hex.is_empty() && chars.peek() == Some(&'\r') {
                chars.next();
                if chars.peek() == Some(&'\n') {
                    chars.next();
                    continue;
                }
                result.push_str("\r\n");
                result.push_str(&hex);
                result.push('\r');
            } else {
                result.push_str("\r\n");
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Extract JSON body from an HTTP response transcript.
pub fn extract_json(transcript: &PartialTranscript) -> Option<serde_json::Value> {
    let response = String::from_utf8_lossy(transcript.received_unsafe());
    let body_start = response.find("\r\n\r\n")?;
    let mut body = &response[body_start + 4..];

    if let Some(nl) = body.find('\n') {
        if body[..nl].trim().chars().all(|c| c.is_ascii_hexdigit()) {
            body = &body[nl + 1..];
        }
    }

    let json_start = body.find('{')?;
    let json_end = body.rfind('}').map(|i| i + 1)?;
    let json = remove_chunk_markers(&body[json_start..json_end]);
    serde_json::from_str(&json).ok()
}

/// Run TLSNotary proof: prover and verifier concurrently over a duplex channel.
pub async fn run_proof(path: &str, cookies: &str, referer: &str) -> Result<PartialTranscript> {
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);

    let prover_task = {
        let path = path.to_string();
        let cookies = cookies.to_string();
        let referer = referer.to_string();
        tokio::spawn(async move { prover(prover_socket, &path, &cookies, &referer).await })
    };
    let verifier_task = tokio::spawn(verifier(verifier_socket));

    let (prover_result, verifier_result) = tokio::join!(prover_task, verifier_task);
    prover_result??;
    verifier_result?
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|c| CertificateDer(c.to_vec()))
            .collect(),
    }
}

#[instrument(skip_all)]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    path: &str,
    cookies: &str,
    referer: &str,
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    info!("Setting up MPC-TLS");
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_recv_data(MAX_RECV_DATA)
                        .build()?,
                )
                .build()?,
        )
        .await?;

    info!("Connecting to TikTok");
    let tcp = tokio::net::TcpStream::connect(format!("{}:443", TIKTOK_HOST)).await?;
    let (tls, prover_fut) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(TIKTOK_HOST.try_into()?))
            .root_store(root_store())
            .build()?,
        tcp.compat(),
    )?;

    let prover_task = tokio::spawn(prover_fut);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls.compat())).await?;
    tokio::spawn(conn);

    let request = Request::builder()
        .uri(path)
        .header("Host", TIKTOK_HOST)
        .header("Connection", "close")
        .header("Cookie", cookies)
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0")
        .header("Accept", "*/*")
        .header("Referer", referer)
        .body(Empty::<Bytes>::new())?;

    info!("Sending request");
    let response = sender.send_request(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    if status != StatusCode::OK {
        anyhow::bail!("TikTok returned {}: {}", status, String::from_utf8_lossy(&body));
    }
    info!("Response: {} bytes", body.len());

    let mut prover = prover_task.await??;
    let mut config = ProveConfig::builder(prover.transcript());
    config.server_identity();
    config.reveal_sent(&(0..prover.transcript().sent().len()))?;
    config.reveal_recv(&(0..prover.transcript().received().len()))?;

    prover.prove(&config.build()?).await?;
    prover.close().await?;
    handle.close();
    driver_task.await??;
    Ok(())
}

#[instrument(skip_all)]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle
        .new_verifier(VerifierConfig::builder().root_store(root_store()).build()?)?
        .commit()
        .await?;

    let reject = match verifier.request().protocol() {
        TlsCommitProtocolConfig::Mpc(cfg) => {
            if cfg.max_sent_data() > MAX_SENT_DATA || cfg.max_recv_data() > MAX_RECV_DATA {
                Some("data limits exceeded")
            } else {
                None
            }
        }
        _ => Some("expecting MPC-TLS"),
    };

    if let Some(reason) = reject {
        verifier.reject(Some(reason)).await?;
        anyhow::bail!("rejected: {}", reason);
    }

    let verifier = verifier.accept().await?.run().await?.verify().await?;
    if !verifier.request().server_identity() {
        verifier.reject(Some("expecting server identity")).await?;
        anyhow::bail!("no server identity");
    }

    let (output, verifier) = verifier.accept().await?;
    verifier.close().await?;
    handle.close();
    driver_task.await??;

    let VerifierOutput { server_name, transcript, .. } = output;
    let server_name = server_name.expect("server name revealed");
    let transcript = transcript.expect("transcript revealed");
    let ServerName::Dns(name) = server_name;
    if !name.as_str().contains("tiktok.com") {
        anyhow::bail!("unexpected server: {}", name.as_str());
    }
    info!("Verified: {}", name.as_str());
    Ok(transcript)
}
