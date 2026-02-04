//! Provides a TLS client.

use crate::mpz::ProverZk;
use mpc_tls::SessionKeys;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tlsn_core::transcript::{TlsTranscript, Transcript};

mod mpc;

pub(crate) use mpc::MpcTlsClient;

/// TLS client for MPC and proxy-based TLS implementations.
pub(crate) trait TlsClient {
    type Error: std::error::Error + Send + Sync + Unpin + 'static;

    /// Returns `true` if the client wants to read TLS data from the server.
    fn wants_read_tls(&self) -> bool;

    /// Returns `true` if the client wants to write TLS data to the server.
    fn wants_write_tls(&self) -> bool;

    /// Reads TLS data from the server.
    fn read_tls(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;

    /// Writes TLS data for the server into the provided buffer.
    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Returns `true` if the client wants to read plaintext data.
    fn wants_read(&self) -> bool;

    /// Returns `true` if the client wants to write plaintext data.
    fn wants_write(&self) -> bool;

    /// Reads plaintext data from the server into the provided buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Writes plaintext data to be sent to the server.
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;

    /// Client closes the connection.
    fn client_close(&mut self);

    /// Server closes the connection.
    fn server_close(&mut self);

    /// Returns the inner decryption state.
    fn decrypt(&self) -> Arc<DecryptState>;

    /// Polls the client to make progress.
    fn poll(&mut self, cx: &mut Context) -> Poll<Result<TlsOutput, Self::Error>>;
}

/// Decryption state.
#[derive(Debug)]
pub(crate) struct DecryptState {
    decrypt: AtomicBool,
    /// Flag to request key reveal for hybrid MPC mode.
    reveal_key_requested: AtomicBool,
    /// Flag indicating key has been revealed.
    key_revealed: AtomicBool,
}

impl DecryptState {
    pub(crate) fn enable_decryption(&self, enable: bool) {
        self.decrypt.store(enable, Ordering::Release);
    }

    pub(crate) fn is_decrypting(&self) -> bool {
        self.decrypt.load(Ordering::Acquire)
    }

    /// Requests the decryption key to be revealed to the follower.
    /// After this, the follower can decrypt server responses locally.
    pub(crate) fn request_key_reveal(&self) {
        self.reveal_key_requested.store(true, Ordering::Release);
    }

    /// Checks if key reveal has been requested (and clears the flag).
    pub(crate) fn take_reveal_request(&self) -> bool {
        self.reveal_key_requested.swap(false, Ordering::AcqRel)
    }

    /// Marks the key as revealed.
    pub(crate) fn mark_key_revealed(&self) {
        self.key_revealed.store(true, Ordering::Release);
    }

    /// Returns true if the key has been revealed.
    pub(crate) fn is_key_revealed(&self) -> bool {
        self.key_revealed.load(Ordering::Acquire)
    }
}

/// Output of a TLS session.
pub(crate) struct TlsOutput {
    pub(crate) ctx: mpz_common::Context,
    pub(crate) vm: ProverZk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) transcript: Transcript,
}
