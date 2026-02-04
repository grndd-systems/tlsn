use serde::{Deserialize, Serialize};
use tls_core::{
    key::PublicKey,
    msgs::enums::{ContentType, ProtocolVersion},
};

use crate::record_layer::{DecryptMode, EncryptMode};

/// MPC-TLS protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    SetClientRandom(SetClientRandom),
    StartHandshake(StartHandshake),
    SetServerRandom(SetServerRandom),
    SetServerKey(SetServerKey),
    ClientFinishedVd(ClientFinishedVd),
    ServerFinishedVd(ServerFinishedVd),
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    StartTraffic,
    Flush { is_decrypting: bool },
    CloseConnection,
    /// Leader reveals the full decryption key to Follower.
    /// This enables Follower to decrypt responses locally (hybrid MPC mode).
    RevealDecryptionKey(RevealDecryptionKey),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetClientRandom {
    pub(crate) random: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StartHandshake {
    pub(crate) time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetServerRandom {
    pub(crate) random: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetServerKey {
    pub(crate) key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Decrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) mode: DecryptMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Encrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) mode: EncryptMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ClientFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ServerFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct CloseConnection;

/// Message sent by Leader to reveal the full decryption key to Follower.
/// After receiving this, Follower can decrypt TLS responses locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RevealDecryptionKey {
    /// Full server_write_key (AES-128 key for decrypting server responses)
    pub server_write_key: [u8; 16],
    /// Full server_write_iv (implicit nonce for AES-GCM)
    pub server_write_iv: [u8; 4],
}
