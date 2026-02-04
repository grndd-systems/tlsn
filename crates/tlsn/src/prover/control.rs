use crate::prover::client::DecryptState;
use std::sync::Arc;

/// A controller for the prover.
///
/// Can be used to control the decryption of server traffic.
#[derive(Clone, Debug)]
pub struct ProverControl {
    pub(crate) decrypt_state: Arc<DecryptState>,
}

impl ProverControl {
    /// Returns whether the prover is decrypting the server traffic.
    pub fn is_decrypting(&self) -> bool {
        self.decrypt_state.is_decrypting()
    }

    /// Enables or disables the decryption of server traffic.
    ///
    /// # Arguments
    ///
    /// * `enable` - If decryption should be enabled or disabled.
    pub fn enable_decryption(&self, enable: bool) {
        self.decrypt_state.enable_decryption(enable)
    }

    /// Requests the decryption key to be revealed to the follower.
    ///
    /// This enables hybrid MPC mode where only request encryption uses MPC,
    /// while response decryption happens locally on the follower.
    /// This can significantly improve performance (~7x speedup).
    ///
    /// After calling this, the prover future must be polled for the
    /// key reveal to complete.
    pub fn reveal_decryption_key(&self) {
        self.decrypt_state.request_key_reveal()
    }

    /// Returns whether the decryption key has been revealed.
    pub fn is_key_revealed(&self) -> bool {
        self.decrypt_state.is_key_revealed()
    }
}
