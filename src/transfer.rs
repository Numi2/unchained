use serde::{Serialize, Deserialize};
use crate::crypto::{Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SIG_BYTES};

use serde_big_array::BigArray;

/// A coin transfer, which includes the sender's full public key to enable
/// verification, and a signature over the content. This forms a spendable UTXO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
    pub coin_id: [u8; 32],
    // The sender's full public key is required for stateless signature verification.
    #[serde(with = "BigArray")]
    pub sender_pk: [u8; DILITHIUM3_PK_BYTES],
    // The address of the new owner.
    pub to: Address,
    // The hash of the previous transaction, forming a per-coin chain.
    pub prev_tx_hash: [u8; 32],
    // A Dilithium3 signature from the sender.
    #[serde(with = "BigArray")]
    pub sig: [u8; DILITHIUM3_SIG_BYTES],
}

impl Transfer {
    
}