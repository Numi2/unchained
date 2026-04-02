// Library interface for unchained blockchain
// This allows tests and external consumers to use the blockchain functionality

#[cfg(feature = "classical_perimeter")]
pub mod bridge;
pub mod coin;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod epoch;
pub mod metrics;
pub mod miner;
pub mod network;
pub mod node_identity;
pub mod protocol;
pub mod storage;
pub mod sync;
pub mod transaction;
pub mod transfer;
pub mod wallet;
#[cfg(feature = "classical_perimeter")]
pub mod x402;

pub use coin::Coin;
pub use crypto::{address_from_pk, argon2id_pow, blake3_hash, Address};
pub use epoch::{Anchor, MerkleTree};
pub use storage::Store;
pub use wallet::Wallet;

// Legacy Transfer removed; export only Spend
#[cfg(feature = "classical_perimeter")]
pub use bridge::{
    BridgeEvent, BridgeInTransaction, BridgeOutTransaction, BridgeState, BridgeStatus,
};
pub use transaction::Tx;
pub use transfer::Spend;
