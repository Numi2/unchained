// Library interface for UnchainedCoin blockchain
// This allows tests and external consumers to use the blockchain functionality

pub mod config;
pub mod crypto;
pub mod storage;
pub mod epoch;
pub mod coin;
pub mod transfer;
pub mod miner;
pub mod network;
pub mod sync;
pub mod metrics;
pub mod wallet;

// Re-export commonly used types for convenience
pub use coin::Coin;
pub use crypto::{Address, blake3_hash, argon2id_pow, address_from_pk, dilithium3_keypair};
pub use storage::Store;
pub use epoch::{Anchor, MerkleTree};
pub use wallet::Wallet;
pub use transfer::Transfer;