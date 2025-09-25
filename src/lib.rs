// Library interface for unchained blockchain
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
pub mod consensus;
pub mod bridge;
pub mod x402;

pub use coin::Coin;
pub use crypto::{Address, blake3_hash, argon2id_pow, address_from_pk};
pub use storage::Store;
pub use epoch::{Anchor, MerkleTree};
pub use wallet::Wallet;

// Legacy Transfer removed; export only Spend
pub use transfer::Spend;
pub use bridge::{BridgeState, BridgeEvent, BridgeOutTransaction, BridgeInTransaction, BridgeStatus};