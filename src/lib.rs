// Library interface for unchained blockchain
// This allows tests and external consumers to use the blockchain functionality

pub mod app;
pub mod canonical;
pub mod coin;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod epoch;
pub mod local_control;
pub mod metrics;
pub mod miner;
pub mod network;
pub mod node_control;
pub mod node_identity;
pub mod proof;
pub mod protocol;
pub mod shielded;
pub mod storage;
pub mod sync;
pub mod transaction;
pub mod wallet;
pub mod wallet_control;

pub use coin::Coin;
pub use crypto::{address_from_pk, argon2id_pow, blake3_hash, Address};
pub use epoch::{Anchor, MerkleTree};
pub use storage::Store;
pub use wallet::Wallet;

pub use transaction::Tx;
