// Library interface for unchained blockchain
// This allows tests and external consumers to use the blockchain functionality

pub mod canonical;
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
pub mod shielded;
pub mod storage;
pub mod sync;
pub mod transaction;
pub mod transfer;
pub mod wallet;

pub use coin::Coin;
pub use crypto::{address_from_pk, argon2id_pow, blake3_hash, Address};
pub use epoch::{Anchor, MerkleTree};
pub use storage::Store;
pub use wallet::Wallet;

pub use transaction::Tx;
pub use transfer::Spend;
