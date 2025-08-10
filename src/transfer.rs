use serde::{Serialize, Deserialize};
use crate::crypto::{Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SIG_BYTES};
use anyhow::{Result, Context, anyhow};
use pqcrypto_dilithium::dilithium3::{PublicKey, SecretKey, DetachedSignature};
use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};

use serde_big_array::BigArray;

/// A coin transfer, which includes the sender's full public key to enable
/// verification, and a signature over the content. This forms a spendable UTXO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
    /// Version 0: legacy (no ts/seq in signature);
    /// Version 1: includes ts_unix and seq in signature bytes
    #[serde(default = "default_transfer_version")]
    pub version: u8,
    pub coin_id: [u8; 32],
    // The sender's full public key is required for stateless signature verification.
    #[serde(with = "BigArray")]
    pub sender_pk: [u8; DILITHIUM3_PK_BYTES],
    // The address of the new owner.
    pub to: Address,
    // The hash of the previous transaction, forming a per-coin chain.
    pub prev_tx_hash: [u8; 32],
    /// Wall-clock timestamp (Unix seconds) for replay protection and UX
    #[serde(default)]
    pub ts_unix: u64,
    /// Per-sender monotonically increasing sequence number for replay protection
    #[serde(default)]
    pub seq: u64,
    // A Dilithium3 signature from the sender.
    #[serde(with = "BigArray")]
    pub sig: [u8; DILITHIUM3_SIG_BYTES],
}

impl Transfer {
    fn signing_bytes_v0(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + DILITHIUM3_PK_BYTES + 32 + 32);
        v.extend_from_slice(&self.coin_id);
        v.extend_from_slice(&self.sender_pk);
        v.extend_from_slice(&self.to);
        v.extend_from_slice(&self.prev_tx_hash);
        v
    }

    /// Canonical bytes-to-sign: coin_id ‖ sender_pk ‖ to ‖ prev_tx_hash.
    /// For version 1, also includes ts_unix ‖ seq.
    /// This deterministic serialization prevents replay/tamper attacks and is
    /// independent of any serde/bincode representation.
    pub fn signing_bytes(&self) -> Vec<u8> {
        match self.version {
            0 => self.signing_bytes_v0(),
            _ => {
                let mut v = Vec::with_capacity(32 + DILITHIUM3_PK_BYTES + 32 + 32 + 8 + 8 + 1);
                v.push(1u8); // version marker inside signing bytes for domain separation
                v.extend_from_slice(&self.coin_id);
                v.extend_from_slice(&self.sender_pk);
                v.extend_from_slice(&self.to);
                v.extend_from_slice(&self.prev_tx_hash);
                v.extend_from_slice(&self.ts_unix.to_le_bytes());
                v.extend_from_slice(&self.seq.to_le_bytes());
                v
            }
        }
    }

    /// Backwards-compat alias used by old code paths – now forwards to signing_bytes().
    #[deprecated(note = "Use signing_bytes() instead")]    
    pub fn content_bytes(&self) -> Vec<u8> {
        self.signing_bytes()
    }

    /// Deterministic hash over the canonical signing bytes (not over serde encoding).
    pub fn hash(&self) -> [u8; 32] {
        crate::crypto::blake3_hash(&self.signing_bytes())
    }

    /// Creates a new transfer from a coin to a recipient address.
    /// This is the main entry point for creating transfers.
    /// For replay protection, caller must provide current unix time and next sequence number.
    pub fn create(
        coin_id: [u8; 32],
        sender_pk: PublicKey,
        sender_sk: &SecretKey,
        to: Address,
        prev_tx_hash: [u8; 32],
        ts_unix: u64,
        seq: u64,
    ) -> Result<Self> {
        // Validate inputs
        if to == [0u8; 32] {
            return Err(anyhow!("Invalid recipient address: cannot be zero"));
        }

        let sender_pk_bytes = sender_pk.as_bytes();
        let mut transfer = Transfer {
            version: 1,
            coin_id,
            sender_pk: [0u8; DILITHIUM3_PK_BYTES],
            to,
            prev_tx_hash,
            ts_unix,
            seq,
            sig: [0u8; DILITHIUM3_SIG_BYTES],
        };
        
        // Copy public key bytes
        transfer.sender_pk.copy_from_slice(sender_pk_bytes);

        // Sign the transfer
        let signing_bytes = transfer.signing_bytes();
        let signature = pqcrypto_dilithium::dilithium3::detached_sign(&signing_bytes, sender_sk);
        transfer.sig.copy_from_slice(signature.as_bytes());

        Ok(transfer)
    }

    /// Validates a transfer against the current blockchain state.
    /// Returns Ok(()) if valid, Err with reason if invalid.
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {
        // Check coin exists
        let coin: crate::coin::Coin = db.get("coin", &self.coin_id)
            .context("Failed to query coin from database")?
            .ok_or_else(|| anyhow!("Referenced coin does not exist"))?;

        // Determine last owner and expected prev_tx_hash
        let last_tx: Option<Transfer> = db.get("transfer", &self.coin_id)
            .context("Failed to query transfer from database")?;
        let (expected_owner_addr, expected_prev_hash) = match last_tx {
            Some(ref t) => (t.recipient(), t.hash()),
            None => (coin.creator_address, self.coin_id),
        };

        // Validate sender is last owner
        let sender_pk = PublicKey::from_bytes(&self.sender_pk)
            .context("Invalid sender public key")?;
        let sender_addr = crate::crypto::address_from_pk(&sender_pk);
        if sender_addr != expected_owner_addr {
            return Err(anyhow!("Sender is not current owner"));
        }

        // Validate recipient address
        if self.to == [0u8; 32] {
            return Err(anyhow!("Invalid recipient address: cannot be zero"));
        }

        // Validate signature
        let signature = DetachedSignature::from_bytes(&self.sig)
            .context("Invalid signature format")?;
        if pqcrypto_dilithium::dilithium3::verify_detached_signature(
            &signature,
            &self.signing_bytes(),
            &sender_pk,
        ).is_err() {
            return Err(anyhow!("Invalid signature"));
        }

        // Anti-replay: prev_tx_hash must match current chain tip for this coin
        if self.prev_tx_hash != expected_prev_hash {
            return Err(anyhow!("Invalid prev_tx_hash"));
        }

        // Replay protection (version >= 1): enforce timestamp window and monotonic (ts, seq)
        if self.version >= 1 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Allow at most 24h clock skew into the future
            let max_future_skew = 24 * 60 * 60;
            if self.ts_unix > now + max_future_skew {
                return Err(anyhow!("Transfer timestamp too far in the future"));
            }
            // Lookup last seen (ts, seq) for this sender
            let last = db.get_replay_state(&self.sender_pk)?;
            if let Some((last_ts, last_seq)) = last {
                let newer = self.ts_unix > last_ts || (self.ts_unix == last_ts && self.seq > last_seq);
                if !newer {
                    return Err(anyhow!("Non-monotonic (ts,seq) for sender; possible replay"));
                }
            }
        }

        Ok(())
    }

    /// Applies a validated transfer to the database.
    /// This should only be called after validate() returns Ok.
    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        // Store the transfer to mark the coin as spent
        db.put("transfer", &self.coin_id, self)
            .context("Failed to store transfer in database")?;
        // Update replay state for the sender (idempotent on same (ts,seq))
        if self.version >= 1 {
            db.put_replay_state(&self.sender_pk, self.ts_unix, self.seq)
                .context("Failed to update replay state")?;
        }
        
        Ok(())
    }

    /// Gets the recipient address of this transfer
    pub fn recipient(&self) -> Address {
        self.to
    }

    /// Gets the sender's address (derived from public key)
    pub fn sender(&self) -> Result<Address> {
        let sender_pk = PublicKey::from_bytes(&self.sender_pk)
            .context("Invalid sender public key")?;
        Ok(crate::crypto::address_from_pk(&sender_pk))
    }

    /// Checks if this transfer is to a specific address
    pub fn is_to(&self, address: &Address) -> bool {
        &self.to == address
    }

    /// Checks if this transfer is from a specific address
    pub fn is_from(&self, address: &Address) -> Result<bool> {
        Ok(self.sender()? == *address)
    }
}

fn default_transfer_version() -> u8 { 0 }

/// Transfer manager for handling transfer operations
pub struct TransferManager {
    db: std::sync::Arc<crate::storage::Store>,
}

impl TransferManager {
    pub fn new(db: std::sync::Arc<crate::storage::Store>) -> Self {
        Self { db }
    }

    /// Creates and broadcasts a transfer
    pub async fn send_transfer(
        &self,
        coin_id: [u8; 32],
        sender_pk: PublicKey,
        sender_sk: &SecretKey,
        to: Address,
        network: &crate::network::NetHandle,
    ) -> Result<Transfer> {
        // Get the previous transaction hash for this coin
        let prev_tx_hash = self.get_previous_tx_hash(&coin_id)?;

        // Derive timestamp and next sequence for replay protection
        let ts_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sender_pk_bytes = sender_pk.as_bytes();
        let last = self.db.get_replay_state(sender_pk_bytes)?;
        let next_seq = match last { Some((_ts, seq)) => seq.saturating_add(1), None => 0 };

        // Create the transfer
        let transfer = Transfer::create(
            coin_id,
            sender_pk,
            sender_sk,
            to,
            prev_tx_hash,
            ts_unix,
            next_seq,
        )?;

        // Validate the transfer
        transfer.validate(&self.db)?;

        // Apply the transfer to our local database
        transfer.apply(&self.db)?;

        // Broadcast the transfer to the network
        network.gossip_transfer(&transfer).await;

        Ok(transfer)
    }

    /// Gets the previous transaction hash for a coin (coin_id if first spend)
    fn get_previous_tx_hash(&self, coin_id: &[u8; 32]) -> Result<[u8; 32]> {
        if let Some(last) = self.get_transfer_for_coin(coin_id)? {
            Ok(last.hash())
        } else {
            Ok(*coin_id)
        }
    }

    /// Gets all transfers for a specific address (as sender or recipient)
    pub fn get_transfers_for_address(&self, address: &Address) -> Result<Vec<Transfer>> {
        let cf = self.db.db.cf_handle("transfer")
            .ok_or_else(|| anyhow!("'transfer' column family missing"))?;

        let iter = self.db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut transfers = Vec::new();
        
        for item in iter {
            let (_key, value) = item?;
            if let Ok(transfer) = bincode::deserialize::<Transfer>(&value) {
                // Check if this transfer involves the address
                if transfer.is_to(address) || transfer.is_from(address)? {
                    transfers.push(transfer);
                }
            }
        }
        
        Ok(transfers)
    }

    /// Gets the transfer for a specific coin (if it exists)
    pub fn get_transfer_for_coin(&self, coin_id: &[u8; 32]) -> Result<Option<Transfer>> {
        self.db.get("transfer", coin_id)
    }

    /// Checks if a coin is spent
    pub fn is_coin_spent(&self, coin_id: &[u8; 32]) -> Result<bool> {
        Ok(self.get_transfer_for_coin(coin_id)?.is_some())
    }
}