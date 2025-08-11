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

/// Tracks the current tip of a coin's transfer chain.
/// last_seq == 0 and last_hash == coin_id means the coin has never been transferred.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tip {
    pub last_hash: [u8; 32],
    pub last_seq: u64,
}

/// A transfer plus its acceptance epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferInclusion {
    pub transfer: Transfer,
    pub epoch_num: u64,
}

impl Transfer {
    /// Canonical bytes-to-sign: coin_id ‖ sender_pk ‖ to ‖ prev_tx_hash.
    /// This deterministic serialization prevents replay/tamper attacks and is
    /// independent of any serde/bincode representation.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + DILITHIUM3_PK_BYTES + 32 + 32);
        v.extend_from_slice(&self.coin_id);
        v.extend_from_slice(&self.sender_pk);
        v.extend_from_slice(&self.to);
        v.extend_from_slice(&self.prev_tx_hash);
        v
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
    pub fn create(
        coin_id: [u8; 32],
        sender_pk: PublicKey,
        sender_sk: &SecretKey,
        to: Address,
        prev_tx_hash: [u8; 32],
    ) -> Result<Self> {
        // Validate inputs
        if to == [0u8; 32] {
            return Err(anyhow!("Invalid recipient address: cannot be zero"));
        }

        let sender_pk_bytes = sender_pk.as_bytes();
        let mut transfer = Transfer {
            coin_id,
            sender_pk: [0u8; DILITHIUM3_PK_BYTES],
            to,
            prev_tx_hash,
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

        // Determine last owner and expected prev_tx_hash from the per-coin tip
        let tip = db
            .get_transfer_tip(&self.coin_id)
            .context("Failed to read transfer tip")?;

        let (expected_owner_addr, expected_prev_hash) = match tip {
            Some(ref tip) if tip.last_seq > 0 => {
                // Load the last transfer to get recipient/current owner
                let last: Transfer = db
                    .get_last_transfer_for_coin(&self.coin_id)
                    .context("Failed to fetch last transfer")?
                    .ok_or_else(|| anyhow!("Tip says last_seq>0 but no transfer found"))?;
                (last.recipient(), tip.last_hash)
            }
            _ => (coin.creator_address, self.coin_id),
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

        Ok(())
    }

    /// Applies a validated transfer to the database.
    /// This should only be called after validate() returns Ok.
    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        // Append the transfer atomically to the coin's history, updating the tip
        db.append_transfer_if_tip_matches(self)
            .context("Failed to append transfer atomically")
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

        // Create the transfer
        let transfer = Transfer::create(
            coin_id,
            sender_pk,
            sender_sk,
            to,
            prev_tx_hash,
        )?;

        // Validate the transfer
        transfer.validate(&self.db)?;

        // Do not apply immediately; add to mempool locally (epoch finalization will include it)
        self.db.put_mempool_tx(&transfer)?;

        // Broadcast the transfer to the network (mempool)
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
        self.db.get_last_transfer_for_coin(coin_id)
    }

    /// Checks if a coin is spent
    pub fn is_coin_spent(&self, coin_id: &[u8; 32]) -> Result<bool> {
        Ok(self.get_transfer_for_coin(coin_id)?.is_some())
    }
}