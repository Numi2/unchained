use aws_lc_rs::unstable::signature::PqdsaKeyPair;
use unchained::{
    coin::Coin,
    consensus::{
        OrderingPath, QuorumCertificate, Validator, ValidatorId, ValidatorKeys, ValidatorSet,
        ValidatorVote, VoteTarget,
    },
    crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    node_control,
    node_identity::{validator_from_record, NodeIdentity},
    proof,
    staking::{ValidatorMetadata, ValidatorPool, ValidatorStatus},
    transaction::{
        shared_state_action_fee_amount, OrdinaryPrivateTransfer, SharedStateAction,
        SharedStateBatch, SharedStateDagBatch, Tx,
    },
    wallet::Wallet,
    Store,
};

#[allow(dead_code)]
enum CommitteeSigner {
    TestKey(PqdsaKeyPair),
    Identity(NodeIdentity),
}

struct CommitteeMember {
    validator: Validator,
    signer: CommitteeSigner,
}

pub struct TestCommittee {
    members: Vec<CommitteeMember>,
}

impl TestCommittee {
    pub fn single_validator() -> Self {
        let hot_key = ml_dsa_65_generate().expect("generate test hot key");
        let cold_key = ml_dsa_65_generate().expect("generate test cold key");
        let validator = Validator::new(
            1,
            ValidatorKeys {
                hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key)
                    .expect("encode test hot key"),
                cold_governance_key: ml_dsa_65_public_key_spki(&cold_key)
                    .expect("encode test cold key"),
            },
        )
        .expect("create test validator");
        Self {
            members: vec![CommitteeMember {
                validator,
                signer: CommitteeSigner::TestKey(hot_key),
            }],
        }
    }

    #[allow(dead_code)]
    pub fn from_identities(identities: Vec<NodeIdentity>) -> Self {
        Self::from_weighted_identities(
            identities
                .into_iter()
                .map(|identity| (identity, 1))
                .collect(),
        )
    }

    #[allow(dead_code)]
    pub fn from_weighted_identities(weighted_identities: Vec<(NodeIdentity, u64)>) -> Self {
        let members = weighted_identities
            .into_iter()
            .map(|(identity, voting_power)| CommitteeMember {
                validator: validator_from_record(identity.record(), voting_power)
                    .expect("derive validator from runtime identity"),
                signer: CommitteeSigner::Identity(identity),
            })
            .collect();
        Self { members }
    }

    fn validator_set(&self, epoch: u64) -> ValidatorSet {
        ValidatorSet::new(
            epoch,
            self.members
                .iter()
                .map(|member| member.validator.clone())
                .collect(),
        )
        .expect("build validator set")
    }

    #[allow(dead_code)]
    pub fn validator_set_for_epoch(&self, epoch: u64) -> ValidatorSet {
        self.validator_set(epoch)
    }

    pub fn validator_pools(&self, activation_epoch: u64) -> Vec<ValidatorPool> {
        self.members
            .iter()
            .map(|member| {
                ValidatorPool::new(
                    member.validator.clone(),
                    match &member.signer {
                        CommitteeSigner::Identity(identity) => identity.node_id(),
                        CommitteeSigner::TestKey(_) => member.validator.id.0,
                    },
                    0,
                    member.validator.voting_power,
                    activation_epoch,
                    ValidatorStatus::Active,
                    ValidatorMetadata::default(),
                )
                .expect("build validator pool")
            })
            .collect()
    }

    pub fn seed_validator_state(&self, store: &Store, epoch: u64) -> anyhow::Result<()> {
        store.store_validator_committee(&self.validator_set(epoch))?;
        for pool in self.validator_pools(epoch) {
            store.store_validator_pool(&pool)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn leader_for(&self, num: u64) -> ValidatorId {
        let position = Anchor::position_for_num(num);
        self.validator_set(position.epoch).leader_for(position)
    }

    pub fn anchor(
        &self,
        num: u64,
        parent: Option<&Anchor>,
        merkle_root: [u8; 32],
        coin_count: u32,
        ordering_path: OrderingPath,
    ) -> Anchor {
        let position = Anchor::position_for_num(num);
        let validator_set = self.validator_set(position.epoch);
        let block_digest = Anchor::compute_hash(
            num,
            parent.map(|anchor| anchor.hash),
            position,
            ordering_path,
            merkle_root,
            coin_count,
            0,
            &[],
            &[],
            [0u8; 32],
            0,
            &validator_set,
        );
        let target = VoteTarget {
            position,
            ordering_path,
            block_digest,
        };
        let target_bytes = target.signing_bytes();
        let votes = self
            .members
            .iter()
            .map(|member| ValidatorVote {
                voter: member.validator.id,
                target: target.clone(),
                signature: match &member.signer {
                    CommitteeSigner::TestKey(hot_key) => {
                        ml_dsa_65_sign(hot_key, &target_bytes).expect("sign test checkpoint")
                    }
                    CommitteeSigner::Identity(identity) => identity
                        .sign_consensus_message(&target_bytes)
                        .expect("sign runtime checkpoint"),
                },
            })
            .collect();
        let qc = QuorumCertificate::from_votes(&validator_set, target, votes)
            .expect("build test checkpoint QC");
        let anchor = Anchor::new(
            num,
            parent.map(|anchor| anchor.hash),
            ordering_path,
            merkle_root,
            coin_count,
            0,
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            0,
            validator_set,
            qc,
        )
        .expect("build test checkpoint");
        anchor
            .validate_against_parent(parent)
            .expect("validate test checkpoint");
        anchor
    }

    pub fn genesis_anchor(&self) -> Anchor {
        self.anchor(0, None, [0u8; 32], 0, OrderingPath::FastPathPrivateTransfer)
    }

    #[allow(dead_code)]
    pub fn child_anchor(&self, parent: &Anchor, merkle_root: [u8; 32], coin_count: u32) -> Anchor {
        self.anchor(
            parent.num.saturating_add(1),
            Some(parent),
            merkle_root,
            coin_count,
            OrderingPath::FastPathPrivateTransfer,
        )
    }

    #[allow(dead_code)]
    pub fn shared_state_anchor(
        &self,
        parent: &Anchor,
        dag_round: u64,
        dag_frontier: Vec<[u8; 32]>,
        ordered_batches: Vec<SharedStateDagBatch>,
    ) -> Anchor {
        let num = parent.num.saturating_add(1);
        let position = Anchor::position_for_num(num);
        let validator_set = self.validator_set(position.epoch);
        let aggregate_batch =
            SharedStateBatch::from_dag_batches(&ordered_batches).expect("aggregate DAG batches");
        let ordered_batch_ids = ordered_batches
            .iter()
            .map(|batch| batch.batch_id)
            .collect::<Vec<_>>();
        let ordered_tx_count = aggregate_batch
            .ordered_tx_count()
            .expect("aggregate ordered tx count");
        let block_digest = Anchor::compute_hash(
            num,
            Some(parent.hash),
            position,
            OrderingPath::DagBftSharedState,
            [0u8; 32],
            0,
            dag_round,
            &dag_frontier,
            &ordered_batch_ids,
            aggregate_batch.ordered_tx_root,
            ordered_tx_count,
            &validator_set,
        );
        let target = VoteTarget {
            position,
            ordering_path: OrderingPath::DagBftSharedState,
            block_digest,
        };
        let target_bytes = target.signing_bytes();
        let votes = self
            .members
            .iter()
            .map(|member| ValidatorVote {
                voter: member.validator.id,
                target: target.clone(),
                signature: match &member.signer {
                    CommitteeSigner::TestKey(hot_key) => ml_dsa_65_sign(hot_key, &target_bytes)
                        .expect("sign test shared-state checkpoint"),
                    CommitteeSigner::Identity(identity) => identity
                        .sign_consensus_message(&target_bytes)
                        .expect("sign runtime shared-state checkpoint"),
                },
            })
            .collect();
        let qc = QuorumCertificate::from_votes(&validator_set, target, votes)
            .expect("build test shared-state checkpoint QC");
        let anchor = Anchor::new(
            num,
            Some(parent.hash),
            OrderingPath::DagBftSharedState,
            [0u8; 32],
            0,
            dag_round,
            dag_frontier,
            ordered_batch_ids,
            aggregate_batch.ordered_tx_root,
            ordered_tx_count,
            validator_set,
            qc,
        )
        .expect("build test shared-state checkpoint");
        anchor
            .validate_against_parent(Some(parent))
            .expect("validate test shared-state checkpoint");
        anchor
    }
}

#[allow(dead_code)]
pub fn seed_wallet_with_coins(
    store: &Store,
    wallet: &Wallet,
    genesis: &Anchor,
    count: u64,
) -> anyhow::Result<Vec<Coin>> {
    let chain_id = genesis.hash;
    let mut coins = Vec::with_capacity(count as usize);
    for nonce in 7..(7 + count) {
        let candidate_id = Coin::calculate_id(&genesis.hash, nonce, &wallet.address());
        let lock_secret = wallet.compute_genesis_lock_secret(&candidate_id, &chain_id);
        let lock_hash =
            unchained::crypto::lock_hash_from_preimage(&chain_id, &candidate_id, &lock_secret);
        let coin = Coin::new_with_creator_pk_and_lock(
            genesis.hash,
            nonce,
            wallet.address(),
            wallet.public_key().clone(),
            lock_hash,
        );
        store.put("coin", &coin.id, &coin)?;
        store.put_coin_epoch(&coin.id, genesis.num)?;
        store.put_coin_epoch_rev(genesis.num, &coin.id)?;
        coins.push(coin);
    }
    Ok(coins)
}

#[allow(dead_code)]
pub fn fee_payment_transfer_for_action(
    store: &Store,
    wallet: &Wallet,
    action: &SharedStateAction,
) -> anyhow::Result<OrdinaryPrivateTransfer> {
    let snapshot = node_control::build_shielded_runtime_snapshot(store)?;
    let prepared = wallet
        .prepare_fee_payment_for_snapshot(&snapshot, shared_state_action_fee_amount(action))?;
    let (receipt, _journal) = proof::prove_shielded_tx(prepared.witness())?;
    let tx = prepared.tx_with_proof(proof::receipt_to_bytes(&receipt)?);
    Ok(tx
        .ordinary_transfer()
        .cloned()
        .expect("fee payment helper must produce an ordinary private transfer"))
}

#[allow(dead_code)]
pub fn fee_paid_shared_state_tx(
    store: &Store,
    wallet: &Wallet,
    action: SharedStateAction,
    authorization_signature: Vec<u8>,
) -> anyhow::Result<Tx> {
    let fee_payment = fee_payment_transfer_for_action(store, wallet, &action)?;
    Ok(Tx::new_shared_state_with_fee_payment(
        action,
        authorization_signature,
        Some(fee_payment),
    ))
}
