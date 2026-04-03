use aws_lc_rs::unstable::signature::PqdsaKeyPair;
use unchained::{
    consensus::{
        OrderingPath, QuorumCertificate, Validator, ValidatorId, ValidatorKeys, ValidatorSet,
        ValidatorVote, VoteTarget,
    },
    crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    node_identity::{validator_from_record, NodeIdentity},
    staking::{ValidatorMetadata, ValidatorPool, ValidatorStatus},
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
        let members = identities
            .into_iter()
            .map(|identity| CommitteeMember {
                validator: validator_from_record(identity.record(), 1)
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
}
