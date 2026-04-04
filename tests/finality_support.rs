use aws_lc_rs::unstable::signature::PqdsaKeyPair;
use base64::Engine;
use std::{
    fs,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::broadcast, task::JoinHandle};
use unchained::{
    coin::Coin,
    consensus::{
        OrderingPath, QuorumCertificate, Validator, ValidatorId, ValidatorKeys, ValidatorSet,
        ValidatorVote, VoteTarget,
    },
    crypto::{ml_dsa_65_keypair_from_pkcs8, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    ingress, node_control,
    node_identity::{validator_from_record, NodeIdentity},
    proof, proof_assistant, protocol,
    staking::{ValidatorMetadata, ValidatorPool, ValidatorStatus},
    storage::WalletStore,
    transaction::{
        shared_state_action_fee_amount, OrdinaryPrivateTransfer, SharedStateAction,
        SharedStateBatch, SharedStateDagBatch, Tx,
    },
    wallet::Wallet,
    Store,
};

const FIXED_SINGLE_VALIDATOR_HOT_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIPlh59A1tYDbr3iZb7kk8/ZdSBr2GhUyN1OaGkDqL0RE";
const FIXED_SINGLE_VALIDATOR_COLD_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIOYZWUuMD9p3XlOQ0CTOL2tldfnihAvpPiJD4nkQfpmg";
const FIXED_WALLET_SIGNING_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIABA+NTwDFQVCN7fcyoajJy/7YYd1GDAaTehWrCw8lCx";
const FIXED_WALLET_LOCK_SEED: [u8; 32] = [42u8; 32];
const FIXED_NODE1_ROOT_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIKFDlv9ExCEupBXl5fpIPAqBa7S1h3cAe8/jHKufg8dI";
const FIXED_NODE1_AUTH_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAILHsRG5jg017yBw1b1p7Fhb0KtBHYVbZcD0AKh8Uk3t1";
const FIXED_NODE2_ROOT_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIEA3QsmL3qGZEUzn3OK/LHvvzQpgCeRzf4FP3rgpQulN";
const FIXED_NODE2_AUTH_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAlbcRApv4GxpMrhp4v0w7C2uUZu+ZTu17W8XWT3n4BG";
const FIXED_NODE3_ROOT_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIL+v0EWk22hAdWBNd4t2ZmQ+efmQDIsb66h+vUoNcKcu";
const FIXED_NODE3_AUTH_PKCS8_B64: &str =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIJqTkaG2MLIO4pmZ8OvrNbOU9c1FwplffVLv6iICDKfV";

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

#[allow(dead_code)]
pub struct TestIngressHarness {
    pub client: ingress::IngressClient,
    shutdown_tx: broadcast::Sender<()>,
    relay_task: JoinHandle<anyhow::Result<()>>,
    gateway_task: JoinHandle<anyhow::Result<()>>,
}

#[allow(dead_code)]
pub struct TestProofAssistantHarness {
    pub client: proof_assistant::ProofAssistantClient,
    shutdown_tx: broadcast::Sender<()>,
    task: JoinHandle<anyhow::Result<()>>,
}

#[allow(dead_code)]
impl TestIngressHarness {
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(());
        self.relay_task
            .await
            .map_err(|err| anyhow::anyhow!(err))??;
        self.gateway_task
            .await
            .map_err(|err| anyhow::anyhow!(err))??;
        Ok(())
    }
}

#[allow(dead_code)]
impl TestProofAssistantHarness {
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(());
        self.task.await.map_err(|err| anyhow::anyhow!(err))??;
        Ok(())
    }
}

impl TestCommittee {
    pub fn single_validator() -> Self {
        let hot_key = ml_dsa_65_keypair_from_pkcs8(
            &base64::engine::general_purpose::STANDARD
                .decode(FIXED_SINGLE_VALIDATOR_HOT_PKCS8_B64)
                .expect("decode fixed validator hot key"),
        )
        .expect("load fixed validator hot key");
        let cold_key = ml_dsa_65_keypair_from_pkcs8(
            &base64::engine::general_purpose::STANDARD
                .decode(FIXED_SINGLE_VALIDATOR_COLD_PKCS8_B64)
                .expect("decode fixed validator cold key"),
        )
        .expect("load fixed validator cold key");
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
pub fn deterministic_wallet(wallet_store: Arc<WalletStore>) -> anyhow::Result<Wallet> {
    let signing_key_pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(FIXED_WALLET_SIGNING_PKCS8_B64)
        .expect("decode fixed wallet signing key");
    Wallet::from_private_material(wallet_store, &signing_key_pkcs8, FIXED_WALLET_LOCK_SEED)
}

#[allow(dead_code)]
pub fn install_deterministic_node_identity_keys(
    base_dir: &Path,
    slot: usize,
) -> anyhow::Result<()> {
    let (root_b64, auth_b64) = match slot {
        0 => (FIXED_NODE1_ROOT_PKCS8_B64, FIXED_NODE1_AUTH_PKCS8_B64),
        1 => (FIXED_NODE2_ROOT_PKCS8_B64, FIXED_NODE2_AUTH_PKCS8_B64),
        2 => (FIXED_NODE3_ROOT_PKCS8_B64, FIXED_NODE3_AUTH_PKCS8_B64),
        _ => anyhow::bail!("unsupported deterministic node identity slot {slot}"),
    };
    let identity_dir = base_dir.join("node_identity");
    fs::create_dir_all(&identity_dir)?;
    fs::write(
        identity_dir.join("node_root.p8"),
        base64::engine::general_purpose::STANDARD
            .decode(root_b64)
            .expect("decode fixed node root key"),
    )?;
    fs::write(
        identity_dir.join("node_auth.p8"),
        base64::engine::general_purpose::STANDARD
            .decode(auth_b64)
            .expect("decode fixed node auth key"),
    )?;
    Ok(())
}

#[allow(dead_code)]
pub fn reserve_udp_port() -> anyhow::Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

#[allow(dead_code)]
pub fn install_runtime_identity(
    base_dir: &Path,
    slot: usize,
    chain_id: [u8; 32],
    port: u16,
) -> anyhow::Result<NodeIdentity> {
    install_deterministic_node_identity_keys(base_dir, slot)?;
    let _ = unchained::node_identity::init_root_in_dir(base_dir)?;
    let addresses = vec![format!("127.0.0.1:{port}")];
    let (_, request) = unchained::node_identity::prepare_auth_request_in_dir(
        base_dir,
        protocol::CURRENT.version,
        Some(chain_id),
        addresses.clone(),
        None,
    )?;
    let (_, record) = unchained::node_identity::sign_auth_request_in_dir(base_dir, &request, 30)?;
    let _ = unchained::node_identity::install_node_record_in_dir(base_dir, &record)?;
    NodeIdentity::load_runtime_in_dir(
        base_dir,
        protocol::CURRENT.version,
        Some(chain_id),
        addresses,
    )
}

#[allow(dead_code)]
pub async fn spawn_test_ingress(
    root_dir: &Path,
    chain_id: [u8; 32],
    validator_control_base_path: &str,
) -> anyhow::Result<TestIngressHarness> {
    let relay_port = reserve_udp_port()?;
    let gateway_port = reserve_udp_port()?;
    let relay_dir = root_dir.join("access-relay");
    let gateway_dir = root_dir.join("submission-gateway");
    let relay_identity = install_runtime_identity(&relay_dir, 1, chain_id, relay_port)?;
    let gateway_identity = install_runtime_identity(&gateway_dir, 2, chain_id, gateway_port)?;
    let relay_record = relay_identity.record().clone();
    let gateway_record = gateway_identity.record().clone();

    let gateway_server = ingress::SubmissionGatewayServer::bind(
        &gateway_identity,
        vec![relay_record.clone()],
        SocketAddr::from(([127, 0, 0, 1], gateway_port)),
        validator_control_base_path,
        ingress::SubmissionGatewayPolicy::default(),
    )?;
    let relay_server = ingress::AccessRelayServer::bind(
        &relay_identity,
        vec![gateway_record.clone()],
        SocketAddr::from(([127, 0, 0, 1], relay_port)),
        ingress::AccessRelayPolicy::default(),
    )?;
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let relay_task = tokio::spawn({
        let shutdown_rx = shutdown_tx.subscribe();
        async move { relay_server.serve(shutdown_rx).await }
    });
    let gateway_task = tokio::spawn({
        let shutdown_rx = shutdown_tx.subscribe();
        async move { gateway_server.serve(shutdown_rx).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = ingress::IngressClient::new(
        relay_record,
        gateway_record,
        2 * 1024 * 1024,
        Duration::from_secs(5),
    )?;
    Ok(TestIngressHarness {
        client,
        shutdown_tx,
        relay_task,
        gateway_task,
    })
}

#[allow(dead_code)]
pub async fn spawn_test_proof_assistant(
    root_dir: &Path,
    chain_id: [u8; 32],
) -> anyhow::Result<TestProofAssistantHarness> {
    let port = reserve_udp_port()?;
    let assistant_dir = root_dir.join("proof-assistant");
    let assistant_identity = install_runtime_identity(&assistant_dir, 0, chain_id, port)?;
    let assistant_record = assistant_identity.record().clone();
    let server = proof_assistant::ProofAssistantServer::bind(
        &assistant_identity,
        SocketAddr::from(([127, 0, 0, 1], port)),
        proof_assistant::ProofAssistantPolicy::default(),
    )?;
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let task = tokio::spawn({
        let shutdown_rx = shutdown_tx.subscribe();
        async move { server.serve(shutdown_rx).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = proof_assistant::ProofAssistantClient::new(
        assistant_record,
        32 * 1024 * 1024,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )?;
    Ok(TestProofAssistantHarness {
        client,
        shutdown_tx,
        task,
    })
}

#[allow(dead_code)]
pub fn proof_fixture_dir() -> String {
    format!("{}/tests/proof-fixtures", env!("CARGO_MANIFEST_DIR"))
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
pub fn seed_wallet_with_coin_values(
    store: &Store,
    wallet: &Wallet,
    genesis: &Anchor,
    values: &[u64],
) -> anyhow::Result<Vec<Coin>> {
    let mut coins = seed_wallet_with_coins(store, wallet, genesis, values.len() as u64)?;
    for (coin, value) in coins.iter_mut().zip(values.iter().copied()) {
        coin.value = value;
        store.put("coin", &coin.id, coin)?;
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
    let tx = prepared.tx_with_proof(receipt);
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
