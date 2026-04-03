# Unchained

Unchained is a **private real-time settlement chain** built for **post-quantum
safety**.

The canonical design is:

- shielded delegated proof of stake
- Mysticeti-class DAG BFT ordering
- fast-path finality for ordinary private payments
- private delegation and staking
- hybrid `X25519MLKEM768` transport
- `ML-DSA` hot-path validator signatures
- `SLH-DSA` cold recovery and governance keys
- transparent STARK-family proofs with a conservative `>= 128-bit` target

Unchained is **not** a mining chain, **not** a generic smart-contract chain,
and **not** a public-mempool chain.

## Why Unchained Exists

The market already has:

- fast public chains
- privacy-oriented chains
- post-quantum research chains

It does **not** already have a strong answer for this product:

**sub-second confidential settlement with deterministic finality and a credible
post-quantum posture.**

That gap matters for:

- stablecoin settlement
- treasury movement
- payroll
- exchange inventory transfers
- OTC settlement
- merchant settlement without public counterparty graphs
- fintech wallets that cannot expose balances and transaction relationships on
  a public ledger

## Product Definition

Unchained is a specialized settlement rail.

It focuses on:

- private transfer
- private staking and delegation
- private asset issuance and redemption
- governed system actions
- optional private batch exchange or RFQ settlement

It does not aim to be:

- a general compute platform
- an EVM clone
- a public DeFi casino
- a mining economy

That narrower scope is deliberate. It is what makes the privacy, latency, and
PQ claims coherent.

## Canonical Design

### Consensus

Consensus is **shielded delegated proof of stake** with a **small active
validator committee**.

Key properties:

- deterministic finality
- no heaviest-chain race
- no probabilistic "wait for more confirmations" model
- no mining
- no hashpower market

Unchained uses a **Mysticeti-class DAG ordering core** and a **fast path for
ordinary owned-note transfers**. Shared-state actions such as staking changes
or governance actions fall back to the normal BFT path.

The fast path does not weaken payment privacy. Ordinary payments remain fully
shielded and should reveal only nullifiers, note commitments, ciphertexts, and
validity proof data.

### State Model

Unchained uses a **shielded note/object ledger**:

- spends consume notes
- nullifiers mark spent notes
- outputs create new encrypted notes
- note commitments are appended to a global authenticated structure
- there is no transparent balance table for ordinary users

### Staking

Validators are public. Delegators are private.

Delegation is represented by shielded pool-share notes rather than public stake
accounts. Rewards accrue through pool accounting, and slashing is public at the
validator-pool level without revealing the ownership graph of delegators.

### Wallet Addressability

Unchained does not expose reusable public payment addresses.

Wallet UX is built around:

1. short public `LocatorID`s
2. private discovery
3. one-time `RecipientHandle` negotiation
4. direct invoice links for merchant-style flows

The sender never needs to see large PQ key material, and the ledger never needs
to see a reusable outward identity.

### Network Privacy

There is no public mempool.

Wallets submit transactions through ingress relays over hybrid-encrypted
transport. The relay layer adds source separation and small randomized delay,
then diffuses transactions into the validator network.

The canonical network-metadata defense is a **two-role ingress path**:

- an `access relay` that sees client network identity but not transaction
  plaintext
- a `submission gateway` that sees transaction plaintext but not client network
  identity

Gateways release transactions on short fixed ticks using constant-size padded
envelopes and micro-batched validator ingress. That addresses source-timing and
first-seen leakage without mixnet-scale latency.

Wallet sync is based on compact chain data plus fuzzy note-detection tags and
local trial decryption, not requester-linked archive queries.

### Cryptography

- transport: `X25519MLKEM768`
- validator hot signatures: `ML-DSA`
- cold governance and recovery: `SLH-DSA`
- transaction proofs: transparent STARK-family proofs

Unchained does not depend on a trusted setup, a pure-PQ-only transport posture,
or a general-purpose zkVM in the steady-state critical path.

## User Experience Targets

The target experience is simple:

- share a short locator or invoice QR
- wallet resolves privately or consumes the invoice directly
- payment finalizes in under a second when the network is healthy
- the recipient, amount graph, and ownership graph remain shielded by default

The design target is:

- ordinary private payments: `~250-700 ms` finality on a healthy WAN
- shared-state operations: `~500-1200 ms`
- sender-perceived completion, including proof generation: typically under `2 s`

The tradeoffs are also deliberate:

- stake exits are delayed
- validator operation is specialized
- Unchained is narrower than a general-purpose L1

Those are the right tradeoffs for a private settlement product.

## What Is Out

The following are not part of the road ahead:

- proof of work
- mining binaries as a product surface
- epoch-sealed PoW anchors
- public archive-receipt accounting
- reusable public payment addresses
- optional privacy with a transparent default
- public-order-flow DeFi as the product center
- generic smart contracts in the base protocol

## Repository Status

The repository is in transition toward this design.

Legacy archive-accounting and some documentation surfaces still exist, but the
canonical chain-state path is no longer PoW- or miner-shaped and should be
read as validator/finality-first.

`ARCHITECTURE.md` is the source of truth for the road ahead.

The current foundation slice now includes:

- canonical validator-set and quorum-certificate objects
- validator derivation from real node-record hot keys with ML-DSA QC signature
  verification
- deterministic epoch/slot consensus state and leader selection
- public validator-pool objects with commission, metadata, total bonded stake,
  activation epoch, and status
- persisted active-committee snapshots plus deterministic top-stake committee
  selection at epoch boundaries
- leader-proposed checkpoint certification with explicit validator vote
  collection over the network
- finalized checkpoint objects that commit parent linkage, ordering path,
  committee hash, and quorum evidence
- finalized-history replay and sync rules based on contiguous checkpoint
  validation rather than heaviest-chain work
- deterministic candidate admission digests instead of PoW-based coin
  admission
- explicit transaction bodies for ordinary private transfer vs signed
  shared-state action
- executable validator-pool shared-state actions for registration and profile
  updates, authorized by the validator cold governance key
- removal of the public miner binary and miner-facing local control surface

Shared-state transaction execution now has a real canonical runtime for
validator-pool registration and profile updates. Those actions mutate the
public validator-pool state directly, remain off the ordinary transfer fast
path, and require explicit cold-governance authorization rather than being
routed through payment logic.

Checkpoint certification now requires a deterministic slot leader to propose an
`AnchorProposal`, gather validator votes, and assemble a quorum certificate
before a finalized checkpoint is produced. The remaining consensus gap is not
basic QC formation; it is DAG dissemination plus full shared-state BFT ordering
for delegation, undelegation, issuance, redemption, and governed slash flows.

Validator activation is now pulled from persisted validator-pool state rather
than inherited indefinitely from the parent checkpoint. What still does not
exist is the canonical source for those stake totals: shielded delegation /
undelegation notes and their native staking circuits.

## Build

Use a current stable Rust toolchain.

```bash
rustup update
cargo build
cargo test
```

## Docs

- [ARCHITECTURE.md](ARCHITECTURE.md): canonical target architecture
- [README.md](README.md): project overview and product direction
- [SHIELDED_POOL_V1.md](SHIELDED_POOL_V1.md): legacy shielded-pool notes that should be treated as historical context, not the target architecture
