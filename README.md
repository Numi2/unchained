# Unchained

Unchained is a specialized cryptographic settlement network engineered for post-quantum security, sub-second deterministic finality, and end-to-end privacy. By combining a Mysticeti-class Directed Acyclic Graph (DAG) Byzantine Fault Tolerant (BFT) ordering core with a shielded note-based state model, Unchained achieves real-time settlement without exposing transaction graphs, participant identities, or public balances. The architecture strictly excludes general-purpose computation, public mempools, and proof-of-work mechanisms, optimizing exclusively for the latency and privacy requirements of institutional treasury movement, stablecoin settlement, and confidential financial operations.

## 1. Cryptographic Primitives and Transport Security

The network employs a hybrid cryptographic posture, adhering to NIST post-quantum standardization guidelines while maintaining classical security fallbacks.

- **Transport Layer**: Network communication utilizes a hybrid `X25519` and `ML-KEM-768` key encapsulation mechanism over TLS 1.3 and QUIC. This ensures forward secrecy against both classical and quantum adversaries.
- **Consensus Authentication**: Validator hot-path signatures for quorum certificates and block proposals rely on `ML-DSA`, providing efficient post-quantum authentication for high-frequency consensus operations.
- **Cold Storage and Governance**: As part of the target architecture, high-value, low-frequency operations such as root recovery, validator authorization, and emergency governance are designated to utilize `SLH-DSA` (Stateless Hash-Based Digital Signature Algorithm), prioritizing conservative security assumptions over signature size.

## 2. Consensus Architecture: Shielded Delegated Proof of Stake

Unchained implements a stake-weighted Delegated Proof of Stake (DPoS) consensus mechanism with a restricted active validator committee (typically 32 nodes) to accommodate the bandwidth overhead of post-quantum signatures.

### DAG BFT Ordering and Fast-Path Finality

The consensus protocol utilizes a Mysticeti-class DAG ordering core. To minimize latency for standard operations, Unchained implements a bifurcated execution model:

- **Class A (Fast Path)**: Ordinary private transfers that consume only sender-controlled notes bypass full DAG ordering. These transactions achieve deterministic finality in approximately 250–700 milliseconds by taking the shortest safe certification path.
- **Class B (BFT Fallback)**: Shared-state operations, including validator-set transitions, private delegation, and asset issuance, are routed through the full BFT ordering path, achieving finality in 500–1200 milliseconds. Contended fast-path transactions deterministically degrade to this path.

The protocol enforces deterministic finality. Probabilistic confirmation models, heaviest-chain rules, and mining are explicitly excluded.

## 3. State Model and Privacy Invariants

The canonical ledger state is a shielded note and object model. There are no transparent balance tables or public account structures.

- **State Transitions**: Transactions consume existing encrypted notes and produce new encrypted notes. Spent notes are irrevocably marked by cryptographically secure nullifiers.
- **Privacy Preservation**: For ordinary payments, the network observes only nullifiers, note commitments, encrypted ciphertexts, and zero-knowledge validity proofs. Sender identity, recipient identity, transaction amounts, and the broader payment graph remain cryptographically shielded.
- **Shielded Staking**: Delegation is represented by shielded pool-share notes. Rewards accrue via pool exchange rate adjustments rather than public per-wallet credits. Slashing is executed at the validator-pool level, preserving the anonymity of individual delegators.

## 4. Stateless PIR-Native Addressability

Unchained eliminates reusable public payment addresses to prevent off-chain transaction graph analysis. Wallet addressability is achieved through a Private Information Retrieval (PIR) subsystem.

- **Locator Resolution**: Users share short, human-readable `LocatorID`s. Wallets resolve these locators via a stateless single-server PIR query against a directory of fixed-size authenticated records.
- **Cryptographic Unlinkability**: The PIR protocol ensures the directory server cannot determine which `LocatorID` a client is querying.
- **Offline Receive Descriptors**: The PIR response yields an offline receive descriptor containing an `ML-KEM` public key and policy constraints. Senders construct shielded outputs using this descriptor, enabling asynchronous payments without live negotiation. Wallets can also explicitly rotate or compromise-rotate that descriptor without changing the outward locator.
- **One-Time Capabilities**: For policy-bound flows, the PIR payload bootstraps the negotiation of a single-use `RecipientHandle`, ensuring payment authorization keys are never reused.

## 5. Network Metadata Privacy

To mitigate traffic analysis and source-IP correlation, Unchained replaces the standard public mempool with a role-separated ingress architecture.

- **Access Relays**: Receive padded, encrypted transaction envelopes from clients. They observe the client's network identity but cannot decrypt the transaction payload.
- **Submission Gateways**: Receive envelopes from access relays, decrypt the payloads, and interface with the validator network. They observe the transaction plaintext but have no visibility into the originating client's network identity.
- **Timing Obfuscation**: Gateways enforce short, fixed release windows and micro-batched validator ingress. Wallets emit deterministic background cover traffic to obfuscate submission timing.

## 6. Computational Integrity and Proof System

Transaction validity is enforced through purpose-built, transparent STARK-family zero-knowledge proofs.

- **Security Budget**: The proof system targets a conservative minimum security level of $\ge 128$ bits.
- **Trusted Setup**: The architecture strictly requires transparent proof systems, eliminating the need for a trusted setup phase.
- **Native Circuits**: To maintain sub-second proving latency, Unchained utilizes highly optimized native circuits for core operations (transfer, delegation, unbonding, issuance) rather than relying on general-purpose zkVM execution in the critical path.

## Repository Status and Build Instructions

The repository is currently transitioning toward the architecture defined above. Legacy components (e.g., Proof-of-Work artifacts, archive-receipt accounting) are deprecated. `ARCHITECTURE.md` serves as the definitive specification.



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
- e2e post quantum safe, with hybrid capabilities to follow best practices of NIST.
- uncompromissable state of the art Privacy

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
3. offline receive descriptors for ordinary private transfers
4. one-time `RecipientHandle` negotiation for policy-bound receive flows
5. direct invoice links for merchant-style flows

From day one, private discovery is implemented as a **stateless PIR service**.
The discovery directory stores **fixed-size signed discovery records** and
publishes a **signed manifest** carrying the PIR parameter set, and answers
only PIR-shaped queries, so it can help a sender resolve a short locator
without learning which locator was looked up. Discovery returns mailbox
bootstrap material together with a signed offline receive descriptor. Ordinary
locator payments use that descriptor directly, so wallet-to-wallet sends remain
asynchronous even when the recipient is offline. Negotiated one-time
`RecipientHandle`s remain for flows that need explicit recipient authorization,
request-specific policy, or invoice semantics. Wallets can also verify locator
resolution against multiple configured discovery mirrors, and negotiated
handles or direct invoices can bind an exact requested amount when the receive
flow requires it. Discovery operators can inspect the live manifest, PIR
envelope, manifest dataset ID, snapshot epoch, and mailbox queue state through
`unchained_node discovery-status`. Discovery queries can also be gated by an
anonymous manifest-bound query-budget proof, and operators can export signed
snapshot bundles into query-only mirrors with `unchained_node
discovery-export-snapshot` and `unchained_node discovery-import-snapshot`.

The sender never needs to see large PQ key material, and the ledger never needs
to see a reusable outward identity.

Unchained therefore has no mailbox round-trip on the ordinary locator path, but
it still preserves handles and invoices where recipient-controlled constraints
matter.

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
PIR is used for **addressability lookup**, not for ordinary receive-side note
scanning.

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
- wallet resolves privately, optionally cross-checks discovery mirrors, or
  consumes the invoice directly
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
- persisted consensus-accountability evidence for conflicting anchor proposals,
  conflicting validator votes, conflicting validator-authored DAG batches, and
  finalized-QC-derived missed-vote liveness faults
- content-addressed shared-state batch dissemination and batch retrieval for
  validator-ordered actions
- finalized checkpoint objects that commit parent linkage, ordering path,
  committee hash, ordered shared-state batch root/count, and quorum evidence
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
validator-pool registration, profile updates, private delegation,
private undelegation, and unbonding claims. Those actions are staged pending
order, diffused as validator-authored shared-state DAG batches, reconstructed
into a deterministic quorum round/frontier plan, committed into finalized
checkpoints by explicit DAG frontier plus ordered batch list, and only then
applied to public validator-pool state plus shielded note state. Shared-state
execution no longer mutates canonical state on gossip arrival.

Checkpoint certification now requires a deterministic slot leader to propose an
`AnchorProposal`, gather validator votes, and assemble a quorum certificate
before a finalized checkpoint is produced. Shared-state ordering now has a real
round/parent/frontier structure with availability-driven leader proposals over
quorum DAG rounds. Ordinary private payments now also take a real canonical
fast path: nodes stage ordinary shielded transfers into explicit fast-path
batches, leaders finalize only those batch commitments, and duplicate-nullifier
contention deterministically diverts the contended transfer set into the full
ordered DAG/BFT path instead of letting it race the fast path.

The remaining consensus gap is narrower: richer multi-round DAG scheduling,
stronger end-to-end coverage for proof-heavy fast-path/fallback flows across
multiple validators, and broader liveness/accountability policy beyond the
current deterministic equivocation-plus-missed-vote schedule.

Validator activation is now pulled from persisted validator-pool state rather
than inherited indefinitely from the parent checkpoint. The staking lifecycle
now has real private delegation and undelegation semantics: delegation-share
notes carry pool shares rather than plain stake amount, undelegation burns
those shares into delayed unbonding-claim notes, and mature claims have a
native redemption proof path back into ordinary payment notes.

Shared-state staking transactions now expose their embedded shielded transfers
to wallet scanning rather than disappearing behind the shared-state wrapper.
Full zk proving remains available for delegation and the new staking actions,
but the heavy proving paths stay in explicit soak coverage rather than routine
test targets.

Accountability is now enforceable on-chain. Finalized anchors derive missed-vote
liveness-fault records directly from the quorum certificate, slashable evidence
is admitted through ordered shared-state transactions rather than ad hoc local
operator action, and validator-pool penalties reduce bonded stake while leaving
delegation-share ownership intact so delegator ownership remains shielded even
when a pool is slashed. Repeated faults now accumulate in canonical validator
state, liveness or safety faults can jail validators out of future committees,
cold-governance reactivation returns a served jail term back to pending
activation, and repeated safety faults retire the pool permanently. Finalized
committee snapshots remain persisted for finalized epochs, but future committee
selection is derived from current ordered validator-pool state rather than
being frozen by speculative reads.

Reward accrual now follows the same canonical validator-pool state machine.
Each finalized anchor settles per-validator rewards directly into pool state,
missed-vote or jailed/retired validators are suppressed automatically, validator
commission is reserved inside the pool without creating public per-wallet reward
credits, and delegation-share value rises only through claimable pool stake.
That makes undelegation and delayed claim redemption realize rewards through the
pool exchange rate rather than through a separate public reward balance.

Fee material now follows that same path instead of escaping into a transparent
side channel. Ordinary private transfers, private delegation, private
undelegation, and mature unbonding claims all carry explicit fee amounts inside
their shielded proof balance equations, and finalized anchors apportion the
exact finalized fee pot back into validator pools alongside the base protocol
reward. Fees therefore stay private at submission time while still landing in
the same pool-accounting reward path that drives delegation economics.

The same private fee model now extends to ordered shared-state control actions.
Validator registration, validator profile updates, penalty-evidence admission,
and validator reactivation can carry a separate shielded fee-payment sidecar,
and node-control status now exposes the latest finalized reward split as
protocol reward plus fee reward rather than a single opaque total. Wallet
history likewise records fee amounts explicitly for sent transfers.

Internal self-change and staking-note outputs now use deterministic one-time
ML-KEM receive keys derived from wallet secret material plus the transaction
send seed rather than random long-lived internal receive-key minting. That
keeps self-addressed outputs private without relying on mutable wallet-global
receive-key state.

The operator path for those control actions is now explicit. `unchained_node`
can build cold-signed validator registration, profile-update, reactivation, and
penalty-evidence control documents using the canonical local node root as the
validator cold-governance key, and `unchained_wallet` can submit those
documents through wallet-control with a private fee sidecar instead of relying
on a local zero-fee exception.

The fee-paid control-path test harness is now deterministic as well. Fresh
single-action staking tests can seed a single high-value genesis note, internal
change keys are derived deterministically, the single-validator and
deterministic multivalidator shielded fee witnesses now have committed cached
transparent receipts, and fresh fee-paid staking-control tests can execute
without re-proving those witnesses on every run. Routine verification now uses
fast local staking state-machine tests for accountability and pool-state
transitions, multivalidator ordered-control coverage in `pq_network`, and the
wallet-control end-to-end fee-paid registration flow. The validator transport
path also carries explicit QUIC keep-alive and idle-timeout policy instead of
relying on library defaults.

Outward payment handles are now true one-time capability documents. Each minted
handle carries a fresh payment-capability signing key plus a fresh ML-KEM
receive key, and the wallet-global signing identity is no longer exposed or
reused across outward payment handles.

Wallet checkpoint refresh also no longer depends on requester-linked historical
extension queries through node control. The wallet now derives historical
unspent extensions locally from the current shielded archive/runtime material.
Separately, ordinary wallet observation now runs from a compact node-control
scan head plus paged deltas. The wallet persists a compact scan cursor,
requests only the next bounded range of committed genesis coins and compact
shielded outputs, uses the existing `view_tag` as the probabilistic detection
tag, and keeps final ownership detection wallet-local through trial
decryption. The same compact head/delta protocol now also runs over the
role-separated relay/gateway transport, so compact wallet refresh no longer
requires a colocated node-control socket. Sender-side proving and checkpoint
refresh now use a smaller send-runtime material bundle carrying the compact
head, validator pools, note-tree root state, root ledger, and archived
nullifier epochs over either node control or relay/gateway ingress, so normal
wallet prepare/prove/submit flows no longer depend on a local node-control
socket either. Sender-side proving can now also be offloaded to a distinct
`unchained_node start-proof-assistant` role over a separate hybrid-encrypted
transport, so remote/mobile wallets no longer need a colocated prover to build
ordinary sends, private staking flows, shared-state fee payments, or
checkpoint-accumulator receipts. The heavyweight full shielded runtime snapshot
remains only as an explicit local/test utility.

Those send, staking, ingress, and proof-assistant paths now also use a
canonical `TransparentProof` object with an explicit statement kind instead of
passing raw backend receipt bytes through transaction and wallet state. Receipt
decoding, adapter-local verifier artifacts, and prototype-proof cache
serialization now live behind `src/proof.rs`, which keeps the steady-state
protocol and wallet model stable while the proving backend is replaced.

That proof boundary now carries an explicit canonical circuit inventory as
well: ordinary transfer, private delegation, private undelegation, unbonding
claim, and checkpoint accumulator are named circuit slots with a conservative
`128-bit` minimum security budget and explicit public-input shapes. The
prototype backend is still internal to `src/proof.rs`, but the rest of the
system now reasons about circuit identity rather than backend method constants.
Checkpoint history bindings also commit only to a verifier-key digest, so raw
zkVM method identifiers no longer leak into transaction-visible journals.

The proof layer now also carries explicit backend identity and capability
manifests. Canonical proofs include their backend, circuit, and statement
metadata, and the remote proof assistant can advertise the exact backend and
supported circuit inventory before serving witness requests. Canonical proof
metadata also treats seal bytes as opaque adapter output rather than naming a
specific receipt serialization format. That keeps the wallet and transport
model stable while the first native transparent backend is introduced behind
the same interface.

Backend selection is now also routed through a canonical per-circuit backend
policy inside `src/proof.rs` rather than hard-coded directly into every
prove/verify path. The current policy still maps every supported circuit to the
prototype backend, but swapping in the first native backend no longer requires
rewiring wallet, assistant, or transaction logic.

Ordinary-path submission now runs through the real two-role ingress boundary.
`unchained_node start-access-relay` and `unchained_node start-submission-gateway`
host distinct ingress roles, `unchained_wallet serve` submits through configured
relay/gateway records instead of direct validator submission, and the ingress
wire path uses hybrid X25519+ML-KEM768 sealing, fixed-size padded envelopes,
short release windows, and micro-batched validator ingress. While the wallet is
online, `unchained_wallet serve` now also emits low-rate cover envelopes on a
deterministic per-wallet cadence through the same relay/gateway path; the
submission gateway drops those covers before validator admission so they add
metadata noise without polluting consensus state.

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
