# Unchained Architecture

This document defines the canonical Unchained design.

It replaces the legacy mining, epoch-based proof-of-work, archive-receipt, and
"current implementation first" framing. If code in the repository disagrees
with this document, the code is transitional and should be changed.

## Product Definition

Unchained is a **private real-time settlement chain**.

It is built for:

- private payments
- private stable asset settlement
- treasury movement
- exchange and OTC inventory transfers
- private delegation and staking

It is **not** built to be:

- a mining chain
- a generic smart-contract chain
- a public mempool chain
- a messenger
- an "optional privacy" network

## Non-Negotiable Goals

- end-to-end privacy
- post-quantum safety
- deterministic finality
- lowest practical user-perceived latency
- simple wallet UX

## Core Architectural Decisions

- consensus is **shielded delegated proof of stake**
- ordering is **Mysticeti-class DAG BFT** with a **fast path for ordinary
  owned-note transfers**
- settlement state is a **shielded note/object ledger**
- staking is **public-validator / private-delegator**
- transport is **hybrid `X25519MLKEM768`**
- online validator signatures are **`ML-DSA`**
- cold recovery and emergency governance keys are **`SLH-DSA`**
- transaction validity uses **purpose-built transparent STARK-family proofs**
- the proving security budget is **conservative `>= 128-bit`**
- there is **no mining**
- there is **no public mempool**
- there is **no archive-query economy**
- there is **no reusable public payment address**

## What Best-In-Class Means Here

Unchained is not trying to win on generality.

It wins by combining four properties in one system:

1. private-by-default settlement
2. deterministic low-latency finality
3. credible post-quantum network and signature posture
4. wallet UX that does not force users to understand large PQ keys or public
   ledger addresses

That combination is the market gap.

## System Overview

Unchained has three layers:

1. `settlement layer`
2. `wallet addressability layer`
3. `operator and governance layer`

Only the first layer is consensus-critical.

## 1. Settlement Layer

The settlement layer is the chain.

It owns:

- transaction validity
- note commitments
- nullifiers
- validator-set transitions
- final ordering
- fees
- slashing outcomes

It does **not** own:

- human-readable identity
- contact discovery
- messaging
- wallet chat
- public account balances

### Settlement State Model

The canonical state is a shielded note/object model:

- spends consume existing notes
- spent notes are represented by nullifiers
- outputs create new encrypted notes
- note commitments are appended to a global authenticated structure
- there is no transparent balance table
- there is no public account model for ordinary users

Every transfer should be expressible as a note spend and note creation without
touching shared mutable user state.

That design is what enables both privacy and fast-path execution.

### Transaction Classes

Unchained supports two execution classes.

`Class A: ordinary private transfers`

- consume sender-controlled notes
- create new notes
- do not touch shared application state
- do not depend on public mempool ordering

`Class B: shared-state operations`

- validator-set changes
- private delegation and undelegation
- issuance and redemption flows
- governed system actions
- optional batch exchange or auction primitives

Class A exists to make the common payment path as fast as possible.

Class B exists because some actions are inherently shared-state and must go
through full consensus ordering.

### Privacy Invariant For Ordinary Payments

Ordinary payments are **not** a lower-privacy fast lane.

The fast path changes only the certification and ordering path. It does not
change the privacy surface.

For an ordinary shielded payment, the chain should see only:

- nullifiers
- new note commitments
- encrypted note ciphertexts
- a validity proof
- fee material, ideally shielded as well

The chain should not learn:

- sender identity
- recipient identity
- reusable payment address
- public balance
- invoice metadata
- payment graph metadata beyond what is unavoidable from state transition shape

Any optimization that requires exposing public sender, recipient, or ordering
metadata is outside the architecture.

### Consensus Design

Consensus is **stake-weighted delegated proof of stake** with a **small active
validator committee**.

Canonical design:

- `32` active validators per epoch
- deterministic slot and epoch schedule in consensus
- quorum certificates formed from explicit validator vote sets
- no heaviest-chain rule
- no probabilistic confirmation model
- finalized history is the only canonical history

The committee must stay small because PQ signatures are larger and more costly
than classical signatures. Small-committee BFT is the correct latency trade for
this product.

### Ordering And Finality

Unchained uses a **Mysticeti-class DAG ordering core** with a **Lutris-style
fast path** for ordinary transfers.

The design goal is:

- ordinary private payments finalize on the fast path whenever they only touch
  sender-owned notes
- shared-state operations finalize through the normal BFT path
- both paths produce deterministic finality

Operationally:

- validators disseminate transactions and batches through a DAG-style
  availability layer
- ordinary transfers take the shortest certification path that preserves
  safety
- contention, ambiguity, or shared-state access routes a transaction to the
  full ordering path automatically

This is the right architecture because Unchained is fundamentally a payment and
settlement system, not a general compute chain.

### Latency Targets

The target user experience is:

- ordinary private payment finality: `~250-700 ms` on a healthy WAN
- shared-state finality: `~500-1200 ms`
- sender-perceived payment completion, including proof generation and ingress:
  typically under `2 s`

These are design targets, not marketing guarantees. They are achievable only
because:

- the committee is small
- there is no mining
- there is no generic VM execution
- the common path is a native payment circuit
- the network does not depend on a public mempool

### Validator Selection And Time

Time is consensus state, not local operator policy.

Rules:

- slots and epochs are protocol-defined
- validator-set changes happen only at epoch boundaries
- proposer and scheduler selection are deterministic from finalized epoch state
- no PQ VRF is required for the base design

The protocol should not depend on non-standard PQ randomness gadgets when a
deterministic schedule is good enough.

### Certificates

Quorum certificates should use:

- validator bitmaps
- explicit validator IDs
- individual `ML-DSA` signatures

The base architecture does **not** depend on custom PQ signature aggregation.

That is deliberate. Unchained should prefer conservative, auditable, standard
components over clever compression schemes that weaken the PQ story.

## 2. Shielded Staking

Staking is native and shielded.

Properties:

- validators are public
- delegators are private
- delegated stake is represented as shielded pool-share notes
- rewards accrue through pool exchange rate movement, not public per-wallet
  reward credits
- slashing is public at the validator-pool level
- delegator ownership of the slashed pool remains shielded

This is the correct structure for a privacy chain because public validator
accountability and private user ownership can coexist.

### Delegation Model

Delegation produces a shielded note representing a claim on a validator pool.

That note:

- is private like any other note
- can be spent, restructured, or unbonded through native staking circuits
- does not reveal the delegator on-chain

Protocol-visible staking state is limited to:

- validator identity
- validator commission and metadata
- total bonded stake per validator
- slash events
- validator status

Per-user staking flows should never create a public relationship graph.

### Unbonding

Unbonding is required and protocol-defined.

It exists for safety, not for UX aesthetics.

The user-facing consequence is simple:

- transfers are fast
- stake exit is delayed

That is a correct trade.

## 3. Wallet Addressability Layer

The ledger does not use reusable public payment addresses.

Instead, wallets use a separate addressability layer built around:

1. `LocatorID`
2. private discovery
3. one-time payment capability negotiation
4. direct invoice links

### Locator

`LocatorID` is the public user-facing locator.

It is:

- short
- human-shareable
- not a ledger address
- not a receive key
- not a payment authorization object

Its only job is to let wallets find the recipient's private discovery record.

### Private Discovery

Wallets resolve locators through private discovery.

Requirements:

- constant-size queries
- constant-size responses
- PIR or equivalent private-discovery protection
- fixed-size directory records

The privacy model is:

- the directory may know a locator exists
- the directory should not learn which locator a given sender looked up

Hashed low-entropy identifiers are not a privacy primitive and are not a valid
substitute for private discovery.

### Handle Negotiation

Discovery yields encrypted mailbox material, not a reusable payment key.

The sender requests a one-time handle.

The receiver returns a **single-use `RecipientHandle`** that binds:

- chain
- asset policy
- amount policy or amount constraint
- expiry
- one-time receive capability
- one-time authorization key

Hard rules:

- the handle authorization key is fresh per handle or per invoice
- a mailbox key is never a payment key
- a discovery key is never a payment key
- a handle must not expose a wallet-global outward identity

The ledger sees only the final payment capability, not the wallet discovery
transcript.

### Direct Invoice Links

Unchained supports pre-minted invoice links.

That gives the system two clean UX modes:

- `wallet-to-wallet mode`: locator, private discovery, negotiated handle
- `merchant mode`: QR or link already contains a one-time `RecipientHandle`

This avoids making every payment depend on live bilateral negotiation.

## 4. Network Privacy Model

Unchained does not have a public mempool.

Wallets submit transactions through an ingress privacy layer.

Canonical flow:

1. wallet constructs a native shielded transaction
2. wallet submits over hybrid-encrypted transport to an ingress relay
3. relay diffuses the transaction into the validator network with small
   randomized delay and source separation
4. validators certify and finalize the transaction

Requirements:

- no public transaction-submission endpoint designed for global scraping
- no requester-linked archive receipts
- no wallet-private historical query telemetry in consensus objects
- no direct wallet-to-validator exposure as the default path

The system should accept a small amount of ingress delay in exchange for much
better source privacy.

### Low-Latency Metadata Defense

The main residual privacy risk for ordinary payments is network metadata:

- source IP
- first-seen timing
- wallet-to-validator linkage
- repeated submission-path linkage for the same wallet

The right fix is **role-separated ingress**, not a mixnet.

Canonical ingress roles:

1. `access relay`
2. `submission gateway`

The access relay:

- sees the client network identity
- sees only a padded encrypted envelope
- does not see plaintext transaction contents
- does not participate in consensus

The submission gateway:

- sees plaintext transaction contents
- sees validator-ingress peers
- does not see the client network identity

Hard rule:

- access relays and submission gateways must be independently operated and must
  not share operator control

This gives Unchained the same core privacy partitioning that makes oblivious
relay designs useful, but adapted to the chain's PQ transport and transaction
submission path.

### Timing Privacy Without Mixnet Latency

To reduce timing correlation without paying seconds of mixnet delay, ingress
must use all of the following:

- constant-size padded submission envelopes
- short fixed release windows at the submission gateway
- micro-batched validator ingress on a fixed cadence
- low-rate background wallet cover traffic while a wallet is online
- no direct wallet-to-validator submission in ordinary operation

The intended behavior is:

- the wallet sends immediately to an access relay
- the access relay forwards immediately to the submission gateway
- the submission gateway releases transactions on a short tick, e.g. tens of
  milliseconds rather than immediately on receipt
- validators admit transactions from gateway batches, not from raw wallet
  arrival timing

This preserves low latency while removing the sharpest source-timing signal.

### Why Not A Mixnet

A mixnet would improve metadata privacy further, but it is not the right base
design for Unchained because it pushes too much latency into the common payment
path.

Likewise, Dandelion-style transaction diffusion is better than naive broadcast
but not strong enough as the primary privacy layer for a sub-second settlement
product, because it still leaves meaningful first-seen and path-correlation
signals inside the validator network.

Role-separated ingress with fixed short release windows is the better default
trade.

### Light Client Sync

Wallets must be able to sync without asking the network which notes belong to
them.

The canonical model is:

- compact block data
- note ciphertexts
- note commitments
- nullifiers
- fuzzy message detection or equivalent compact wallet-side discovery tags

This gives Unchained the mobile-wallet property it needs:

- wallets can scan cheaply
- servers do not need ownership queries
- privacy does not depend on archive accounting tricks

## 5. Cryptography Profile

### Transport And Authentication

The default node transport profile is:

- QUIC
- TLS 1.3
- hybrid `X25519MLKEM768` key exchange
- `ML-DSA` validator and node authentication

This is the correct migration-era choice because it is robust if either the
classical or PQ component survives.

### Key Roles

Unchained must keep key roles separate:

- discovery identity key
- mailbox encryption key
- one-time payment capability key
- validator hot signing key
- cold governance / recovery key

Key reuse across these roles is an architectural bug.

### Cold Keys

Cold-path authority should use `SLH-DSA`.

Use cases:

- emergency governance approval
- root recovery
- validator cold authorization

Hot-path finality votes should remain on `ML-DSA` for performance.

### Proof System

The proving system is part of the security story, not a replaceable marketing
detail.

Canonical requirements:

- transparent STARK-family proofs
- no trusted setup
- conservative `>= 128-bit` security target
- native circuits for native actions
- no general-purpose zkVM in the steady-state critical path

The reason is straightforward:

- Unchained is not trying to support arbitrary contracts
- native circuits are faster to prove
- native circuits are easier to audit
- zkVM convenience is not worth weaker latency or weaker confidence here

### Native Circuits

The base chain should have native circuits for:

- private transfer
- private delegation
- private undelegation
- stake claim or reward realization
- issuance and redemption
- optional batch settlement primitives

This keeps proving latency low enough for ordinary users.

## 6. Execution Scope

Unchained should not launch as a general-purpose application platform.

Supported native actions:

- private transfer
- private staking
- private asset issuance and redemption
- threshold-governed system actions
- optional private batch exchange or RFQ settlement

Explicitly excluded:

- generic smart contracts
- public-order-flow AMMs
- public NFT markets
- public MEV auctions
- arbitrary user programs in consensus

This is not ideological. It is the shortest path to the best privacy, the best
latency, and the clearest product.

## 7. Economics

There is no mining economy.

Fees pay for:

- validator operation
- relay and ingress operation
- state growth
- proving verification costs

Economic design priorities:

- predictable fees
- low variance in confirmation experience
- no hashpower race
- no ASIC moat
- no miner extractive ordering market

## 8. User Experience Consequences

This architecture is chosen partly because of what it feels like to use.

The target user experience is:

- share a short locator or a QR invoice
- wallet resolves privately or consumes the invoice directly
- payment feels final in under a second when healthy
- recipient balance remains shielded
- counterparties and payment graph remain hidden by default
- mobile wallets sync without requesting ownership lookups from the network

Tradeoffs that are intentionally accepted:

- validator operation is more specialized than on a public PoW chain
- stake exits are delayed
- Unchained is narrower than a generic programmable L1

Those are correct tradeoffs for the product.

## 9. What Is Rejected

The following are outside the architecture:

- proof of work
- epoch-sealed mining
- heaviest-chain consensus
- public mempool design
- public-account staking
- public archive-receipt accounting
- optional privacy with a default transparent path
- reusable public payment addresses
- long-lived wallet-global outward payment identities
- general-purpose smart contracts in the base protocol
- general-purpose zkVM execution in the base protocol

## 10. Repository Direction

The repository should converge toward this shape:

- remove miner-specific architecture and binaries
- remove PoW, epoch-weight, and retarget logic
- remove requester-linked archive receipt and archive-accounting machinery
- replace the proving backend with native PQ-safe proof circuits
- replace direct or reusable receive identity surfaces with one-time capability
  flows everywhere
- align networking, README, tests, and CLI language to delegated PoS and
  private settlement

Legacy code that conflicts with this design is not a compatibility obligation.

## Decision

Unchained should be built as a **private real-time settlement chain with
shielded delegated PoS, Mysticeti-class BFT ordering, a fast path for ordinary
payments, private delegation, hybrid PQ transport, and transparent native
proofs**.

That is the best-in-class design for the stated goals.
