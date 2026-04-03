# State Of Unchained Task List

This file tracks the concrete work required to move the repository to the
canonical Unchained design described in `ARCHITECTURE.md`.

The canonical direction is:

- private real-time settlement chain
- shielded delegated proof of stake
- Mysticeti-class DAG BFT ordering
- fast path for ordinary private payments
- private delegation and staking
- hybrid PQ transport
- native transparent proof system

Legacy proof-of-work, miner, epoch-anchor, archive-accounting, and
implementation-specific surfaces still present in the repository are
transitional and should be removed rather than preserved.

## Status Legend

- `[x]` decided or documented
- `[~]` partially present in the repository but not in canonical form
- `[ ]` not started or not yet aligned to the target architecture

## 1. Architecture And Product Scope

- `[x]` Canonical product direction rewritten around private real-time
  settlement rather than mining
- `[x]` `ARCHITECTURE.md` updated to make shielded delegated PoS, low-latency
  BFT ordering, and private delegation the source of truth
- `[x]` `README.md` aligned to the same product and consensus direction
- `[x]` Ordinary fast-path payments explicitly defined as privacy-preserving,
  not a lower-privacy shortcut
- `[x]` Network-metadata caveat addressed with a low-latency two-role ingress
  design rather than a mixnet
- `[ ]` Audit the rest of the Markdown docs and remove or relabel legacy PoW
  and archive-era claims

## 2. Remove Legacy PoW And Mining Architecture

- `[x]` Remove epoch-based proof-of-work from the protocol model
- `[x]` Remove miner-specific control-plane flows and miner-facing wallet/node
  interfaces
- `[x]` Remove heaviest-chain, anchor-weight, retarget, and candidate-admission
  logic
- `[x]` Remove `unchained_miner` as a product-facing binary
- `[~]` Remove PoW-specific terminology from CLI help, config, metrics, and
  tests
- `[~]` Replace PoW bootstrap assumptions in persistence and replay code with
  validator-set bootstrap assumptions

## 3. Consensus And Ordering

- `[x]` Define the canonical validator-set object model
- `[x]` Define epoch boundaries, slot timing, and validator rotation as
  consensus rules
- `[x]` Implement deterministic leader-gated checkpoint proposal and validator
  vote wire flow
- `[x]` Implement stake-weighted committee membership for a small active
  validator set
- `[x]` Implement quorum-certificate formation using `ML-DSA` validator votes
- `[~]` Implement Mysticeti-class DAG dissemination and batch availability
  Batch parents, round/frontier reconstruction, quorum-round checkpoint
  proposals, and multi-validator DAG-order tests now exist. Richer
  multi-round scheduling and fallback behavior are still open.
- `[ ]` Implement a fast path for ordinary owned-note transfers
- `[ ]` Define automatic fallback from fast path to full BFT ordering for
  shared-state or contended transactions
- `[~]` Define finality, fork-choice, and replay rules for deterministic BFT
  history
- `[ ]` Define validator liveness, equivocation, and slashing evidence rules

## 4. Shielded Staking

- `[x]` Define validator registration and validator metadata objects
- `[x]` Implement validator registration and validator-profile shared-state
  execution with cold-governance authorization
- `[x]` Define shielded delegation notes or pool-share notes
- `[x]` Define private undelegation and unbonding flows
- `[x]` Define shielded staking note semantics
- `[ ]` Define reward accrual through pool accounting rather than public
  per-wallet rewards
- `[ ]` Define slash handling at the validator-pool level while keeping
  delegator ownership shielded
- `[~]` Implement native circuits for delegation, undelegation, and stake claim
- `[ ]` Define wallet UX for delegation without exposing a public delegator
  graph

## 5. Shielded Payment Model

- `[~]` Shielded notes and nullifiers already exist, but they are still shaped
  by the old epoch/archive design
- `[ ]` Refactor the note model around the new settlement path rather than PoW
  anchor materialization
- `[ ]` Define fee handling so ordinary private payments do not need a
  transparent payment path
- `[ ]` Keep ordinary transfers on a native fast path without revealing extra
  sender or recipient metadata
- `[x]` Define native transaction classes clearly: ordinary transfer vs
  shared-state operation
- `[ ]` Remove legacy archive-query assumptions from wallet spend and sync
  flows

## 6. Wallet Addressability

- `[~]` Recipient handles exist, but the repository still needs full alignment
  to one-time capability semantics everywhere
- `[ ]` Enforce fresh one-time outward payment authorization keys per handle or
  invoice
- `[ ]` Ensure no wallet-global outward identity key is exposed in payment
  handles
- `[ ]` Define `LocatorID`, private discovery, mailbox records, and negotiated
  handle flows
- `[ ]` Define direct invoice links as a first-class merchant path
- `[ ]` Keep discovery keys, mailbox keys, payment capability keys, and wallet
  root keys strictly separated
- `[ ]` Remove any remaining long-lived receive-key assumptions from wallet UX
  and storage

## 7. Network Privacy And Ingress

- `[ ]` Implement the two-role ingress model:
  `access relay` plus `submission gateway`
- `[ ]` Enforce operator separation between access relays and submission
  gateways
- `[ ]` Use constant-size padded submission envelopes
- `[ ]` Use short fixed release windows and micro-batched validator ingress
- `[ ]` Add low-rate online wallet cover traffic without turning the product
  into a high-latency anonymity network
- `[ ]` Remove direct wallet-to-validator submission as the ordinary path
- `[ ]` Define relay abuse controls and rate limiting that do not destroy source
  privacy

## 8. Wallet Sync And Light Clients

- `[ ]` Replace archive-receipt and requester-linked historical-query flows
  with compact light-client sync
- `[ ]` Define compact chain data for wallet scanning
- `[ ]` Use fuzzy note-detection tags or an equivalent compact probabilistic
  detection mechanism
- `[ ]` Keep final ownership detection wallet-local through trial decryption or
  equivalent local processing
- `[ ]` Make mobile-wallet sync cheap without exposing ownership queries to the
  network

## 9. Proof System

- `[~]` The repository has a proving path today, but it does not match the
  target architecture
- `[ ]` Remove dependence on the current prototype proving backend as the
  long-term integrity anchor
- `[ ]` Define a native transparent STARK-family proving architecture
- `[ ]` Set and document a conservative `>= 128-bit` security budget
- `[ ]` Implement native circuits for ordinary transfer
- `[ ]` Implement native circuits for staking flows
- `[ ]` Implement native circuits for issuance and redemption
- `[ ]` Remove general-purpose zkVM assumptions from the steady-state critical
  path

## 10. Cryptography And Key Management

- `[ ]` Change the default transport profile to hybrid `X25519MLKEM768`
- `[ ]` Standardize online validator voting and authentication on `ML-DSA`
- `[ ]` Standardize cold recovery and emergency governance on `SLH-DSA`
- `[ ]` Separate discovery, mailbox, payment-capability, validator-hot, and
  validator-cold keys throughout the codebase
- `[ ]` Audit all repository key reuse against the canonical role separation

## 11. Execution Scope

- `[x]` General-purpose smart contracts rejected as the base protocol direction
- `[x]` Public mempool DeFi rejected as the base product direction
- `[~]` Define the exact native action set for v1:
  private transfer, private staking, issuance/redemption, governed actions,
  and optional batch settlement
- `[ ]` Remove or quarantine abstractions that assume Unchained is a generic
  programmable L1

## 12. Config, CLI, And Operator Surface

- `[ ]` Redesign config around validators, relays, gateways, and wallet
  services rather than miners and epoch PoW knobs
- `[ ]` Redesign CLI language around validator operation and private settlement
- `[~]` Remove legacy config keys that control PoW, epoch seconds, archive
  provider behavior, or mining workflows
- `[ ]` Define operational ceremonies for validator hot/cold keys and ingress
  operator separation

## 13. Tests And Verification

- `[~]` Replace PoW/miner/epoch integration tests with validator/BFT/finality
  integration tests
- `[x]` Add a multi-validator proposer-to-QC network test for finalized
  checkpoint certification
- `[x]` Add a multi-validator DAG frontier/finalization test for shared-state
  ordering
- `[x]` Add signed shared-state validator registration/profile-update tests
- `[x]` Add ordered shared-state batch finalization tests for validator
  lifecycle actions
- `[ ]` Add tests for ordinary-payment fast-path privacy invariants
- `[ ]` Add tests for fallback from fast path to full BFT ordering
- `[~]` Add tests for private delegation and unbonding flows
- `[ ]` Add tests for ingress role separation and metadata-handling invariants
- `[ ]` Add tests for compact wallet sync and fuzzy detection
- `[ ]` Add proof-system tests aligned to the new native circuits

## 14. Immediate Next Steps

- `[~]` Remove the mining/PoW architecture from protocol definitions and docs
  that still reference it
- `[x]` Define the validator-set and quorum-certificate data structures
- `[x]` Define the native transaction classes and fast-path eligibility rules
- `[x]` Define shielded delegation-share notes and a native private-delegation
  proof path
- `[x]` Define private undelegation and delayed-claim shared-state actions
- `[x]` Define shielded staking note semantics
- `[ ]` Define the two-role ingress wire model
- `[ ]` Define the replacement proof architecture and circuit inventory

## 15. Explicitly Out Of Scope

- `[x]` Proof of work
- `[x]` Mining as a long-term product surface
- `[x]` Public archive-receipt economics
- `[x]` Reusable public payment addresses
- `[x]` Optional privacy with a transparent default
- `[x]` Generic smart contracts in the base protocol
