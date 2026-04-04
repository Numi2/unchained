# State Of Unchained Task List

Unchained aims to be a state of the art blockchain that is e2e post quantum safe and privacy with uncompromising intent.

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

## Summary of Completed Work
See [COMPLETED_FEATURES.md](./COMPLETED_FEATURES.md) for detailed summaries.

- **Architecture & Product Scope**: Pivoted from PoW mining to private real-time settlement.
- **Consensus & Ordering**: Implemented BFT consensus, validator model, and quorum voting.
- **Shielded Staking & Fees**: Developed private staking, reward pools, and fee-paid control actions.
- **Wallet Addressability**: Implemented PIR-native discovery and one-time payment capabilities.
- **Network Privacy**: Deployed the two-role ingress model (access relay + submission gateway).
- **Wallet Sync**: Optimized for privacy-preserving compact light-client sync.
- **Proof System**: Introduced remote proof-assistant and canonical proof objects.
- **Testing**: Established multi-validator network and privacy-invariant tests.

---

## 1. Architecture And Product Scope

- `[ ]` Audit the rest of the Markdown docs and remove or relabel legacy PoW
  and archive-era claims

## 2. Remove Legacy PoW And Mining Architecture

- `[~]` Remove PoW-specific terminology from CLI help, config, metrics, and
  tests
- `[~]` Replace PoW bootstrap assumptions in persistence and replay code with
  validator-set bootstrap assumptions

## 3. Consensus And Ordering

- `[~]` Implement Mysticeti-class DAG dissemination and batch availability
  Batch parents, round/frontier reconstruction, quorum-round checkpoint
  proposals, and multi-validator DAG-order tests now exist. Richer
  multi-round scheduling and fallback behavior are still open.
- `[~]` Implement a fast path for ordinary owned-note transfers
  Ordinary transfers now stage into explicit fast-path batches and finalize
  only through leader-certified fast-path checkpoints; broader multi-validator
  proof-heavy coverage is still open.
- `[~]` Define automatic fallback from fast path to full BFT ordering for
  shared-state or contended transactions
  Duplicate-nullifier contention now deterministically routes ordinary
  transfers into the ordered DAG/BFT path, but end-to-end contention tests
  with real shielded proofs are still missing.
- `[~]` Define finality, fork-choice, and replay rules for deterministic BFT
  history
- `[~]` Define validator liveness, equivocation, and slashing evidence rules
  Conflicting proposals, validator votes, and validator-authored DAG batches
  now persist canonical equivocation evidence; finalized anchors also derive
  missed-vote liveness faults, and slashable evidence is now admitted through
  ordered shared-state penalty actions. Repeated-fault accumulation,
  jail/reactivation state, and committee exclusion/re-entry now derive from
  ordered accountability state. Broader liveness-fault classes and long-term
  policy evolution are still open.

## 4. Shielded Staking

- `[~]` Implement native circuits for delegation, undelegation, and stake claim
- `[ ]` Define wallet UX for delegation without exposing a public delegator
  graph

## 5. Shielded Payment Model

- `[~]` Shielded notes and nullifiers already exist, but they are still shaped
  by the old epoch/archive design
- `[ ]` Refactor the note model around the new settlement path rather than PoW
  anchor materialization
- `[~]` Keep ordinary transfers on a native fast path without revealing extra
  sender or recipient metadata
  Outward payment handles now mint one-time payment-capability signing keys and
  one-time ML-KEM receive keys, so ordinary recipients no longer expose a
  wallet-global outward identity through payment handles. Ordinary-path
  submission now goes through the real access-relay/submission-gateway ingress
  path with fixed-size hybrid-encrypted envelopes and short batched release
  windows. Wallets now emit low-rate online cover envelopes on a deterministic
  per-wallet cadence through the same ingress path.

## 6. Wallet Addressability

- `[~]` Recipient handles, PIR-native discovery, mailbox transport, and
  non-interactive ordinary locator delivery now exist, but the repository still
  needs full alignment to one-time capability semantics everywhere
  Public handles are now signed by per-handle payment-capability keys and carry
  per-handle ML-KEM receive keys rather than the wallet-global signing key.
  Offline locator sends now derive one-time owner identity from signed
  discovery descriptors instead of requiring mailbox liveness; deeper
  key-management audit, abuse controls, and performance hardening are still
  open.
- `[~]` Implement the discovery directory server with snapshot builder, PIR
  query executor, hot-swap snapshot rotation, and replica consistency checks
  The native server now builds signed snapshots, serves PIR queries, and
  refreshes its in-memory index after locator publication; clients now fail
  closed on cross-replica record mismatches, and signed snapshot bundles can
  now be exported into query-only replicas; broader operational rollout and
  mobile tuning are still open.
- `[~]` Implement signed snapshot publication and mirrorable discovery replicas
  so clients can verify they are querying the intended directory snapshot
  Signed manifests are now live and verified by clients, and wallet discovery
  reads can be cross-checked against configured mirrors. The node CLI now
  exports and imports signed snapshot bundles for query-only replica rollout,
  but wider operator distribution policy is still open.
- `[ ]` Benchmark and tune discovery row size, snapshot cadence, and PIR
  parameters for mobile-wallet latency and bandwidth targets
- `[ ]` Benchmark offline-receive scan overhead and descriptor-rotation
  parameters for mobile wallets
- `[~]` Remove any remaining long-lived receive-key assumptions from wallet UX
  and storage
  Internal self-change and staking-note outputs now derive deterministic
  one-time internal ML-KEM receive keys from wallet secret material and the
  transaction send seed, and outward handles now mint one-time payment
  capability keys plus one-time ML-KEM receive keys. PIR-native locator
  discovery, mailbox negotiation, and direct invoice flows are now wired into
  the wallet and CLI; the remaining work is a deeper key-management audit.

## 7. Proof System

- `[~]` The repository has a proving path today, but it does not match the
  target architecture
- `[~]` Remove dependence on the current prototype proving backend as the
  long-term integrity anchor
  Backend-specific receipt parsing and method/image identifiers are now
  contained within `src/proof.rs`, the canonical proof model now carries
  explicit backend identity, and the proof assistant now advertises backend
  capabilities and supported circuits. Proof routing now also runs through a
  canonical per-circuit backend policy instead of direct method wiring, and
  checkpoint history bindings now commit to backend-agnostic verifier-key
  digests instead of leaking raw zkVM method IDs into transaction-visible
  journals. Proof envelopes also bind a canonical statement digest for the
  decoded public journal, but the underlying proving backend is still the
  prototype engine and has not yet been replaced.
- `[~]` Define a native transparent STARK-family proving architecture
  The canonical proof layer now has an explicit circuit inventory for ordinary
  transfer, private delegation, private undelegation, unbonding claim, and
  checkpoint accumulator, each with a named public-input shape and a
  conservative `128-bit` minimum security budget. Proofs and proof-assistant
  transport now also carry explicit backend identity and capability manifests.
  Proof-facing note/nullifier/Merkle/checkpoint commitments now route through
  an algebraic proof-hash adapter in `proof-core` and `src/shielded.rs`, and
  ordinary transfer now prepares an explicit native-backend scaffold with
  separated public inputs, private witness material, envelope bindings, and
  trace layout before dispatching to the prototype backend. Ordinary transfer
  witnesses now also use deterministic full-history extensions from genesis
  rather than hidden checkpoint-accumulator receipts, and transfer journals no
  longer leak an accumulator verifier-key binding. The backend swap itself is
  still open.
- `[ ]` Set and document a conservative `>= 128-bit` security budget
- `[~]` Implement native circuits for transfer
  Ordinary transfer now has the first extracted native-backend boundary in
  `src/proof/native_transfer.rs`, including prepared public inputs, hidden
  witness plumbing, deterministic direct-history witness construction, and
  trace-layout scaffolding over extension record counts. The actual AIR,
  prover, and verifier are still missing.
- `[ ]` Implement native circuits for staking flows
- `[ ]` Implement native circuits for issuance and redemption
- `[ ]` Remove general-purpose zkVM assumptions from the steady-state critical
  path

## 8. Cryptography And Key Management

- `[ ]` Change the default transport profile to hybrid `X25519MLKEM768`
- `[ ]` Standardize online validator voting and authentication on `ML-DSA`
- `[ ]` Standardize cold recovery and emergency governance on `SLH-DSA`
- `[ ]` Separate discovery, mailbox, payment-capability, validator-hot, and
  validator-cold keys throughout the codebase
- `[ ]` Audit all repository key reuse against the canonical role separation

## 9. Execution Scope

- `[~]` Define the exact native action set for v1:
  private transfer, private staking, issuance/redemption, governed actions,
  and optional batch settlement
- `[ ]` Remove or quarantine abstractions that assume Unchained is a generic
  programmable L1

## 10. Config, CLI, And Operator Surface

- `[~]` Redesign config around validators, relays, gateways, and wallet
  services rather than miners and epoch PoW knobs
  Wallet ingress now has explicit `[ingress.wallet]`,
  `[ingress.access_relay]`, and `[ingress.submission_gateway]` config sections,
  and remote proving now has explicit `[proof_assistant.wallet]` and
  `[proof_assistant.server]` config sections, but broader validator/product
  cleanup is still open.
- `[~]` Redesign CLI language around validator operation and private settlement
  The CLI now has explicit `start-access-relay` and
  `start-submission-gateway` / `start-proof-assistant` commands alongside
  cold-signed validator control document flows, but broader operator-language
  cleanup is still open.
- `[~]` Remove legacy config keys that control PoW, epoch seconds, archive
  provider behavior, or mining workflows
- `[~]` Define operational ceremonies for validator hot/cold keys and ingress
  operator separation
  Runtime role separation is now enforced by distinct ingress services and
  identity checks, but the operator ceremony docs are still missing.
- `[~]` Add discovery-directory operator config, PIR parameter selection, and
  signed snapshot publication ceremonies
  Discovery now exposes live operator status over the discovery transport and
  the node CLI can inspect manifest / queue depth / PIR envelope state from a
  running service. The node CLI can also export signed snapshot bundles and
  import them into query-only replicas; broader operator rollout policy and
  mobile parameter tuning are still open.

## 11. Tests And Verification

- `[~]` Replace PoW/miner/epoch integration tests with validator/BFT/finality
  integration tests
- `[~]` Add tests for ordinary-payment fast-path privacy invariants
  Batch/routing unit coverage exists and the ignored ordinary-payment proving
  soak now verifies fast-path finalization semantics; richer privacy-invariant
  coverage is still open.
- `[~]` Add tests for fallback from fast path to full BFT ordering
  Deterministic aggregation tests now lock contention filtering, but an
  end-to-end contended ordinary-payment proof test is still missing.
- `[~]` Add tests for private delegation and unbonding flows
- `[~]` Add tests for ingress role separation and metadata-handling invariants
  The suite now covers fixed-size envelope round trips, role-separation
  rejection, ordinary shielded payment ingress, and fee-paid wallet-control
  submission through the real relay/gateway path. Scheduled cover traffic is
  now verified to avoid transaction persistence and finalized-anchor movement.
  Broader metadata-handling invariants are still open.
- `[~]` Add tests for compact wallet sync and fuzzy detection
  The suite now covers the compact wallet-state stream boundary directly:
  note-tree-only churn changes the explicit runtime snapshot but does not
  perturb the compact wallet-state stream, wallet-control observation rebuilds
  correctly from the compact head-plus-delta path, and node-control now has a
  direct cursor/paging test for compact wallet deltas. A remote-wallet ingress
  test now also verifies compact head/delta pagination and wallet-side balance
  recovery without a local node-control client. Remote ingress coverage now
  also verifies ordinary-send witness preparation, private-delegation witness
  preparation, and fee-paid validator-registration submission without a local
  node-control client. Remote proof-assistant coverage now also verifies
  direct wallet and wallet-control fee-paid registration submission without a
  local prover. Broader compact detection coverage can still be expanded.
- `[~]` Add end-to-end tests for PIR discovery
  Cover fixed-size manifest and row encodings, candidate-slot derivation,
  constant-shape queries and responses, authenticated row verification,
  mailbox bootstrap decoding, negotiated-handle completion, snapshot rotation,
  and failure handling under stale manifests or malformed rows.
  The suite now covers publish/resolve/mailbox completion, negotiated
  amount-bound handles, mirrored-replica mismatch detection, anonymous
  query-budget enforcement, and signed snapshot bundle rollout into a
  query-only replica; malformed-row and stale-manifest coverage are still
  open.
- `[~]` Add privacy-invariant tests for discovery abuse controls
  The suite now verifies manifest-bound anonymous query-budget proof
  enforcement, but broader leakage and tuning coverage is still open.
  Query budgeting, retries, relaying, and operator telemetry must not re-link
  locator resolution to a wallet identity or degrade PIR query privacy.
- `[ ]` Add proof-system tests aligned to the new native circuits
  The suite now includes canonical circuit-inventory and proof-assistant
  capability-manifest coverage, but native-circuit proof tests are still open.

---

## Explicitly Out Of Scope

- `[x]` Proof of work
- `[x]` Mining as a long-term product surface
- `[x]` Public archive-receipt economics
- `[x]` Reusable public payment addresses
- `[x]` Optional privacy with a transparent default
- `[x]` Generic smart contracts in the base protocol
