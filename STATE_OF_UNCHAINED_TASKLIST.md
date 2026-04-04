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

## 1. Architecture And Product Scope

- `[x]` Canonical product direction rewritten around private real-time
  settlement rather than mining
- `[x]` `ARCHITECTURE.md` updated to make shielded delegated PoS, low-latency
  BFT ordering, and private delegation the source of truth
- `[x]` `README.md` aligned to the same product and consensus direction
- `[x]` Canonicalize PIR-native private discovery in the architecture, README,
  and development map
- `[x]` Ordinary fast-path payments explicitly defined as privacy-preserving,
  not a lower-privacy shortcut
- `[x]` Network-metadata caveat addressed with a low-latency two-role ingress
  design rather than a mixnet
- `[x]` Decide that ordinary locator sends use first-class PQ offline receive
  descriptors, while handles and invoices remain the policy-bound receive
  capabilities
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

- `[x]` Define validator registration and validator metadata objects
- `[x]` Implement validator registration and validator-profile shared-state
  execution with cold-governance authorization
- `[x]` Define shielded delegation notes or pool-share notes
- `[x]` Define private undelegation and unbonding flows
- `[x]` Define shielded staking note semantics
- `[x]` Define reward accrual through pool accounting rather than public
  per-wallet rewards
  Finalized anchors now settle validator rewards directly into validator-pool
  state, validator commission is reserved inside the pool rather than emitted
  as a public wallet credit, and missed-vote or jailed/retired validators are
  automatically suppressed from reward growth.
- `[x]` Define slash handling at the validator-pool level while keeping
  delegator ownership shielded
- `[x]` Define validator jail/reactivation lifecycle and committee re-entry
  rules from ordered accountability state
- `[~]` Implement native circuits for delegation, undelegation, and stake claim
- `[ ]` Define wallet UX for delegation without exposing a public delegator
  graph

## 5. Shielded Payment Model

- `[~]` Shielded notes and nullifiers already exist, but they are still shaped
  by the old epoch/archive design
- `[ ]` Refactor the note model around the new settlement path rather than PoW
  anchor materialization
- `[x]` Define fee handling so ordinary private payments do not need a
  transparent payment path
  Ordinary private transfers, private delegation, private undelegation, and
  mature unbonding claims now carry explicit shielded fee amounts inside their
  proof-balance equations, and finalized anchors route the exact finalized fee
  pot back into validator-pool reward settlement. Validator registration,
  profile update, penalty-evidence admission, and validator reactivation now
  also accept shielded fee-payment sidecars so control actions no longer need a
  zero-fee exception.
- `[x]` Expose fee-paid validator control submission through canonical operator
  tooling
  `unchained_node` now builds cold-signed registration, profile-update,
  reactivation, and penalty-evidence control documents from the local node
  root, and `unchained_wallet` now submits those documents through
  wallet-control with a private fee-payment sidecar.
- `[x]` Add deterministic proof-fixture coverage for fee-paid control
  submissions
  Deterministic wallet material, deterministic internal change-key derivation,
  stable fee-witness IDs, committed cached shielded-spend receipts for the
  single-validator and deterministic multivalidator control witnesses, fast
  local staking state-machine coverage, multivalidator ordered-control coverage
  in `pq_network`, and the wallet-control end-to-end fee-paid registration flow
  are now all wired into the routine suite. Redundant prover-heavy local
  ordered-control copies in `staking_transactions` were removed in favor of the
  stronger multivalidator network tests plus direct local state-machine tests.
- `[~]` Keep ordinary transfers on a native fast path without revealing extra
  sender or recipient metadata
  Outward payment handles now mint one-time payment-capability signing keys and
  one-time ML-KEM receive keys, so ordinary recipients no longer expose a
  wallet-global outward identity through payment handles. Ordinary-path
  submission now goes through the real access-relay/submission-gateway ingress
  path with fixed-size hybrid-encrypted envelopes and short batched release
  windows. Wallets now emit low-rate online cover envelopes on a deterministic
  per-wallet cadence through the same ingress path.
- `[x]` Define native transaction classes clearly: ordinary transfer vs
  shared-state operation
- `[x]` Remove legacy archive-query assumptions from wallet spend and sync
  flows
  Wallet checkpoint refresh now derives historical unspent extensions locally
  from the node-control shielded runtime snapshot instead of sending
  requester-linked historical-extension queries through node control.

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
- `[x]` Enforce fresh one-time outward payment authorization keys per handle or
  invoice
- `[x]` Ensure no wallet-global outward identity key is exposed in payment
  handles
- `[x]` Define `LocatorID`, stateless PIR-native private discovery, mailbox
  records, and negotiated handle flows
  The canonical design now requires stateless single-server PIR discovery with
  fixed-size signed records, fixed-shape queries and responses, authenticated
  snapshot manifests, and mailbox bootstrap material that is distinct from
  payment keys.
- `[x]` Define direct invoice links as a first-class merchant path
- `[x]` Keep discovery keys, mailbox keys, payment capability keys, and wallet
  root keys strictly separated at the architecture level
  The architectural role separation is now explicit; the codebase audit and
  implementation cleanup remain open under cryptography and key-management
  tasks.
- `[x]` Define and lock the canonical discovery manifest, snapshot, and
  signed-PIR-parameter formats for native locator lookups
- `[x]` Define and lock the fixed-size discovery-record schema, padding rules,
  and record size for small-record PIR operation
- `[x]` Implement PIR-native locator indexing from signed manifest parameters
  with no cleartext lookup fallback
- `[x]` Implement the Rust PIR discovery client library for manifest fetch,
  signature verification, query generation, record decoding, and mailbox
  bootstrap extraction
- `[~]` Implement the discovery directory server with snapshot builder, PIR
  query executor, hot-swap snapshot rotation, and replica consistency checks
  The native server now builds signed snapshots, serves PIR queries, and
  refreshes its in-memory index after locator publication; cross-replica
  consistency enforcement is still open.
- `[~]` Implement signed snapshot publication and mirrorable discovery replicas
  so clients can verify they are querying the intended directory snapshot
  Signed manifests are now live and verified by clients; mirrored publication
  and replica distribution policy are still open.
- `[x]` Implement mailbox transport and one-time `RecipientHandle`
  request/response flows against PIR-fetched discovery records
- `[x]` Document PQ offline receive as the ordinary locator-delivery path while
  retaining negotiated handles and invoices for policy-bound receive flows
- `[x]` Define the `OfflineReceiveDescriptor` schema, signature binding, and
  discovery-record extension format
- `[x]` Define sender policy so ordinary locator sends use offline receive,
  while handles and invoices remain the explicit policy path
- `[x]` Implement wallet receive-material support for rotating offline receive
  descriptors
- `[x]` Extend wallet output decryption to validate
  shared-secret-derived one-time owner identity for offline-receive notes
- `[x]` Implement an explicit wallet send path for offline ordinary transfers
  using the offline receive descriptor
- `[ ]` Define rotation, expiry, and compromise-handling policy for offline
  receive descriptors
- `[ ]` Implement privacy-preserving abuse controls for discovery queries
  using blinded rate-limit tokens or an equivalent anonymous query-budget
  mechanism
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

## 7. Network Privacy And Ingress

- `[x]` Implement the two-role ingress model:
  `access relay` plus `submission gateway`
- `[x]` Enforce operator separation between access relays and submission
  gateways
- `[x]` Use constant-size padded submission envelopes
- `[x]` Use short fixed release windows and micro-batched validator ingress
- `[x]` Add low-rate online wallet cover traffic without turning the product
  into a high-latency anonymity network
- `[x]` Remove direct wallet-to-validator submission as the ordinary path
- `[x]` Define relay abuse controls and rate limiting that do not destroy source
  privacy

## 8. Wallet Sync And Light Clients

- `[x]` Replace archive-receipt and requester-linked historical-query flows
  with compact light-client sync
  Wallet-side checkpoint extension refresh no longer sends requester-linked
  historical queries; it derives the extension locally from the node snapshot.
  Wallet observation and receive-side ownership refresh now run from a compact
  node-control scan head plus paged deltas carrying committed genesis coins and
  compact shielded outputs, and the wallet uses the existing `view_tag` as the
  compact probabilistic detection tag before local trial decryption. The wallet
  persists a compact scan cursor, so refresh no longer rereads the entire
  compact set every time. Proving and checkpoint-refresh work now use a
  smaller send-runtime material bundle carrying the compact head, validator
  pools, note tree, root ledger, and archived nullifier epochs, and that same
  material path now also runs over the real relay/gateway transport. Compact
  sync and normal wallet prepare/prove/submit flows therefore no longer
  require a colocated node-control socket, and sender-side proving can now be
  offloaded to a separate remote proof-assistant role instead of requiring a
  local prover.
- `[x]` Define compact chain data for wallet scanning
- `[x]` Use fuzzy note-detection tags or an equivalent compact probabilistic
  detection mechanism
- `[x]` Keep final ownership detection wallet-local through trial decryption or
  equivalent local processing
- `[x]` Make mobile-wallet sync cheap without exposing ownership queries to the
  network
  Compact wallet refresh is now incremental and cursor-driven, so the wallet
  requests bounded deltas instead of the full compact set while still keeping
  ownership detection local. The same compact sync path now works over the
  relay/gateway transport, so remote wallet sync no longer depends on local
  node-control access.

## 9. Proof System

- `[~]` The repository has a proving path today, but it does not match the
  target architecture
- `[x]` Define a remote proof-assistant / receipt-delivery path for sender
  wallets
  A distinct proof-assistant service now accepts hybrid-encrypted proof
  witness requests and returns verified STARK receipts for ordinary shielded
  spends, private delegation, private undelegation, unbonding claims, and
  checkpoint accumulators, so remote/mobile wallets no longer require a local
  prover for the canonical send path.
- `[x]` Introduce a canonical transparent-proof object boundary across
  transactions, wallets, ingress, and proof-assistant transport
  Steady-state transaction, wallet, ingress, and proof-assistant flows now
  carry statement-typed `TransparentProof` objects rather than raw backend
  receipt bytes, and backend verification / method-ID handling is isolated to
  `src/proof.rs`.
- `[~]` Remove dependence on the current prototype proving backend as the
  long-term integrity anchor
  Backend-specific receipt parsing and method/image identifiers are now
  contained within `src/proof.rs`, the canonical proof model now carries
  explicit backend identity, and the proof assistant now advertises backend
  capabilities and supported circuits. Proof routing now also runs through a
  canonical per-circuit backend policy instead of direct method wiring, but
  the underlying proving backend is still the prototype engine and has not yet
  been replaced.
- `[~]` Define a native transparent STARK-family proving architecture
  The canonical proof layer now has an explicit circuit inventory for ordinary
  transfer, private delegation, private undelegation, unbonding claim, and
  checkpoint accumulator, each with a named public-input shape and a
  conservative `128-bit` minimum security budget. Proofs and proof-assistant
  transport now also carry explicit backend identity and capability manifests.
  The backend swap itself is still open.
- `[ ]` Set and document a conservative `>= 128-bit` security budget
- `[ ]` Implement native circuits for transfer
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
- `[ ]` Add discovery-directory operator config, PIR parameter selection, and
  signed snapshot publication ceremonies
- `[ ]` Add wallet/client CLI and service surfaces for locator resolution via
  PIR and mailbox-based handle negotiation

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
- `[ ]` Add end-to-end tests for PIR discovery
  Cover fixed-size manifest and row encodings, candidate-slot derivation,
  constant-shape queries and responses, authenticated row verification,
  mailbox bootstrap decoding, negotiated-handle completion, snapshot rotation,
  and failure handling under stale manifests or malformed rows.
- `[ ]` Add privacy-invariant tests for discovery abuse controls
  Query budgeting, retries, relaying, and operator telemetry must not re-link
  locator resolution to a wallet identity or degrade PIR query privacy.
- `[ ]` Add proof-system tests aligned to the new native circuits
  The suite now includes canonical circuit-inventory and proof-assistant
  capability-manifest coverage, but native-circuit proof tests are still open.

## 14. Immediate Next Steps

- `[~]` Remove the mining/PoW architecture from protocol definitions and docs
  that still reference it
- `[x]` Define the validator-set and quorum-certificate data structures
- `[x]` Define the native transaction classes and fast-path eligibility rules
- `[x]` Define shielded delegation-share notes and a native private-delegation
  proof path
- `[x]` Define private undelegation and delayed-claim shared-state actions
- `[x]` Define shielded staking note semantics
- `[x]` Define the two-role ingress wire model
- `[x]` Canonicalize stateless single-server PIR as the discovery backend for
  `LocatorID` resolution
- `[ ]` Define and lock the PIR-native discovery manifest, fixed-size record
  layout, and candidate-slot derivation rules
- `[ ]` Implement the PIR discovery client, directory server, and mailbox
  negotiation path end to end
- `[~]` Define the replacement proof architecture and circuit inventory
  The canonical proof-object boundary and named circuit inventory are now in
  place across transaction, wallet, ingress, and proof-assistant paths; the
  replacement backend and the remaining native circuits are still open.

## 15. Explicitly Out Of Scope

- `[x]` Proof of work
- `[x]` Mining as a long-term product surface
- `[x]` Public archive-receipt economics
- `[x]` Reusable public payment addresses
- `[x]` Optional privacy with a transparent default
- `[x]` Generic smart contracts in the base protocol
