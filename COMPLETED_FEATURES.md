# Completed Features Summary

## 1. Architecture and Product Scope
The Unchained architecture has been fully pivoted from a legacy Proof-of-Work (PoW) mining model to a private, real-time settlement chain. Key achievements include:
- **Canonical Direction**: Rewrote product goals around shielded delegated Proof-of-Stake (PoS) and low-latency BFT ordering.
- **Privacy-First Design**: Defined ordinary fast-path payments as natively privacy-preserving and established a two-role ingress model (access relay + submission gateway) to protect network metadata.
- **Identity Management**: Transitioned to one-time PQ offline receive descriptors and policy-bound handles/invoices, separating discovery, mailbox, and payment keys.

## 2. Consensus and Ordering
Implemented a modern BFT consensus engine:
- **Validator Model**: Defined the validator-set object model, epoch boundaries, and slot timing.
- **Quorum & Voting**: Implemented stake-weighted committee membership and quorum-certificate formation using ML-DSA validator votes.
- **Deterministic Checkpoints**: Established leader-gated checkpoint proposals and validator vote wire flows.

## 3. Shielded Staking & Fees
Developed a private staking and fee mechanism:
- **Validator Lifecycle**: Implemented validator registration, profile updates, and jail/reactivation rules driven by ordered accountability state.
- **Shielded Rewards**: Rewards now accrue through pool accounting rather than public per-wallet emissions, with fees handled entirely within the shielded path.
- **Operator Tooling**: Added support for fee-paid validator control submissions via `unchained_node` and `unchained_wallet`.

## 4. Wallet Addressability & Discovery
Revolutionized how wallets find each other privately:
- **PIR Discovery**: Implemented stateless, single-server Private Information Retrieval (PIR) for locator discovery, ensuring the server never learns which locator is being resolved.
- **One-Time Capabilities**: Enforced fresh one-time outward payment authorization keys per handle/invoice to prevent identity leakage.
- **Offline Receive**: Developed PQ-safe offline receive descriptors with automatic rotation and compromise-handling policies.

## 5. Network Privacy & Ingress
Hardened the network against traffic analysis:
- **Two-Role Ingress**: Deployed the access relay and submission gateway model to decouple user identity from transaction submission.
- **Traffic Obfuscation**: Implemented constant-size padded envelopes, fixed release windows, and low-rate wallet cover traffic.

## 6. Wallet Sync & Light Clients
Optimized the wallet experience for privacy and performance:
- **Compact Sync**: Replaced requester-linked historical queries with a compact light-client sync path that keeps ownership detection local to the wallet.
- **Remote Proving**: Introduced a proof-assistant role, allowing mobile and remote wallets to offload heavy proving work without sacrificing privacy.

## 7. Testing & Verification
Established a robust verification suite:
- **Network Tests**: Added multi-validator tests for checkpoint certification, DAG finalization, and shared-state ordering.
- **Privacy Invariants**: Verified fixed-size envelope round trips, role separation, and anonymous query-budget enforcement for PIR discovery.
- **Deterministic Fixtures**: Integrated comprehensive proof-fixture coverage for fee-paid control flows.
