# ZEC Native Proof Backend

This document tracks the native transparent proof boundary for shielded ZEC
staking. It is intentionally implementation-facing: public anchor admission can
be live only when its native verifier succeeds, while private stake acceptance
must remain fail-closed until the hidden witness obligations below are backed by
a production transparent prover and verifier.

## Current Status

- `OrchardV1` and `IronwoodV1` are the only accepted Zcash shielded protocol
  tags.
- `ExternalAssetAnchorV1` now has a native Winterfell STARK seal in
  `src/proof/zec_native_stark.rs`. The prover validates the public ZEC anchor
  journal, encodes the canonical anchor public inputs, proves the
  `TransparentProof.statement_digest` and public-input field elements, and
  serializes the Winterfell proof into `TransparentProof.seal`.
- Private external stake has an internal native statement-seal path over its
  canonical public inputs. The witness now carries a Zcash lock evidence
  envelope, and the public journal binds that envelope by action commitment,
  lock commitment, proof digest, and claim digest. Consensus verification
  remains fail-closed in `src/proof.rs` until the hidden Orchard/Ironwood lock
  and receipt relation is arithmetized.
- The Zcash lock claim also has its own ops-only native statement seal over a
  226-byte public input vector. This proves the claim binding and envelope
  digest are the exact public values being fed into the private stake stage; it
  is not a consensus verifier for the hidden Orchard/Ironwood lock relation.
- `proof-core` defines the public journal shape for the future native circuits,
  including the Zcash lock envelope binding used by private stake.
- `src/proof.rs` now exposes production statement-digest helpers and
  circuit-bound verifier-key commitments for the registered native circuits.
- Node-control exposes per-circuit readiness flags covering journal shape
  validation, statement-digest binding, native prover/verifier availability,
  vector coverage, and the operator activation gate.
- Node-control also exposes the current native backend activation manifest.
  The manifest is valid only when it matches the canonical backend, circuit
  inventory, verifier-key commitments, public input shapes, and readiness
  evidence. Prover, verifier, positive-vector, negative-vector, and operator
  readiness flags must each be backed by a nonzero activation commitment; stale
  commitments are rejected while the corresponding flag is disabled.
- `tachyon/` and `ragu/` are local reference checkouts only. The checked-out
  Tachyon crate currently depends on Ragu's mock API surface, so it must not be
  used as a consensus verifier.

## Proof Binding

Every native transparent proof must bind its decoded public journal through a
statement digest. The digest commits to:

- transparent proof object version
- transparent proof statement tag
- transparent circuit tag
- public input shape string
- circuit verifier-key commitment
- circuit public input encoding

For ZEC anchor and private stake circuits, the statement digest now uses the
explicit native public-input encoders in `proof-core` rather than generic
journal serialization:

- `encode_external_asset_anchor_public_inputs()`
- `encode_private_external_stake_public_inputs()`

Those encoders define the byte order the native prover and verifier must
consume for the circuit public inputs.

The Winterfell seal currently turns the statement digest and canonical public
input bytes into base-field elements and asserts those elements directly in the
AIR. The verifier decodes the public bytes from the seal, validates their
journal shape, recomputes the statement digest from the same bytes, and then
verifies the serialized STARK proof against that exact element vector.

For private stake development, there are two native statement stages:

- the 226-byte Zcash lock claim statement, containing envelope version,
  protocol, anchor hash, external nullifier, stake-position commitment, action
  commitment, lock commitment, lock proof digest, and claim digest
- the 509-byte private external stake statement, containing the accepted Zcash
  anchor fields, activation epoch, external nullifier, stake-position
  commitment, the lock claim binding, and the Unchained receipt output binding

The verifier-key commitment is derived from the native backend name, circuit
name, public input shape, statement tag, circuit tag, and target security
budget. Node-control consensus status exposes this commitment for every
registered circuit so operators can confirm exactly which verifier slot is
active or fail-closed.

When a verifier returns a decoded public journal, consensus independently
checks that the proof object's statement digest equals the digest of that
journal for the expected circuit. This keeps proof acceptance bound to the
public inputs consumed by transaction validation.

## Anchor Admission Circuit

The external asset anchor proof publicly binds:

- Unchained chain id
- Unchained current epoch
- external asset id
- Zcash shielded protocol tag, currently Orchard or Ironwood
- Zcash anchor height
- Zcash block hash
- Zcash note commitment root
- Zcash nullifier root
- Zcash anchor hash
- Zcash confirmation depth

The verifier validates that the anchor hash is exactly:

```text
Hash(
  "unchained-zcash-stake-anchor-v1",
  protocol,
  height,
  block_hash,
  note_commitment_root,
  nullifier_root
)
```

Consensus still checks the decoded journal against the transaction's anchor
fields and configured ZEC asset policy. Chain-inclusion policy for imported
Zcash headers remains an integration boundary outside this local STARK seal.

## Private External Stake Circuit

The private stake proof must publicly bind every anchor field above plus:

- activation epoch
- external stake nullifier
- hidden stake-position commitment
- Zcash shielded action commitment
- Zcash lock commitment
- digest of the Zcash lock proof envelope
- digest of the Zcash lock claim bound to protocol, anchor, nullifier, stake
  position, action commitment, lock commitment, and proof digest
- Unchained receipt note commitment
- Unchained receipt output digest

The circuit must prove:

- the Zcash-side stake lock is valid under the selected Orchard/Ironwood
  protocol rules
- the Zcash lock proof envelope opened by the claim digest is the proof used by
  the hidden Orchard/Ironwood lock relation
- the external nullifier is derived from the locked ZEC position
- the stake-position commitment is the same hidden position used by the Zcash
  lock and the Unchained receipt note kind
- the receipt output encrypts a valid `ExternalStakeReceipt` note for the asset
  id and stake-position commitment
- the receipt note birth epoch matches the Unchained current epoch

## Active And Fail-Closed Requirements

- current prover capabilities advertise `ExternalAssetAnchorV1`
- node-control consensus status reports `ExternalAssetAnchorV1` as prover and
  verifier enabled with native implementation, vector, and operator evidence
  commitments
- `verify_external_asset_anchor_proof()` must decode the native seal, validate
  the public anchor journal shape, recompute the proof statement digest, and
  verify the serialized Winterfell proof against digest plus canonical public
  input elements
- consensus must only admit anchors after that verifier call succeeds and must
  reject any returned journal whose digest does not match the proof object's
  statement digest

Until private stake production proofs exist:

- current prover capabilities must not advertise support for
  `ZcashShieldedStakeV1`
- node-control consensus status must report `ZcashShieldedStakeV1` as disabled,
  verifier-disabled, and fail-closed
- readiness must keep consensus activation disabled until a native verifier,
  negative vectors, and the operator gate are all present
- readiness must keep prover advertisement disabled until consensus activation,
  a native prover, and positive vectors are all present
- the activation manifest must validate before any circuit is surfaced as
  enabled
- native prover/verifier readiness and positive/negative vector readiness must
  each carry a nonzero artifact commitment in that manifest
- `verify_private_external_stake_proof()` must reject every proof
- the internal private stake statement-seal verifier may be tested, but it must
  not be wired to consensus until the private witness relation is complete
- consensus must only admit private stakes after that verifier call succeeds
- tests must cover the stake rejection path and the full public journal binding
  shape

## Implementation Sequence

1. Extend the private stake circuit beyond statement binding to prove the
   Orchard/Ironwood lock, nullifier derivation, stake-position commitment, and
   encrypted receipt relation.
2. Add private stake prover functions that construct the exact public journal
   from witness data without serializing hidden witness material into the seal.
3. Advertise `ZcashShieldedStakeV1` only after generation and verification both
   pass negative tests.
4. Add consensus tests with valid generated private stake proofs and forged
   proof variants for each public input.
5. Keep the verifier-only runtime path available for public nodes.
