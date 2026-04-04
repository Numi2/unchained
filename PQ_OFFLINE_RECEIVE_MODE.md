# PQ Offline Receive

Unchained now uses a **first-class post-quantum offline receive path** for
ordinary locator-based payments.

This is not a replacement for:

- negotiated one-time `RecipientHandle`s
- direct invoice links
- mailbox transport as a policy and authorization channel

Instead, the architecture is cleanly split:

- `ordinary wallet-to-wallet`: locator -> PIR discovery -> offline receive
  descriptor -> shielded payment
- `policy-bound wallet-to-wallet`: locator -> PIR discovery -> mailbox ->
  negotiated one-time handle -> shielded payment
- `merchant / invoice`: direct one-time invoice capability -> shielded payment

## Why This Is The Right Default

The old mailbox-only locator flow had a structural weakness: the recipient had
to be online to mint the one-time handle before the sender could even start the
proof.

That was wrong for ordinary private payments because it introduced:

- a recipient liveness dependency
- an avoidable latency round-trip before proving
- mailbox load on the common wallet-to-wallet path

For ordinary transfers, the better design is non-interactive delivery. The
mailbox remains valuable, but only where the recipient must authorize or shape
the receive capability.

## Canonical Discovery Record Shape

Each signed discovery record now carries both:

- mailbox bootstrap material
- a signed `OfflineReceiveDescriptor`

The mailbox material is still private to PIR resolution and still distinct from
payment keys.

The offline descriptor is a reusable but short-lived receive capability scoped
to ordinary transfers. It is not a public account address and it must not be
treated as one.

## Offline Receive Descriptor

The descriptor binds:

- protocol version
- chain ID
- locator ID
- wallet root signing public key
- one-time rotating `scan_kem_pk`
- descriptor binding bytes
- asset policy
- policy flags
- issue / expiry time
- wallet signature

The descriptor binding is domain-separated and covers the fields that matter
for ownership and scope, so the sender and receiver derive the same one-time
owner identity from the same transcript.

## Ordinary Locator Send Flow

1. Sender resolves the recipient's `LocatorID` via PIR.
2. Discovery returns the signed record, including the offline receive
   descriptor.
3. Sender encapsulates to `descriptor.scan_kem_pk`.
4. Sender derives a one-time owner identity from:
   - the KEM shared secret
   - the descriptor binding
   - the output ciphertext
   - the payment value tag
   - the chain ID
5. Sender constructs a normal shielded payment output:
   - `owner_kem_pk = descriptor.scan_kem_pk`
   - `owner_signing_pk = derive_one_time_pk_bytes(stealth_seed_v3(...))`
6. Sender proves and submits the ordinary shielded transfer.

The public chain object does not change. This is intentionally a receive-layer
change, not a new ledger object family.

## Receive And Spend Semantics

The receiver keeps the secret key for each active offline descriptor and scans
shielded outputs exactly as before:

- decapsulate
- check `view_tag`
- decrypt payload
- recompute the expected one-time owner identity
- accept the note only if the decrypted owner identity matches the derived one

The note is then spent through the normal note-key path. Offline receive does
not redefine spend authorization.

## Rotation Policy

Offline descriptors are rotating receive capabilities.

The wallet now:

- reuses a fresh active descriptor when republishing the locator record
- rotates to a new descriptor when the active one approaches expiry
- supports explicit operator-triggered rotation when the locator capability
  should be refreshed immediately
- supports explicit compromise rotation that marks the previous descriptor as
  compromised before publishing the next one
- retains retired and compromised descriptor keys locally for a bounded scan
  window so historical outputs remain decryptable

This avoids unbounded key churn from ordinary republishing while preserving the
ability to receive asynchronously.

The current local retention rule is simple:

- descriptor secret keys remain eligible for compact scanning until
  `descriptor_expiry + bounded_scan_retention`
- active descriptors are the only ones eligible for republication
- retired and compromised descriptors are never republished

Longer-horizon tuning is still open around mobile-wallet rotation cadence and
retention-size benchmarking.

## What Still Uses Handles Or Invoices

Handles and invoices remain the correct path when the recipient needs any of
the following:

- amount or asset constraints
- one-time authorization semantics
- request-specific metadata
- QR / checkout flows
- merchant UX
- richer policy binding than ordinary receive permits

That separation is intentional. Unchained is not turning every receive path
into a generic stealth-address system.

## Security Properties

This design preserves the core privacy and product invariants:

- no reusable public on-chain payment address
- no cleartext locator lookup
- no public mempool
- no new output type in the hot path
- no wallet-global outward identity inside ordinary outputs

The tradeoff is that an offline descriptor is reusable during its lifetime, so
descriptor rotation and expiry discipline matter.

## Design Verdict

Unchained should be built around:

- non-interactive PQ offline receive for ordinary locator payments
- negotiated one-time handles for explicit recipient-controlled receive policy
- invoice links for merchant and checkout flows

That is the unified architecture. It removes the mailbox bottleneck from the
common path without discarding the stronger authorization model that handles and
invoices provide.
