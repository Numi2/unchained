## HTLC (Epoch‑Based) CLI Guide

This guide shows how two parties complete an HTLC transfer on Unchained using epoch numbers (not timestamps). The HTLC supports two paths:
- Claim: receiver reveals s_claim before epoch T
- Refund: sender reveals s_refund at/after epoch T

Both paths use commitment hashes (CH) of secrets; secrets themselves are never exchanged on-chain.

## Roles and artifacts
- Sender inputs: wallet, receiver paycode, chosen timeout epoch T
- Receiver inputs: wallet, chosen claim secret s_claim
- Exchanged off-chain:
  - Sender→Receiver: plan.json (inputs and parameters)
  - Receiver→Sender: claims.json (per‑coin CH for claim)
  - Sender→Receiver: refunds.json (per‑coin CH for refund)

## 0) Prerequisites
- Node synced to network tip (or running in standalone mode)
- Wallet unlocked
- Receiver paycode available (base64‑url; see `unchained stealth-address`)

## 1) Sender plans the offer
Create a plan that selects inputs and binds amount and timeout epoch.

```bash
unchained htlc-plan --paycode <RECEIVER_PAYCODE> --amount <AMOUNT> --timeout <EPOCH_T> --out plan.json
```

Notes:
- `<EPOCH_T>` is the block epoch number deadline.
- `plan.json` includes `chain_id`, inputs, receiver paycode, and timeout epoch.

## 2) Receiver prepares claim commitments
Receiver commits to s_claim without revealing it by producing per‑coin CH values.

```bash
unchained htlc-claim-prepare --claim_secret <HEX_OR_B64_S_CLAIM> \
  --coins <COIN_ID_HEX_1,COIN_ID_HEX_2,...> \
  --out claims.json
```

Notes:
- The coin ids come from the sender’s `plan.json` (share securely out‑of‑band).
- Output `claims.json` looks like:

```json
{
  "claims": [
    { "coin_id": "...32-byte hex...", "ch_claim": "...32-byte hex..." }
  ]
}
```

## 3) Sender prepares refund commitments (no secrets printed)
Sender must either:
- Provide a deterministic base and write CHs only:

```bash
unchained htlc-refund-prepare --plan plan.json \
  --refund_base <HEX_OR_B64_REFUND_BASE> --out refunds.json
```

- Or generate per-coin secrets and save them to a file (keep secure):

```bash
unchained htlc-refund-prepare --plan plan.json \
  --out refunds.json --out_secrets refund_secrets.json
```

Notes:
- `refunds.json` looks like:

```json
{
  "refunds": [
    { "coin_id": "...", "ch_refund": "..." }
  ]
}
```
- If you used `--out_secrets`, store `refund_secrets.json` securely; it contains raw secrets.

## 4) Sender executes the offer
Build HTLC spends with the composite HTLC lock (epoch‑gated claim/refund) and broadcast them.

```bash
unchained htlc-offer-execute --plan plan.json --claims claims.json \
  --refund_base <HEX_OR_B64_REFUND_BASE>
```

Or, if you did not use a deterministic base, you must persist generated secrets to a file:

```bash
unchained htlc-offer-execute --plan plan.json --claims claims.json \
  --refund_secrets_out refund_secrets.json
```

Policy: one of `--refund_base` or `--refund_secrets_out` is required. The tool does not print refund secrets.

## 5A) Receiver claims before T
Receiver spends with s_claim when current epoch < T. Requires sender’s `refunds.json` so both CHs are enforced. The CLI guards against running on the wrong side of T.

```bash
unchained htlc-claim --timeout <EPOCH_T> \
  --claim_secret <HEX_OR_B64_S_CLAIM> \
  --refunds refunds.json \
  --paycode <RECEIVER_NEXT_HOP_PAYCODE>
```

## 5B) Sender refunds at/after T
Sender spends with refund secret when current epoch ≥ T. Requires receiver’s `claims.json`. The CLI guards against running on the wrong side of T.

```bash
unchained htlc-refund --timeout <EPOCH_T> \
  --refund_secret <HEX_OR_B64_S_REFUND> \
  --claims claims.json \
  --paycode <SENDER_NEXT_HOP_PAYCODE>
```

## Data formats (reference)
- Plan (`plan.json`):

```json
{
  "chain_id": "...32-byte hex...",
  "timeout_epoch": 12345,
  "amount": 100,
  "paycode": "<base64-url>",
  "coins": [ { "coin_id": "...", "value": 1 } ]
}
```

- Claims (`claims.json`): see section 2.
- Refunds (`refunds.json`): see section 3.

## Security & operational notes
- Refund secrets are never printed. Use `--refund_base` for deterministic derivation or `--refund_secrets_out` to persist generated secrets securely.
- Set strict filesystem permissions (0600) on secrets files; consider disk encryption.
- Exchanging CH documents (`claims.json`, `refunds.json`) is safe; they contain commitments only.
- Timeout uses epoch number; ensure both parties are synced to the same network.

## Troubleshooting
- Proof timeouts: ensure peers are reachable and node is synced.
- Epoch mismatch: claim requires current_epoch < T; refund requires current_epoch ≥ T (CLI enforces this).
- Invalid CH errors: ensure CH docs match `plan.json` and the same chain.


