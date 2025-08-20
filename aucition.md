Here’s the simplest viable path: a non-custodial CLOB with atomic, hashlock-based settlement. No new scripting language. One small consensus change.

Goal

Price-time central limit order book for Unchained assets. Settlement is atomic on-chain via V3 hashlocks. No custodian. No signatures in the transfer path.

Minimal consensus extensions
	1.	BatchTx: a transaction that bundles N input spends and M outputs. All spends must validate. Either all commit or none.
	2.	HalfSpend tag (wallet-only concept, not a new on-chain type): a standard Spend that requires a specific preimage p (via existing unlock_preimage) and whose outputs and amounts are fixed. It is valid only when p is revealed. No consensus change needed here; it is a plain Spend assembled by the matcher into a BatchTx.

Core primitives
	•	Preimage p and hash h=BLAKE3(p). All matched legs share the same p. Ownership still = knowledge of preimage.
	•	Order intent: off-chain object {market, side, px, qty, tif, min_fill, coin_ids[]}. Auth for relayers can be classical or PQ; consensus does not rely on it.
	•	Reserve set: specific spendable coins the wallet dedicates to the order. No global UTXO locks on chain until match.

Matching flow (atomic 2-leg)
	1.	Maker posts intent to relayer. Wallet chooses reserve coins.
	2.	Matcher finds crossing taker.
	3.	Matcher proposes h to both sides.
	4.	Each wallet builds a HalfSpend:
	•	input: chosen coin(s)
	•	requires unlock_preimage = p where on chain it will carry p at broadcast time
	•	outputs: counterparty’s destination(s) and change
	•	amounts fixed; nullifier computed normally
	•	sends HalfSpend without p to matcher
	5.	Matcher verifies both HalfSpends net out at agreed price and quantities.
	6.	Matcher assembles BatchTx = {HalfSpend_A, HalfSpend_B, outputs}.
	7.	Matcher releases p to both wallets using Kyber session keys; inserts p into both HalfSpends.
	8.	Broadcast BatchTx. Either both spends land or none. Reorgs → rebroadcast.

Partial fills
	•	Split maker reserve into multiple HalfSpends with decreasing timestamps. Taker can match any subset. Each fill yields one BatchTx.
	•	min_fill enforced by wallet refusing to construct HalfSpends below threshold.

Cancel
	•	Maker cancels off-chain. Since coins were never spent, nothing on chain. Any stale HalfSpend is unusable without the match p.

Time-in-force
	•	IOC: matcher discards if no immediate cross.
	•	GTD: relayer expiry time; wallet refuses to honor h after deadline.
	•	FOK: require full size in one BatchTx.

Price-time priority
	•	Order book is off-chain. Deterministic ranking: (price, seq, nonce). Include the tuple in the intent to allow third-party auditors to reproduce the book.

Fees
	•	Protocol can be zero-fee. If you later add maker/taker fees, put them as additional outputs in BatchTx to a fee address. Still atomic.

Front-running defenses
	•	Commit-reveal for takers: taker first sends BLAKE3(order_blob) to relayer. Short reveal window when a cross exists. Stops shadow matching.
	•	Batch-only atomic settlement eliminates leg-grab risk.

Failure modes and handling
	•	Wallet races: user spends reserved coin elsewhere → HalfSpend invalid. Matcher drops and re-quotes.
	•	Reorgs: relayer re-submits the same BatchTx. Nullifiers keep uniqueness.
	•	DoS: per-client rate limits and proof-of-work ticket for posting intents.

Markets and assets
	•	If single native asset only: you get auctions, not trading pairs. To trade pairs, you need a minimal asset_id in coins. Add asset_id: [u8;32] to Coin. Matching requires both legs have different asset_ids. If you refuse asset_ids, limit the system to auctions of the native coin.

Privacy notes
	•	Today amounts are visible. If you want hidden sizes later, add off-chain RFQ and iceberg orders at the relayer. Keep on-chain atomicity unchanged.

APIs (relayer)
	•	POST /orders: {market, side, px, qty, tif, min_fill, reserve_coin_ids[]} → order_id
	•	WS /book/{market}: level2 stream
	•	WS /trades/{market}: matched trades
	•	POST /cancel: {order_id}
	•	POST /confirm-halfspend: submit HalfSpend bytes for a proposed h
	•	POST /commit: for taker commit-reveal

Wallet responsibilities
	•	Maintain UTXO reserve pools per order.
	•	Build HalfSpends deterministically.
	•	Refuse reuse of a HalfSpend once p revealed or tif expired.
	•	Handle reorg rebroadcasts idempotently.

Consensus checklist (what to implement)
	1.	BatchTx container type with M spends and K outputs. Validation = validate each spend exactly as today, then apply atomically.
	2.	No other rule changes. Nullifiers and Merkle roots unchanged.

MVP build order
	1.	BatchTx in node + mempool rules.
	2.	Wallet HalfSpend builder and reserve manager.
	3.	Single relayer with in-memory CLOB + WS streams.
	4.	Price-time matching + atomic BatchTx assembly.
	5.	Cancel/expiry. Reorg handling. Basic monitoring.
	6.	Optional: taker commit-reveal. Maker iceberg.



Main dev tasks:
1. BatchTx consensus 