To dos
Critical first-order tasks:

	1.	Replace the flawed address-generation code in src/crypto.rs by deleting the GLOBAL_ADDR_COUNTER tweak and returning the raw BLAKE3 hash of the public key;

	2.	Encrypt every wallet’s secret key before it is written to disk—derive an encryption key from a user pass-phrase with Argon2id, store the Dilithium3 secret key ciphertext, and require a pass-phrase to unlock;

	3.	Finish validate_transfer so it checks Dilithium3 signatures, ownership of the referenced UTXO, double-spend status, coin value, and existence of the previous transaction;
	4.	Add a validate_anchor routine that refuses anchors whose cumulative work, hash chain, or difficulty retarget math is inconsistent, and never writes an unvalidated anchor to the database;
	5.	Upgrade the libp2p transport to a post-quantum–secure handshake (e.g., Kyber in a Noise pattern for QUIC).

Important follow-up work:
6) Define an unambiguous byte sequence for Transfer signatures (e.g., deterministic serialization of coin_id, to, prev_tx_hash, and maybe a timestamp) and verify against it;
7) Remove the direct dependency on wall-clock time for epoch changes—use block height or a median-time-past calculation instead;
8) Decide how to handle “late coins” (either forbid retroactive insertion or bound the allowed lateness) and adjust the epoch logic accordingly;
9) Treat any database-flush or network-publish failure as a hard error—do not propagate coins, anchors, or transfers if they were not durably written;
10) Make epoch-hash look-ups type-safe by fetching Anchor objects directly instead of raw bytes;
11) Add fork tracking and automatic re-org logic so the node can switch to a better chain;
12) Introduce peer scoring or bans when a remote sends malformed anchors, coins, or transfers.

Best-practice hardening:
13) Feed a unique salt (e.g., the block hash or nonce) into each Argon2id PoW challenge;
14) Re-evaluate or eliminate the fixed max_mining_attempts so miners don’t abandon epochs too early;
15) Replace println! debugging with structured logging via tracing and environment-controlled log levels;
16) Give the wallet helper APIs to list its unspent coins and calculate balances;
17) Protect new nodes against long-range attacks by checkpointing a recent epoch hash or demanding majority confirmation for very old history.
