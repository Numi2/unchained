# DeepBook Integration Guide

DeepBookV3 is Sui's canonical on-chain central limit order book (CLOB). Instead of deploying your own
matching engine, you integrate directly with DeepBook's Move modules and shared objects. This guide
summarizes the on-chain model, the order lifecycle, and the pieces you need to ship a complete DEX
experience on top of DeepBook.

## 1. System overview

- **Shared Pools** – Every market (e.g. `SUI/USDC`) has a single `Pool` shared object.
- **Move-native design** – Pools, registries, and balance managers are standard Move structs; there is
  no slab allocator or crank loop.
- **Parallel execution** – Sui serializes access *within* a Pool but can execute transactions touching
  different Pools concurrently.
- **Composable API** – Any package can import DeepBook modules to place orders, cancel, or manage
  balances.

## 2. Core on-chain components

### 2.1 Pool shared object

Each public entry (place order, cancel, etc.) takes a mutable reference to the `Pool`. The Pool is
logically split into three layers for clarity and upgrade flexibility:

| Layer | Purpose |
| --- | --- |
| **Book** | Bid/ask price levels with price–time priority queues and per-order metadata. |
| **State** | Market configuration (tick size, lot size, fees, admin/paused flags). |
| **Vault** | Custodies the two assets (base + quote) with Sui `Coin<T>` ownership guarantees. |

### 2.2 PoolRegistry

- Guarantees uniqueness per `(base, quote)` pair.
- Records which DeepBook package version instantiated the Pool for future migrations.
- Only needed during Pool creation.

### 2.3 BalanceManager (per user)

- Users deposit assets once; all orders across Pools debit/credit this object.
- Settlements stay internal until users withdraw, minimizing coin movements.
- Simplifies accounting because you have one BalanceManager per account, not per market.

## 3. Order model

DeepBook supports the following semantics:

- **Order types:** limit and market.
- **Time-in-force:** standard expiration timestamps (you can lower expiration but not extend it).
- **Order options:**
  - Self-match policies (`cancel_both`, `cancel_old`, `cancel_new`).
  - Fee payment toggle (`pay_with_deep`) to use DEEP tokens or the input asset.
- **Modification:** only size reductions and earlier expirations are allowed; increasing requires
  cancel + re-place.
- **Cancellation APIs:** cancel a single order or every order for a user within a Pool.

## 4. Matching + settlement path

A single Move transaction performs matching, vault updates, and accounting atomically:

1. **User call:** invoke `deepbook::orders::place_order` (name simplified) with `&mut Pool`,
   `&mut BalanceManager`, order params, and `&mut TxContext`.
2. **Balance check:** the engine validates that the BalanceManager has enough base/quote funds.
3. **Matching:** DeepBook walks the opposite side of the book, fills orders respecting price–time
   priority, and generates fills.
4. **Accounting:** maker/taker balances are updated inside both the BalanceManager and Pool Vault.
5. **Resting order:** any remainder becomes a resting order in the Book structure.
6. **Atomicity:** the entire call succeeds or reverts—no crankers or background jobs are required.
7. **Parallelism:** distinct Pools are separate shared objects, so different markets execute in
   parallel without coordination.

## 5. Integration pattern

### 5.1 On-chain wrapper module

Your package typically wraps DeepBook to enforce defaults and compose additional logic. Example:

```move
module mydex::router {
    use deepbook::balance_manager;
    use deepbook::orders;
    use deepbook::pool;

    public entry fun place_limit_bid(
        pool: &mut pool::Pool,
        balances: &mut balance_manager::BalanceManager,
        price: u64,
        quantity: u64,
        ctx: &mut TxContext,
    ) {
        orders::place_limit_order(
            pool,
            balances,
            /* side = */ orders::Side::Bid,
            price,
            quantity,
            orders::Options {
                tif: orders::TimeInForce::GTC,
                self_match: orders::SelfMatch::CancelOld,
                pay_with_deep: false,
            },
            ctx,
        );
    }
}
```

Typical flows you expose via entry functions:

- Create + fund a BalanceManager (if absent) and deposit coins.
- Place limit or market orders with policy defaults.
- Withdraw settled funds back to wallet-controlled `Coin<T>` objects.

### 5.2 Off-chain indexer + APIs

On-chain data structures are not optimized for UI queries. Run an indexer or consume a hosted data
provider to supply:

- Live order book depth snapshots per Pool.
- Trade history / ticker feeds.
- Per-address open orders, fills, and realized fees.

Expose this data through REST/GraphQL/WebSocket endpoints so your front end never needs to read raw
Move storage layouts.

### 5.3 Front-end flow

1. Connect user wallet (Sui Wallet, Ethos, Backpack, etc.).
2. If no BalanceManager exists, build a Programmable Transaction Block (PTB) that creates it and
   deposits assets.
3. Build PTBs that call your wrapper functions for each order, sign, and submit.
4. Stream book depth, trades, and user-specific state from your indexer for responsive UX.

## 6. Differences vs. Serum-style CLOBs

| Aspect | Serum (Solana) | DeepBook (Sui) |
| --- | --- | --- |
| Matching | Request/Event queues + off-chain crankers | Fully in-transaction, no crankers |
| Data model | Custom slab allocator | Standard Move structs (Pool/Book/Vault) |
| Parallelism | Account locks limit concurrency | Independent Pools lock separately |
| Integration | Apps talk to Serum instructions directly | Apps wrap DeepBook modules |

## 7. Implementation checklist

1. **Identify markets:** fetch or create the target Pool via the `PoolRegistry`.
2. **Create BalanceManager:** one-time setup per user; deposit base/quote assets.
3. **Expose entry functions:** wrap DeepBook order APIs with your defaults and security checks.
4. **Indexer:** subscribe to Pool + BalanceManager events, persist book depth + trades.
5. **Front-end:** use indexer feeds for UX, use PTBs for state-changing actions.
6. **Operations:** monitor Pool versioning via the registry and plan migrations when DeepBook updates.

Following this pattern lets you focus on UX, tokenomics, and routing logic while DeepBook supplies the
battle-tested on-chain CLOB.
