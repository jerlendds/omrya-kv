# RFC 0005: Session-Aware Transactions

## Status

Draft

## Summary

Extend Fjall's transactional APIs with secure, session-aware variants. Transactions capture session context at begin time and enforce permissions and visibility filtering for all secure operations inside the transaction.

## Motivation

Fjall supports serializable transactions through `SingleWriterTxDatabase` and `OptimisticTxDatabase`. Secure keyspaces must preserve those guarantees while applying authorization consistently.

## Proposed API Sketch

```rust
let mut tx = db.begin_secure_tx(&session)?;

tx.put(&events, key, value)?;
let value = tx.get(&events, cell)?;

tx.commit()?;
```

The concrete names should follow the existing transaction modules:

- `SingleWriterSecureTxDatabase`
- `OptimisticSecureTxDatabase`
- or secure wrappers around the existing transaction types

## Session Capture

Transactions should capture the session's identity and authorizations at transaction start.

This avoids mid-transaction authorization drift and aligns with snapshot isolation:

1. transaction begins
2. storage snapshot and session authorizations are captured
3. reads apply snapshot selection
4. reads apply captured authorization filtering
5. writes apply captured permission checks
6. commit uses normal Fjall transaction validation

## Permission Checks

Read permissions may be checked:

- once at first keyspace read in the transaction
- or on every operation

Write and delete permissions should be checked before staging mutations. Commit should not be the first time a security denial is reported.

## Read-Your-Own-Writes

Secure transactions must preserve existing read-your-own-writes behavior. Reads inside a transaction must apply visibility rules to both:

- committed records visible in the transaction snapshot
- writes staged by the same transaction

If the transaction writes a record with a visibility expression not satisfied by the session's own authorizations, the write may still be allowed if the user has `Write` permission. A subsequent read by the same transaction should follow the normal visibility rule unless the API explicitly offers an administrative bypass.

## Conflict Checking

Optimistic conflict checking should operate on encoded physical keys. Security filtering must not hide write conflicts.

For example, a transaction may conflict with an unauthorized physical record if both mutate the same encoded key. Authorization controls exposure, not storage-level conflict detection.

## Failure Semantics

Security failures must fail closed:

- invalid session rejects transaction begin
- permission failures reject the operation
- authorization provider failure during begin rejects transaction begin
- provider failure after begin should not affect captured authorization state

## Validation

Tests should cover both transactional engines:

- secure reads inside transactions
- secure writes inside transactions
- permission denial before mutation staging
- read-your-own-writes with visibility filtering
- optimistic conflict detection with secure records
- captured authorization stability across transaction lifetime

## Open Questions

- Should session-aware transactions be separate types or extension methods?
- Should administrative transactions support bypassing visibility checks?
- Should authorization changes force active transactions to abort, or is begin-time capture sufficient?

