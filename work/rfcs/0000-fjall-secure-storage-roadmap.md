# RFC 0000: Fjall Secure Storage Roadmap

## Status

Draft

## Summary

This roadmap splits the Fjall security, data model, and MVCC proposal into smaller scoped RFCs.

Fjall remains an embedded, safe Rust, log-structured LSM key-value engine. These RFCs add optional secure storage capabilities without turning Fjall into a SQL engine, distributed coordinator, standalone server, or wide-column database.

## Motivation

Fjall currently exposes ordered byte keys, multiple keyspaces, prefix and range scans, snapshots, compaction, and optional serializable transactions. Modern embedded applications increasingly need structured keys, explicit versioned records, visibility-label filtering, pluggable authorization, encryption, and retention-aware compaction.

Fjall's secure keyspace model combines sorted composite keys, descending timestamps, column visibility expressions, and authorization-aware scans in an embedded architecture.

## RFC Set

1. [RFC 0001: Ordered Composite Keys](0001-ordered-composite-keys.md)
2. [RFC 0002: Explicit Versioned Cells and MVCC Scans](0002-versioned-cells-and-mvcc-scans.md)
3. [RFC 0003: Visibility Expressions and Authorizations](0003-visibility-expressions-and-authorizations.md)
4. [RFC 0004: Secure Keyspaces and Pluggable Security Providers](0004-secure-keyspaces-and-security-providers.md)
5. [RFC 0005: Session-Aware Transactions](0005-session-aware-transactions.md)
6. [RFC 0006: Encryption Providers](0006-encryption-providers.md)
7. [RFC 0007: Policy-Aware Compaction and Audit Hooks](0007-policy-aware-compaction-and-audit.md)

## Ordering

The RFCs are intentionally ordered by dependency:

1. Composite key encoding is the byte-order foundation.
2. Versioned cells define scan semantics on top of that encoding.
3. Visibility expressions define the record-level authorization predicate.
4. Secure keyspaces define how the API enforces those predicates.
5. Transactions define how sessions interact with serializable writes.
6. Encryption hardens secure keyspaces against raw storage access.
7. Compaction and audit define background policy behavior.

## Feature Gate

All public APIs introduced by these RFCs should initially live behind an optional feature:

```toml
[features]
secure-keyspaces = []
```

Individual implementation details may use internal modules before the feature is stabilized.

## Implementation Status

- The `secure-keyspaces` feature gate is declared in `Cargo.toml`.
- The crate exposes a documented `fjall::secure` module only when that feature is enabled.
- The module is currently a compatibility-preserving landing zone; individual APIs should be added as their scoped RFCs move from draft to implementation.

## Compatibility

Existing raw Fjall keyspaces remain unchanged. Secure keyspaces are additive and must not alter the behavior of `Database`, `Keyspace`, `SingleWriterTxDatabase`, or `OptimisticTxDatabase` unless the new feature is enabled.

Secure keyspaces must not claim process-level security against arbitrary code with direct access to raw database files or raw keyspace APIs. In an embedded database, authorization is enforceable only through cooperating APIs unless encryption keys are held outside the storage engine.

## Non-Goals

These RFCs do not introduce:

- SQL
- Joins
- Query planning
- Distributed consensus
- Replication
- RPC servers
- Cross-process coordination
- Row-level locking
- Secondary indexes
