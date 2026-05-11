# RFC 0007: Policy-Aware Compaction and Audit Hooks

## Status

Draft

## Summary

Add optional retention policies, policy-aware compaction behavior, and audit hooks for secure keyspaces.

## Motivation

Versioned secure records need lifecycle management. Applications may require a bounded number of versions, TTL deletion, audit records for denied access, and visibility-preserving compaction.

Compaction must preserve security metadata and must not depend on the authorizations of any user session.

## Retention Policies

```rust
pub struct RetentionPolicy {
    pub max_versions: Option<usize>,
    pub ttl: Option<Duration>,
}
```

Policies may initially apply at keyspace scope. More granular policies can be added later.

Possible future scopes:

- keyspace
- family
- row prefix
- visibility domain

## Compaction Semantics

Compaction must preserve:

- composite key ordering
- visibility expressions
- timestamps
- tombstone correctness
- encrypted value decryptability

Compaction may:

- remove expired versions
- enforce `max_versions`
- collapse tombstones when safe
- rewrite encrypted values for key rotation if encryption RFCs support it

Compaction must not:

- evaluate visibility using a user session
- expose unauthorized data through audit output
- remove records based on the current caller's authorizations

## Policy Evaluation

Retention operates on physical version groups:

```text
(row, family, qualifier, visibility)
```

This matches the sort order from RFC 0001 and the version grouping from RFC 0002.

If later RFCs define cross-visibility latest selection, retention must specify whether it applies per visibility label or across labels.

## Audit Hooks

```rust
pub trait AuditSink<I> {
    fn record(&self, event: AuditEvent<'_, I>);
}

pub enum AuditEvent<'a, I> {
    AuthenticationSucceeded { identity: &'a I },
    AuthenticationFailed,
    AuthorizationDenied { identity: &'a I, keyspace: &'a str },
    PolicyViolation { keyspace: &'a str },
    CompactionDeleted { keyspace: &'a str, reason: CompactionDeleteReason },
    KeyspaceAccess { identity: &'a I, keyspace: &'a str },
}
```

Audit sinks must be best-effort or fail-closed depending on configuration.

```rust
pub enum AuditFailureMode {
    BestEffort,
    FailClosed,
}
```

## Privacy

Audit events should avoid including full keys or values by default. If applications need detailed audit records, they should opt in explicitly.

## Failure Semantics

Security-sensitive failures must fail closed:

- malformed policy rejects configuration
- compaction policy errors abort that compaction task
- fail-closed audit sink errors reject the audited operation
- best-effort audit sink errors are recorded through logging or metrics only

## Validation

Tests should cover:

- max-version retention
- TTL retention
- tombstone behavior with retention
- policy behavior independent from user authorizations
- encrypted value survival through compaction
- audit sink invocation on allowed and denied operations
- fail-closed versus best-effort audit behavior

## Open Questions

- Should retention policy use wall-clock time, logical timestamps, or both?
- Should retention apply during normal scans as well as compaction?
- Should audit hooks be synchronous, asynchronous, or buffered?
- Should audit sinks be able to redact or hash keys consistently?

