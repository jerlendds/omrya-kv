# RFC 0002: Explicit Versioned Cells and MVCC Scans

## Status

Draft - initial implementation landed behind `secure-keyspaces`

## Summary

Expose explicit user-level versioned cells on top of ordered composite keys. Versions are ordered by descending user timestamp so the newest version appears first for a logical cell.

This is separate from Fjall's internal sequence-number MVCC, which continues to provide snapshot isolation for storage operations.

## Motivation

Fjall already uses MVCC internally through the backing LSM tree and supports repeatable snapshot reads. Applications such as event stores, time-series stores, audit logs, and document indexes also need user-visible record versions.

Fjall-style timestamp ordering gives efficient latest-version scans without scanning an entire history first.

## Definitions

A physical secure record is identified by:

```text
(row, family, qualifier, visibility, timestamp)
```

A version group is identified by:

```text
(row, family, qualifier, visibility)
```

Because visibility is part of the sort key before timestamp, versions are grouped by visibility label. A "latest version" lookup in this RFC means the latest version within one visibility label unless a later RFC explicitly defines cross-visibility latest selection.

## Proposed API Sketch

```rust
pub struct Cell {
    pub row: Slice,
    pub family: Slice,
    pub qualifier: Slice,
    pub visibility: Slice,
}

pub struct VersionedCell {
    pub cell: Cell,
    pub timestamp: i64,
}

pub struct VersionScan {
    pub min_timestamp: Option<i64>,
    pub max_timestamp: Option<i64>,
    pub max_versions: Option<usize>,
}
```

Secure keyspace APIs may later wrap these types with visibility expression types instead of raw `Slice`.

## Scan Semantics

For a version group, iteration returns versions in descending timestamp order:

```text
cell@9
cell@7
cell@5
```

Timestamp range filters are logical timestamp filters, not byte ranges exposed to callers.

## Snapshot Semantics

Storage snapshots are applied before user-visible version filtering:

1. Open or use an existing Fjall snapshot.
2. Iterate encoded composite keys visible to that snapshot.
3. Apply timestamp/version selection.
4. Later secure RFCs apply authorization filtering before exposing values.

This preserves Fjall's existing snapshot guarantees.

## Reads

The initial API should support:

- exact version lookup
- latest version lookup for a version group
- version history scan for a version group
- row/family/qualifier range scan with versions in encoded order

## Writes

Writes must reject malformed composite keys and must require an explicit timestamp. A helper may provide wall-clock timestamps, but the storage layer should not silently invent them unless the API name makes that behavior clear.

## Deletes

Deletion semantics should be explicit:

- delete exact version
- delete all versions in a version group
- delete versions older than a timestamp

Tombstone encoding should be compatible with Fjall's existing delete and compaction behavior.

## Validation

Tests should prove:

- newest-version-first ordering
- exact version lookup
- range-limited version scans
- internal snapshot isolation with user-level versions
- delete behavior for exact and grouped deletes

## Compatibility

This RFC does not expose or alter Fjall's internal sequence numbers. User timestamps are application data encoded into keys.

## Initial Implementation Notes

The first implementation exposes `fjall::secure::{Cell, VersionedCell, VersionScan, VersionedEntry}` behind the `secure-keyspaces` feature.

Read helpers are split across:

- `VersionedCellReadExt` for `Readable` snapshots, so storage MVCC is chosen before version filtering
- `VersionedCellKeyspaceExt` for raw `Keyspace` read/write/delete convenience methods

The initial helper set supports exact version reads, latest-version reads, version history scans, composite-prefix scans in encoded order, exact-version deletes, group deletes, and exclusive "older than timestamp" deletes.

The implementation includes tests for newest-version-first ordering, exact and latest reads, timestamp bounds, version limits, snapshot isolation, composite-prefix scans, exact deletes, grouped deletes, and older-than deletes.

## Open Questions

- Should "latest visible" across multiple visibility labels be supported as a first-class operation?
- Should duplicate writes to the same full composite key replace the value or be rejected?
- Should timestamp units be opaque `i64`, Unix nanoseconds, or a dedicated newtype?
