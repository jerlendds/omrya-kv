# RFC 0001: Ordered Composite Keys

## Status

Draft - initial implementation landed behind `secure-keyspaces`

## Summary

Add a binary-sortable composite key type for secure and versioned records. The key is inspired by Fjall's row, family, qualifier, visibility, and timestamp ordering, but implemented as an optional Fjall encoding layer over existing byte-key keyspaces.

## Motivation

Fjall's public data model is byte-oriented:

```rust
type Key = &[u8];
type Value = &[u8];
```

This is efficient and flexible, but secure wide-row-style records need stable sub-key ordering for:

- row-local scans
- family and qualifier selection
- visibility-aware storage
- newest-version-first iteration

The storage engine should continue to compare encoded byte keys lexicographically.

## Proposed API

```rust
pub struct CompositeKey {
    pub row: Slice,
    pub family: Slice,
    pub qualifier: Slice,
    pub visibility: Slice,
    pub timestamp: i64,
}

impl CompositeKey {
    pub fn encode(&self) -> Result<UserKey>;

    pub fn decode(encoded: &[u8]) -> Result<Self>;
}
```

The concrete owned/borrowed representation may change during implementation. The important contract is the encoded byte ordering.

## Sort Semantics

Encoded composite keys must sort by:

1. `row` ascending
2. `family` ascending
3. `qualifier` ascending
4. `visibility` ascending
5. `timestamp` descending

Example order:

```text
user1/profile/email/admin@9
user1/profile/email/admin@7
user1/profile/name/admin@5
```

## Encoding Requirements

The encoding must be binary sortable. A naive `[len][bytes]` encoding is not acceptable because it sorts by field length before field contents.

The implementation should use a proven ordered tuple encoding pattern, such as:

- escaped field bytes terminated by a delimiter that sorts before ordinary escaped bytes
- fixed sortable numeric encodings for integers
- explicit version byte prefix for future format changes

One possible shape:

```text
[format_version]
[escaped row][terminator]
[escaped family][terminator]
[escaped qualifier][terminator]
[escaped visibility][terminator]
[descending sortable timestamp]
```

The timestamp should be encoded as a descending sortable `i64`, not as `u64::MAX - timestamp`.

For signed timestamps:

```rust
let ascending = (timestamp as u64) ^ 0x8000_0000_0000_0000;
let descending = !ascending;
```

The resulting `descending` value is written in big-endian byte order.

## Prefix Construction

The API should expose helpers for constructing range bounds without decoding all keys:

```rust
pub struct CompositePrefix {
    pub row: Option<Slice>,
    pub family: Option<Slice>,
    pub qualifier: Option<Slice>,
    pub visibility: Option<Slice>,
}

impl CompositePrefix {
    pub fn range(&self) -> Result<Range<UserKey>>;
}
```

The exact type can follow Fjall's existing `util::prefix_to_range` and `util::prefixed_range` conventions.

## Validation

Implementations must test that encoded byte order exactly matches logical order, including:

- empty fields
- binary fields containing delimiter bytes
- high-bit bytes
- negative timestamps
- `i64::MIN`
- `i64::MAX`
- adjacent timestamps

## Compatibility

This RFC does not change raw `Keyspace` ordering. Composite keys are an optional encoding layer used by later secure-keyspace RFCs.

## Implementation Update

The first implementation exposes `fjall::secure::{CompositeKey, CompositePrefix}` behind the `secure-keyspaces` feature.

- Composite fields are owned `Slice` values for now.
- The encoded key starts with a v1 format byte.
- Field encoding uses `0x00` terminators and escapes `0x00`/`0x01` data bytes so terminators sort before any continued field data.
- Timestamps use the signed sortable transform from this RFC, inverted and written big-endian for newest-version-first ordering.
- Prefix ranges are constructed from complete leading fields and delegate upper-bound construction to `util::prefix_to_range`.

The implementation includes tests for empty fields, escaped delimiter bytes, high-bit bytes, negative timestamps, `i64::MIN`, `i64::MAX`, adjacent timestamps, roundtrips, malformed encodings, and prefix ranges.

## Open Questions

- Should composite keys use `Slice`, `Vec<u8>`, `Box<[u8]>`, or borrowed field types?
- Should the visibility field store raw expression bytes, a canonical normalized expression, or an interned identifier?
- Should the encoder live in Fjall itself or in a submodule gated by `secure-keyspaces`?
