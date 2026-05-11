// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Ordered composite key encoding.

use crate::{Error, Slice, UserKey};
use std::ops::Bound;

const FORMAT_VERSION: u8 = 1;
const FIELD_TERMINATOR: u8 = 0;
const FIELD_ESCAPE: u8 = 1;
const ESCAPED_ZERO: u8 = 1;
const ESCAPED_ONE: u8 = 2;
const ENCODED_TIMESTAMP_LEN: usize = std::mem::size_of::<i64>();
const MAX_USER_KEY_LEN: usize = u16::MAX as usize;

/// A binary-sortable wide-row key.
///
/// The encoded form sorts by row, family, qualifier, and visibility in
/// ascending byte order, then by timestamp in descending signed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeKey {
    /// Row bytes.
    pub row: Slice,

    /// Column family bytes.
    pub family: Slice,

    /// Column qualifier bytes.
    pub qualifier: Slice,

    /// Visibility expression bytes.
    pub visibility: Slice,

    /// Version timestamp. Newer timestamps sort before older timestamps for
    /// otherwise identical fields.
    pub timestamp: i64,
}

impl CompositeKey {
    /// Encodes the composite key into a lexicographically sortable Fjall user key.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded key would exceed Fjall's user-key length
    /// limit.
    pub fn encode(&self) -> crate::Result<UserKey> {
        let fields = [
            self.row.as_ref(),
            self.family.as_ref(),
            self.qualifier.as_ref(),
            self.visibility.as_ref(),
        ];
        let mut encoded = encode_prefix_fields(&fields);

        encoded.extend_from_slice(&encode_descending_timestamp(self.timestamp));
        validate_encoded_len(encoded.len())?;

        Ok(encoded.into())
    }

    /// Decodes a composite key previously produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns an error if the version byte is unsupported or the encoded bytes
    /// are malformed.
    pub fn decode(encoded: &[u8]) -> crate::Result<Self> {
        let (version, rest) = encoded
            .split_first()
            .ok_or(Error::InvalidCompositeKey("missing composite key version"))?;

        if *version != FORMAT_VERSION {
            return Err(Error::InvalidCompositeKey(
                "unsupported composite key version",
            ));
        }

        let (row, rest) = decode_field(rest)?;
        let (family, rest) = decode_field(rest)?;
        let (qualifier, rest) = decode_field(rest)?;
        let (visibility, rest) = decode_field(rest)?;

        if rest.len() != ENCODED_TIMESTAMP_LEN {
            return Err(Error::InvalidCompositeKey(
                "composite key timestamp must be exactly 8 bytes",
            ));
        }

        let mut timestamp = [0; ENCODED_TIMESTAMP_LEN];
        timestamp.copy_from_slice(rest);

        Ok(Self {
            row,
            family,
            qualifier,
            visibility,
            timestamp: decode_descending_timestamp(timestamp),
        })
    }
}

/// Prefix selector for ordered composite-key scans.
///
/// Fields must be supplied contiguously from `row` onward. For example, a row
/// and family prefix is valid, but a family without a row is not.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompositePrefix {
    /// Exact row prefix component.
    pub row: Option<Slice>,

    /// Exact family prefix component.
    pub family: Option<Slice>,

    /// Exact qualifier prefix component.
    pub qualifier: Option<Slice>,

    /// Exact visibility prefix component.
    pub visibility: Option<Slice>,
}

impl CompositePrefix {
    /// Returns Fjall range bounds covering all encoded keys with this prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if fields are not supplied contiguously from `row`
    /// onward or if the encoded prefix would exceed Fjall's user-key length
    /// limit.
    pub fn range(&self) -> crate::Result<(Bound<UserKey>, Bound<UserKey>)> {
        let mut fields = vec![];

        match (
            self.row.as_ref(),
            self.family.as_ref(),
            self.qualifier.as_ref(),
            self.visibility.as_ref(),
        ) {
            (None, None, None, None) => {}
            (Some(row), None, None, None) => fields.push(row.as_ref()),
            (Some(row), Some(family), None, None) => {
                fields.push(row.as_ref());
                fields.push(family.as_ref());
            }
            (Some(row), Some(family), Some(qualifier), None) => {
                fields.push(row.as_ref());
                fields.push(family.as_ref());
                fields.push(qualifier.as_ref());
            }
            (Some(row), Some(family), Some(qualifier), Some(visibility)) => {
                fields.push(row.as_ref());
                fields.push(family.as_ref());
                fields.push(qualifier.as_ref());
                fields.push(visibility.as_ref());
            }
            _ => {
                return Err(Error::InvalidCompositeKey(
                    "composite prefix fields must be contiguous",
                ));
            }
        }

        let prefix = encode_prefix_fields(&fields);
        validate_encoded_len(prefix.len())?;

        Ok(crate::util::prefix_to_range(&prefix))
    }
}

fn validate_encoded_len(len: usize) -> crate::Result<()> {
    if len > MAX_USER_KEY_LEN {
        return Err(Error::InvalidCompositeKey(
            "encoded composite key exceeds Fjall's user-key length limit",
        ));
    }

    Ok(())
}

fn encode_prefix_fields(fields: &[&[u8]]) -> Vec<u8> {
    let encoded_fields_len = fields
        .iter()
        .map(|field| encoded_field_len(field))
        .sum::<usize>();
    let mut encoded = Vec::with_capacity(1 + encoded_fields_len + ENCODED_TIMESTAMP_LEN);

    encoded.push(FORMAT_VERSION);

    for field in fields {
        encode_field(field, &mut encoded);
    }

    encoded
}

fn encoded_field_len(field: &[u8]) -> usize {
    field
        .iter()
        .map(|byte| {
            if matches!(*byte, FIELD_TERMINATOR | FIELD_ESCAPE) {
                2
            } else {
                1
            }
        })
        .sum::<usize>()
        + 1
}

fn encode_field(field: &[u8], encoded: &mut Vec<u8>) {
    for byte in field {
        match *byte {
            FIELD_TERMINATOR => {
                encoded.push(FIELD_ESCAPE);
                encoded.push(ESCAPED_ZERO);
            }
            FIELD_ESCAPE => {
                encoded.push(FIELD_ESCAPE);
                encoded.push(ESCAPED_ONE);
            }
            byte => encoded.push(byte),
        }
    }

    encoded.push(FIELD_TERMINATOR);
}

fn decode_field(mut remaining: &[u8]) -> crate::Result<(Slice, &[u8])> {
    let mut decoded = vec![];

    loop {
        let (byte, tail) = remaining.split_first().ok_or(Error::InvalidCompositeKey(
            "unterminated composite key field",
        ))?;

        match *byte {
            FIELD_TERMINATOR => return Ok((decoded.into(), tail)),
            FIELD_ESCAPE => {
                let (escaped, next) = tail
                    .split_first()
                    .ok_or(Error::InvalidCompositeKey("unterminated field escape"))?;

                match *escaped {
                    ESCAPED_ZERO => decoded.push(FIELD_TERMINATOR),
                    ESCAPED_ONE => decoded.push(FIELD_ESCAPE),
                    _ => return Err(Error::InvalidCompositeKey("invalid field escape")),
                }

                remaining = next;
            }
            byte => {
                decoded.push(byte);
                remaining = tail;
            }
        }
    }
}

fn encode_descending_timestamp(timestamp: i64) -> [u8; ENCODED_TIMESTAMP_LEN] {
    let ascending = u64::from_ne_bytes(timestamp.to_ne_bytes()) ^ 0x8000_0000_0000_0000;

    (!ascending).to_be_bytes()
}

fn decode_descending_timestamp(encoded: [u8; ENCODED_TIMESTAMP_LEN]) -> i64 {
    let descending = u64::from_be_bytes(encoded);
    let ascending = !descending;

    i64::from_ne_bytes((ascending ^ 0x8000_0000_0000_0000).to_ne_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cmp::Ordering, ops::Bound};
    use test_log::test;

    fn key(
        row: &[u8],
        family: &[u8],
        qualifier: &[u8],
        visibility: &[u8],
        timestamp: i64,
    ) -> CompositeKey {
        CompositeKey {
            row: row.into(),
            family: family.into(),
            qualifier: qualifier.into(),
            visibility: visibility.into(),
            timestamp,
        }
    }

    fn cmp_logical(left: &CompositeKey, right: &CompositeKey) -> Ordering {
        left.row
            .as_ref()
            .cmp(right.row.as_ref())
            .then_with(|| left.family.as_ref().cmp(right.family.as_ref()))
            .then_with(|| left.qualifier.as_ref().cmp(right.qualifier.as_ref()))
            .then_with(|| left.visibility.as_ref().cmp(right.visibility.as_ref()))
            .then_with(|| right.timestamp.cmp(&left.timestamp))
    }

    fn contains(range: &(Bound<UserKey>, Bound<UserKey>), key: &[u8]) -> bool {
        let lower = match &range.0 {
            Bound::Included(bound) => key >= bound.as_ref(),
            Bound::Excluded(bound) => key > bound.as_ref(),
            Bound::Unbounded => true,
        };
        let upper = match &range.1 {
            Bound::Included(bound) => key <= bound.as_ref(),
            Bound::Excluded(bound) => key < bound.as_ref(),
            Bound::Unbounded => true,
        };

        lower && upper
    }

    #[test]
    fn encoded_byte_order_matches_logical_order() -> crate::Result<()> {
        let mut logical = vec![
            key(b"user1", b"profile", b"email", b"admin", 7),
            key(b"user1", b"profile", b"email", b"admin", 9),
            key(b"user1", b"profile", b"email", b"admin", 8),
            key(b"user1", b"profile", b"email", b"admin", -1),
            key(b"user1", b"profile", b"email", b"admin", i64::MAX),
            key(b"user1", b"profile", b"email", b"admin", i64::MIN),
            key(b"user1", b"profile", b"name", b"admin", 5),
            key(b"", b"", b"", b"", 0),
            key(b"\0", b"", b"", b"", 0),
            key(b"\x01", b"", b"", b"", 0),
            key(b"\xff", b"", b"", b"", 0),
            key(b"user1", b"\0fam", b"qual\x01", b"\xff", -10),
            key(b"user2", b"profile", b"email", b"admin", 1),
        ];
        logical.sort_by(cmp_logical);

        let mut encoded = logical
            .iter()
            .map(CompositeKey::encode)
            .collect::<crate::Result<Vec<_>>>()?;
        encoded.reverse();
        encoded.sort();

        let decoded = encoded
            .iter()
            .map(|encoded| CompositeKey::decode(encoded))
            .collect::<crate::Result<Vec<_>>>()?;

        assert_eq!(decoded, logical);

        Ok(())
    }

    #[test]
    fn roundtrips_binary_fields_and_timestamp_extremes() -> crate::Result<()> {
        for timestamp in [i64::MIN, -1, 0, 1, i64::MAX] {
            let original = key(
                b"\0\x01\xfe\xff",
                b"fam\0",
                b"\x01qual",
                b"\xff\0",
                timestamp,
            );
            let encoded = original.encode()?;
            let decoded = CompositeKey::decode(&encoded)?;

            assert_eq!(decoded, original);
        }

        Ok(())
    }

    #[test]
    fn prefix_range_matches_contiguous_prefix_fields() -> crate::Result<()> {
        let range = CompositePrefix {
            row: Some("user1".into()),
            family: Some("profile".into()),
            qualifier: None,
            visibility: None,
        }
        .range()?;

        let matching = key(b"user1", b"profile", b"email", b"admin", 7).encode()?;
        let other_family = key(b"user1", b"settings", b"email", b"admin", 7).encode()?;
        let other_row = key(b"user2", b"profile", b"email", b"admin", 7).encode()?;

        assert!(contains(&range, &matching));
        assert!(!contains(&range, &other_family));
        assert!(!contains(&range, &other_row));

        Ok(())
    }

    #[test]
    fn empty_prefix_range_is_scoped_to_composite_version() -> crate::Result<()> {
        let range = CompositePrefix::default().range()?;
        let matching = key(b"user1", b"profile", b"email", b"admin", 7).encode()?;

        assert!(contains(&range, &matching));
        assert!(!contains(&range, &[0]));
        assert!(!contains(&range, &[2]));

        Ok(())
    }

    #[test]
    fn rejects_non_contiguous_prefix_fields() {
        let prefix = CompositePrefix {
            row: Some("user1".into()),
            family: None,
            qualifier: Some("email".into()),
            visibility: None,
        };

        assert!(prefix.range().is_err());
    }

    #[test]
    fn rejects_malformed_encoded_keys() {
        assert!(CompositeKey::decode(&[]).is_err());
        assert!(CompositeKey::decode(&[2]).is_err());
        assert!(CompositeKey::decode(&[FORMAT_VERSION, FIELD_ESCAPE]).is_err());
        assert!(CompositeKey::decode(&[FORMAT_VERSION, FIELD_ESCAPE, 3]).is_err());
        assert!(CompositeKey::decode(&[FORMAT_VERSION, 0, 0, 0, 0, 0]).is_err());
    }
}
