// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Versioned cell helpers built on ordered composite keys.

use crate::{Keyspace, Readable, Slice, UserKey, UserValue};

use super::{CompositeKey, CompositePrefix};

/// A logical secure cell without a version timestamp.
///
/// Versions are grouped by the full `(row, family, qualifier, visibility)`
/// tuple. Cross-visibility latest-version selection is intentionally not
/// provided here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cell {
    /// Row bytes.
    pub row: Slice,

    /// Column family bytes.
    pub family: Slice,

    /// Column qualifier bytes.
    pub qualifier: Slice,

    /// Visibility expression bytes.
    pub visibility: Slice,
}

impl Cell {
    /// Returns a timestamped version of this cell.
    #[must_use]
    pub fn version(&self, timestamp: i64) -> VersionedCell {
        VersionedCell {
            cell: self.clone(),
            timestamp,
        }
    }

    fn composite_prefix(&self) -> CompositePrefix {
        CompositePrefix {
            row: Some(self.row.clone()),
            family: Some(self.family.clone()),
            qualifier: Some(self.qualifier.clone()),
            visibility: Some(self.visibility.clone()),
        }
    }
}

/// A logical secure cell with an explicit user-level version timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedCell {
    /// Logical cell identity.
    pub cell: Cell,

    /// User-level version timestamp.
    pub timestamp: i64,
}

impl VersionedCell {
    /// Encodes this versioned cell as a sortable Fjall user key.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded key would exceed Fjall's user-key
    /// length limit.
    pub fn encode(&self) -> crate::Result<UserKey> {
        CompositeKey::from(self).encode()
    }
}

impl From<&VersionedCell> for CompositeKey {
    fn from(cell: &VersionedCell) -> Self {
        Self {
            row: cell.cell.row.clone(),
            family: cell.cell.family.clone(),
            qualifier: cell.cell.qualifier.clone(),
            visibility: cell.cell.visibility.clone(),
            timestamp: cell.timestamp,
        }
    }
}

impl From<CompositeKey> for VersionedCell {
    fn from(key: CompositeKey) -> Self {
        Self {
            cell: Cell {
                row: key.row,
                family: key.family,
                qualifier: key.qualifier,
                visibility: key.visibility,
            },
            timestamp: key.timestamp,
        }
    }
}

/// Version scan controls for a version group or composite-key prefix.
///
/// Timestamp bounds are inclusive logical timestamp filters applied after the
/// storage snapshot is chosen.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionScan {
    /// Lowest timestamp to return, inclusive.
    pub min_timestamp: Option<i64>,

    /// Highest timestamp to return, inclusive.
    pub max_timestamp: Option<i64>,

    /// Maximum number of matching versions to return.
    pub max_versions: Option<usize>,
}

impl VersionScan {
    pub(crate) fn includes(&self, timestamp: i64) -> bool {
        self.min_timestamp.is_none_or(|min| timestamp >= min)
            && self.max_timestamp.is_none_or(|max| timestamp <= max)
    }

    pub(crate) fn is_satisfied_by(&self, count: usize) -> bool {
        self.max_versions.is_some_and(|max| count >= max)
    }
}

/// A decoded versioned cell and its value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedEntry {
    /// Decoded versioned cell.
    pub cell: VersionedCell,

    /// Stored value.
    pub value: UserValue,
}

/// Read helpers for explicit user-level versioned cells.
pub trait VersionedCellReadExt: Readable {
    /// Retrieves one exact version of a cell from a readable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if key encoding fails or the storage read fails.
    fn get_version(
        &self,
        keyspace: impl AsRef<Keyspace>,
        cell: &VersionedCell,
    ) -> crate::Result<Option<UserValue>> {
        self.get(keyspace, cell.encode()?)
    }

    /// Retrieves the newest version in one `(row, family, qualifier, visibility)` group.
    ///
    /// # Errors
    ///
    /// Returns an error if key encoding, key decoding, or storage reads fail.
    fn latest_version(
        &self,
        keyspace: impl AsRef<Keyspace>,
        cell: &Cell,
    ) -> crate::Result<Option<VersionedEntry>> {
        Ok(self
            .scan_versions(
                keyspace,
                cell,
                VersionScan {
                    max_versions: Some(1),
                    ..VersionScan::default()
                },
            )?
            .into_iter()
            .next())
    }

    /// Scans versions in one `(row, family, qualifier, visibility)` group.
    ///
    /// Results follow encoded order, which means newest matching timestamp
    /// first for a single version group.
    ///
    /// # Errors
    ///
    /// Returns an error if prefix encoding, key decoding, or storage reads fail.
    fn scan_versions(
        &self,
        keyspace: impl AsRef<Keyspace>,
        cell: &Cell,
        scan: VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>> {
        self.scan_versioned_prefix(keyspace, &cell.composite_prefix(), scan)
    }

    /// Scans versioned cells matching a composite-key prefix.
    ///
    /// This supports row, family, qualifier, or full-cell scans while preserving
    /// the encoded composite-key order.
    ///
    /// # Errors
    ///
    /// Returns an error if prefix encoding, key decoding, or storage reads fail.
    fn scan_versioned_prefix(
        &self,
        keyspace: impl AsRef<Keyspace>,
        prefix: &CompositePrefix,
        scan: VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>> {
        let range = prefix.range()?;
        let mut entries = Vec::new();

        for guard in self.range(keyspace, range) {
            let (key, value) = guard.into_inner()?;
            let cell = VersionedCell::from(CompositeKey::decode(&key)?);

            if scan.includes(cell.timestamp) {
                entries.push(VersionedEntry { cell, value });
            }

            if scan.is_satisfied_by(entries.len()) {
                break;
            }
        }

        Ok(entries)
    }
}

impl<T: Readable> VersionedCellReadExt for T {}

/// Read and write helpers for explicit user-level versioned cells on raw keyspaces.
pub trait VersionedCellKeyspaceExt {
    /// Inserts or replaces one exact version of a cell.
    ///
    /// The timestamp must be supplied explicitly through [`VersionedCell`].
    ///
    /// # Errors
    ///
    /// Returns an error if key encoding fails or the storage write fails.
    fn insert_version<V: Into<UserValue>>(
        &self,
        cell: &VersionedCell,
        value: V,
    ) -> crate::Result<()>;

    /// Retrieves one exact version of a cell.
    ///
    /// # Errors
    ///
    /// Returns an error if key encoding fails or the storage read fails.
    fn get_version(&self, cell: &VersionedCell) -> crate::Result<Option<UserValue>>;

    /// Retrieves the newest version in one `(row, family, qualifier, visibility)` group.
    ///
    /// # Errors
    ///
    /// Returns an error if key encoding, key decoding, or storage reads fail.
    fn latest_version(&self, cell: &Cell) -> crate::Result<Option<VersionedEntry>>;

    /// Scans versions in one `(row, family, qualifier, visibility)` group.
    ///
    /// Results are newest matching timestamp first.
    ///
    /// # Errors
    ///
    /// Returns an error if prefix encoding, key decoding, or storage reads fail.
    fn scan_versions(&self, cell: &Cell, scan: VersionScan) -> crate::Result<Vec<VersionedEntry>>;

    /// Scans versioned cells matching a composite-key prefix in encoded order.
    ///
    /// # Errors
    ///
    /// Returns an error if prefix encoding, key decoding, or storage reads fail.
    fn scan_versioned_prefix(
        &self,
        prefix: &CompositePrefix,
        scan: VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>>;

    /// Deletes one exact version of a cell.
    ///
    /// # Errors
    ///
    /// Returns an error if key encoding fails or the storage delete fails.
    fn delete_version(&self, cell: &VersionedCell) -> crate::Result<()>;

    /// Deletes all versions in one `(row, family, qualifier, visibility)` group.
    ///
    /// This helper issues one raw delete per matching encoded key.
    ///
    /// # Errors
    ///
    /// Returns an error if prefix encoding, key decoding, or storage deletes fail.
    fn delete_versions(&self, cell: &Cell) -> crate::Result<()>;

    /// Deletes versions older than `timestamp` in one version group.
    ///
    /// The cutoff is exclusive: a version with exactly `timestamp` is retained.
    ///
    /// # Errors
    ///
    /// Returns an error if prefix encoding, key decoding, or storage deletes fail.
    fn delete_versions_older_than(&self, cell: &Cell, timestamp: i64) -> crate::Result<()>;
}

impl VersionedCellKeyspaceExt for Keyspace {
    fn insert_version<V: Into<UserValue>>(
        &self,
        cell: &VersionedCell,
        value: V,
    ) -> crate::Result<()> {
        self.insert(cell.encode()?, value)
    }

    fn get_version(&self, cell: &VersionedCell) -> crate::Result<Option<UserValue>> {
        self.get(cell.encode()?)
    }

    fn latest_version(&self, cell: &Cell) -> crate::Result<Option<VersionedEntry>> {
        Ok(self
            .scan_versions(
                cell,
                VersionScan {
                    max_versions: Some(1),
                    ..VersionScan::default()
                },
            )?
            .into_iter()
            .next())
    }

    fn scan_versions(&self, cell: &Cell, scan: VersionScan) -> crate::Result<Vec<VersionedEntry>> {
        self.scan_versioned_prefix(&cell.composite_prefix(), scan)
    }

    fn scan_versioned_prefix(
        &self,
        prefix: &CompositePrefix,
        scan: VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>> {
        let range = prefix.range()?;
        let mut entries = Vec::new();

        for guard in self.range(range) {
            let (key, value) = guard.into_inner()?;
            let cell = VersionedCell::from(CompositeKey::decode(&key)?);

            if scan.includes(cell.timestamp) {
                entries.push(VersionedEntry { cell, value });
            }

            if scan.is_satisfied_by(entries.len()) {
                break;
            }
        }

        Ok(entries)
    }

    fn delete_version(&self, cell: &VersionedCell) -> crate::Result<()> {
        self.remove(cell.encode()?)
    }

    fn delete_versions(&self, cell: &Cell) -> crate::Result<()> {
        delete_versions_matching(self, cell, |_| true)
    }

    fn delete_versions_older_than(&self, cell: &Cell, timestamp: i64) -> crate::Result<()> {
        delete_versions_matching(self, cell, |version| version < timestamp)
    }
}

fn delete_versions_matching(
    keyspace: &Keyspace,
    cell: &Cell,
    mut predicate: impl FnMut(i64) -> bool,
) -> crate::Result<()> {
    let range = cell.composite_prefix().range()?;
    let mut keys = Vec::new();

    for guard in keyspace.range(range) {
        let key = guard.key()?;
        let versioned_cell = VersionedCell::from(CompositeKey::decode(&key)?);

        if predicate(versioned_cell.timestamp) {
            keys.push(key);
        }
    }

    for key in keys {
        keyspace.remove(key)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, KeyspaceCreateOptions};
    use test_log::test;

    fn open_keyspace() -> crate::Result<(tempfile::TempDir, Database, Keyspace)> {
        let folder = tempfile::tempdir()?;
        let db = Database::builder(&folder).open()?;
        let keyspace = db.keyspace("secure", KeyspaceCreateOptions::default)?;

        Ok((folder, db, keyspace))
    }

    fn cell() -> Cell {
        Cell {
            row: "row-a".into(),
            family: "family-a".into(),
            qualifier: "qualifier-a".into(),
            visibility: "admin".into(),
        }
    }

    fn timestamps(entries: &[VersionedEntry]) -> Vec<i64> {
        entries.iter().map(|entry| entry.cell.timestamp).collect()
    }

    fn values(entries: &[VersionedEntry]) -> Vec<UserValue> {
        entries.iter().map(|entry| entry.value.clone()).collect()
    }

    #[test]
    fn scans_versions_newest_first() -> crate::Result<()> {
        let (_folder, _db, keyspace) = open_keyspace()?;
        let cell = cell();

        keyspace.insert_version(&cell.version(7), "value-7")?;
        keyspace.insert_version(&cell.version(9), "value-9")?;
        keyspace.insert_version(&cell.version(5), "value-5")?;

        let history = keyspace.scan_versions(&cell, VersionScan::default())?;

        assert_eq!(vec![9, 7, 5], timestamps(&history));
        assert_eq!(
            vec![
                UserValue::from("value-9"),
                UserValue::from("value-7"),
                UserValue::from("value-5"),
            ],
            values(&history),
        );

        Ok(())
    }

    #[test]
    fn reads_exact_and_latest_versions() -> crate::Result<()> {
        let (_folder, _db, keyspace) = open_keyspace()?;
        let cell = cell();

        keyspace.insert_version(&cell.version(1), "old")?;
        keyspace.insert_version(&cell.version(2), "new")?;

        assert_eq!(
            Some(UserValue::from("old")),
            keyspace.get_version(&cell.version(1))?,
        );
        assert_eq!(
            Some(VersionedEntry {
                cell: cell.version(2),
                value: UserValue::from("new"),
            }),
            keyspace.latest_version(&cell)?,
        );

        Ok(())
    }

    #[test]
    fn applies_timestamp_bounds_and_version_limit() -> crate::Result<()> {
        let (_folder, _db, keyspace) = open_keyspace()?;
        let cell = cell();

        for timestamp in [1, 2, 3, 4, 5] {
            keyspace.insert_version(&cell.version(timestamp), timestamp.to_string())?;
        }

        let history = keyspace.scan_versions(
            &cell,
            VersionScan {
                min_timestamp: Some(2),
                max_timestamp: Some(4),
                max_versions: Some(2),
            },
        )?;

        assert_eq!(vec![4, 3], timestamps(&history));

        Ok(())
    }

    #[test]
    fn snapshot_reads_filter_versions_after_storage_snapshot() -> crate::Result<()> {
        let (_folder, db, keyspace) = open_keyspace()?;
        let cell = cell();

        keyspace.insert_version(&cell.version(1), "v1")?;
        let snapshot = db.snapshot();
        keyspace.insert_version(&cell.version(2), "v2")?;

        assert_eq!(
            vec![1],
            timestamps(&snapshot.scan_versions(&keyspace, &cell, VersionScan::default())?),
        );
        assert_eq!(
            vec![2, 1],
            timestamps(&keyspace.scan_versions(&cell, VersionScan::default())?),
        );

        Ok(())
    }

    #[test]
    fn deletes_exact_group_and_older_versions() -> crate::Result<()> {
        let (_folder, _db, keyspace) = open_keyspace()?;
        let cell = cell();

        for timestamp in [1, 2, 3, 4] {
            keyspace.insert_version(&cell.version(timestamp), timestamp.to_string())?;
        }

        keyspace.delete_version(&cell.version(3))?;
        assert_eq!(
            vec![4, 2, 1],
            timestamps(&keyspace.scan_versions(&cell, VersionScan::default())?),
        );

        keyspace.delete_versions_older_than(&cell, 2)?;
        assert_eq!(
            vec![4, 2],
            timestamps(&keyspace.scan_versions(&cell, VersionScan::default())?),
        );

        keyspace.delete_versions(&cell)?;
        assert!(keyspace
            .scan_versions(&cell, VersionScan::default())?
            .is_empty());

        Ok(())
    }

    #[test]
    fn scans_composite_prefix_in_encoded_order() -> crate::Result<()> {
        let (_folder, _db, keyspace) = open_keyspace()?;
        let first = cell();
        let second = Cell {
            row: "row-a".into(),
            family: "family-a".into(),
            qualifier: "qualifier-b".into(),
            visibility: "admin".into(),
        };

        keyspace.insert_version(&second.version(1), "second")?;
        keyspace.insert_version(&first.version(1), "first-old")?;
        keyspace.insert_version(&first.version(2), "first-new")?;

        let entries = keyspace.scan_versioned_prefix(
            &CompositePrefix {
                row: Some("row-a".into()),
                family: Some("family-a".into()),
                qualifier: None,
                visibility: None,
            },
            VersionScan::default(),
        )?;

        assert_eq!(
            vec![first.version(2), first.version(1), second.version(1),],
            entries
                .into_iter()
                .map(|entry| entry.cell)
                .collect::<Vec<_>>(),
        );

        Ok(())
    }
}
