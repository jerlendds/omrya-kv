// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Secure database and keyspace wrappers.

use crate::{Database, DatabaseBuilder, Error, Keyspace, UserValue};
use std::{path::Path, sync::Arc};

use super::{
    crypto::{maybe_decrypt_entry, maybe_encrypt_value, SecureKeyspaceOptions, ValueEncryption},
    policy::SecureCompactionPolicy,
    Authorizations, CompositeKey, CompositePrefix, Credentials, KeyspacePermission,
    SecurityProviders, VersionScan, VersionedCell, VersionedEntry, VisibilityExpr,
};

/// Authenticated session context for secure operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session<I> {
    /// Authenticated application identity.
    pub identity: I,

    /// Authorization labels resolved for the identity.
    pub auths: Authorizations,
}

/// Secure database wrapper backed by a raw [`Database`].
#[derive(Clone)]
pub struct SecureDatabase<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: Database,
    security: Arc<SecurityProviders<I>>,
}

impl<I> SecureDatabase<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates a builder for a secure database at `path`.
    pub fn builder(path: impl AsRef<Path>) -> SecureDatabaseBuilder<I> {
        SecureDatabaseBuilder::new(path.as_ref())
    }

    /// Wraps an already-open database with security providers.
    #[must_use]
    pub fn new(inner: Database, security: SecurityProviders<I>) -> Self {
        Self {
            inner,
            security: Arc::new(security),
        }
    }

    /// Returns the wrapped raw database.
    #[must_use]
    pub fn inner(&self) -> &Database {
        &self.inner
    }

    /// Authenticates credentials and resolves a session.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication fails or the authorizor cannot
    /// resolve authorization labels.
    pub fn authenticate(&self, credentials: &Credentials) -> crate::Result<Session<I>> {
        self.security.authenticate(credentials)
    }

    /// Creates or opens a secure keyspace handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying database cannot open the keyspace.
    ///
    /// # Panics
    ///
    /// Panics if the keyspace name is invalid.
    pub fn secure_keyspace(
        &self,
        name: &str,
        create_options: impl FnOnce() -> SecureKeyspaceOptions,
    ) -> crate::Result<SecureKeyspace<I>> {
        let physical_name = physical_keyspace_name(name);
        let SecureKeyspaceOptions {
            create_options,
            encryption,
            retention,
        } = create_options();
        let encryption = encryption.map(|config| ValueEncryption::new(name, config));
        let create_options = install_retention_policy(
            name,
            create_options,
            retention,
            self.security.audit_config(),
        )?;
        let inner = self.inner.raw_keyspace(&physical_name, || create_options)?;

        Ok(SecureKeyspace {
            inner,
            name: name.to_owned(),
            security: self.security.clone(),
            encryption,
        })
    }
}

/// Builder for [`SecureDatabase`].
pub struct SecureDatabaseBuilder<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: DatabaseBuilder<Database>,
    authenticator: Option<Arc<dyn super::Authenticator<Identity = I>>>,
    permission_handler: Option<Arc<dyn super::PermissionHandler<I>>>,
    authorizor: Option<Arc<dyn super::Authorizor<I>>>,
    audit: Option<super::audit::AuditConfig<I>>,
}

impl<I> SecureDatabaseBuilder<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn new(path: &Path) -> Self {
        Self {
            inner: Database::builder(path),
            authenticator: None,
            permission_handler: None,
            authorizor: None,
            audit: None,
        }
    }

    /// Sets the authenticator.
    #[must_use]
    pub fn authenticator<A>(mut self, authenticator: A) -> Self
    where
        A: super::Authenticator<Identity = I>,
    {
        self.authenticator = Some(Arc::new(authenticator));
        self
    }

    /// Sets the permission handler.
    #[must_use]
    pub fn permission_handler<P>(mut self, permission_handler: P) -> Self
    where
        P: super::PermissionHandler<I>,
    {
        self.permission_handler = Some(Arc::new(permission_handler));
        self
    }

    /// Sets the authorizor.
    #[must_use]
    pub fn authorizor<Z>(mut self, authorizor: Z) -> Self
    where
        Z: super::Authorizor<I>,
    {
        self.authorizor = Some(Arc::new(authorizor));
        self
    }

    /// Installs an audit sink.
    #[must_use]
    pub fn audit_sink<A>(mut self, sink: A, failure_mode: super::AuditFailureMode) -> Self
    where
        A: super::AuditSink<I>,
    {
        self.audit = Some(super::audit::AuditConfig::new(sink, failure_mode));
        self
    }

    /// Opens the secure database.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider is missing or the raw database cannot
    /// be opened.
    pub fn open(self) -> crate::Result<SecureDatabase<I>> {
        let authenticator = self
            .authenticator
            .ok_or(Error::MissingSecurityProvider("authenticator"))?;
        let permission_handler = self
            .permission_handler
            .ok_or(Error::MissingSecurityProvider("permission_handler"))?;
        let authorizor = self
            .authorizor
            .ok_or(Error::MissingSecurityProvider("authorizor"))?;

        let inner = self.inner.open()?;
        let security = SecurityProviders {
            authenticator,
            permission_handler,
            authorizor,
            audit: self.audit,
        };

        Ok(SecureDatabase {
            inner,
            security: Arc::new(security),
        })
    }
}

pub(super) fn install_retention_policy<I>(
    name: &str,
    create_options: crate::KeyspaceCreateOptions,
    retention: Option<super::RetentionPolicy>,
    audit: Option<super::audit::AuditConfig<I>>,
) -> crate::Result<crate::KeyspaceCreateOptions>
where
    I: Clone + Send + Sync + 'static,
{
    let Some(retention) = retention else {
        return Ok(create_options);
    };

    Ok(SecureCompactionPolicy::new(name, retention, audit)?.install_on(create_options))
}

/// Secure keyspace wrapper that requires a [`Session`] for data access.
#[derive(Clone)]
pub struct SecureKeyspace<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: Keyspace,
    name: String,
    security: Arc<SecurityProviders<I>>,
    encryption: Option<ValueEncryption>,
}

impl<I> SecureKeyspace<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Returns the secure keyspace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the wrapped raw keyspace.
    #[must_use]
    pub fn inner(&self) -> &Keyspace {
        &self.inner
    }

    /// Inserts or replaces one versioned cell after checking write permission.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, the visibility expression is
    /// invalid or non-canonical, key encoding fails, or storage rejects the
    /// write.
    pub fn insert_version<V>(
        &self,
        session: &Session<I>,
        cell: &VersionedCell,
        value: V,
    ) -> crate::Result<()>
    where
        V: Into<UserValue>,
    {
        self.check(session, KeyspacePermission::Write)?;
        let canonical_cell = canonicalize_cell(cell)?;
        let encoded_key = canonical_cell.encode()?;
        let stored_value = maybe_encrypt_value(self.encryption.as_ref(), &encoded_key, value)?;

        self.inner.insert(encoded_key, stored_value)
    }

    /// Retrieves one exact version if it is visible to the session.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, key encoding fails, storage
    /// rejects the read, or the stored visibility expression is invalid.
    pub fn get_version(
        &self,
        session: &Session<I>,
        cell: &VersionedCell,
    ) -> crate::Result<Option<UserValue>> {
        self.check(session, KeyspacePermission::Read)?;

        if !is_visible(cell.cell.visibility.as_ref(), &session.auths)? {
            return Ok(None);
        }

        let encoded_key = cell.encode()?;
        let Some(stored) = self.inner.get(&encoded_key)? else {
            return Ok(None);
        };

        maybe_decrypt_entry(self.encryption.as_ref(), &encoded_key, stored).map(Some)
    }

    /// Scans versioned cells matching a composite-key prefix in encoded order.
    ///
    /// Returned records are filtered by the session's authorization labels.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, prefix encoding fails,
    /// storage rejects the scan, or a stored key has an invalid visibility
    /// expression.
    pub fn scan_versioned_prefix(
        &self,
        session: &Session<I>,
        prefix: &CompositePrefix,
        scan: &VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>> {
        self.check(session, KeyspacePermission::Read)?;

        let range = prefix.range()?;
        let mut entries = Vec::new();

        for guard in self.inner.range(range) {
            let (key, stored_value) = guard.into_inner()?;
            let cell = VersionedCell::from(CompositeKey::decode(&key)?);

            if scan.includes(cell.timestamp)
                && is_visible(cell.cell.visibility.as_ref(), &session.auths)?
            {
                let value = maybe_decrypt_entry(self.encryption.as_ref(), &key, stored_value)?;
                entries.push(VersionedEntry { cell, value });
            }

            if scan.is_satisfied_by(entries.len()) {
                break;
            }
        }

        Ok(entries)
    }

    /// Deletes one exact version after checking delete permission.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, the visibility expression is
    /// invalid or non-canonical, key encoding fails, or storage rejects the
    /// delete.
    pub fn delete_version(&self, session: &Session<I>, cell: &VersionedCell) -> crate::Result<()> {
        self.check(session, KeyspacePermission::Delete)?;
        let canonical_cell = canonicalize_cell(cell)?;

        self.inner.remove(canonical_cell.encode()?)
    }

    fn check(&self, session: &Session<I>, permission: KeyspacePermission) -> crate::Result<()> {
        self.security
            .check_keyspace_permission(&session.identity, &self.name, permission)
    }
}

pub(super) fn canonicalize_cell(cell: &VersionedCell) -> crate::Result<VersionedCell> {
    let visibility = parse_visibility(cell.cell.visibility.as_ref())?;

    if visibility.as_bytes() != cell.cell.visibility.as_ref() {
        return Err(Error::InvalidVisibilityExpression(
            "secure writes require canonical visibility expressions",
        ));
    }

    Ok(cell.clone())
}

fn parse_visibility(bytes: &[u8]) -> crate::Result<VisibilityExpr> {
    let expr = std::str::from_utf8(bytes).map_err(|_| {
        Error::InvalidVisibilityExpression("visibility expression must be valid UTF-8")
    })?;

    VisibilityExpr::parse(expr)
}

pub(super) fn is_visible(bytes: &[u8], auths: &Authorizations) -> crate::Result<bool> {
    Ok(parse_visibility(bytes)?.evaluate(auths))
}

pub(super) fn physical_keyspace_name(name: &str) -> String {
    format!("{}{name}", super::RAW_KEYSPACE_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure::{
            AllowAllPermissions, AuditEvent, AuditFailureMode, AuditSink, CryptoContext,
            CryptoProvider, EncryptionConfig, EncryptionScope, RetentionPolicy,
            StaticAuthenticator, StaticAuthorizor, StaticPermissionHandler,
        },
        Slice,
    };
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use test_log::test;

    fn authenticator() -> StaticAuthenticator<String> {
        StaticAuthenticator::new().with_principal("alice", "secret", "alice".to_string())
    }

    fn authorizor(labels: &[&str]) -> crate::Result<StaticAuthorizor> {
        Ok(StaticAuthorizor::new(Authorizations::from_labels(
            labels.iter().copied(),
        )?))
    }

    fn cell(visibility: &str, timestamp: i64) -> VersionedCell {
        VersionedCell {
            cell: super::super::Cell {
                row: "row".into(),
                family: "family".into(),
                qualifier: "qualifier".into(),
                visibility: visibility.into(),
            },
            timestamp,
        }
    }

    #[derive(Clone)]
    struct TaggedXorCryptoProvider {
        key: u8,
    }

    impl CryptoProvider for TaggedXorCryptoProvider {
        fn encrypt(&self, _context: CryptoContext<'_>, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
            let mut ciphertext = Vec::with_capacity(plaintext.len() + 1);
            ciphertext.push(self.key);
            ciphertext.extend(plaintext.iter().map(|byte| byte ^ self.key));
            Ok(ciphertext)
        }

        fn decrypt(
            &self,
            _context: CryptoContext<'_>,
            ciphertext: &[u8],
        ) -> crate::Result<Vec<u8>> {
            let Some((&key, rest)) = ciphertext.split_first() else {
                return Err(Error::Crypto("missing test key tag"));
            };

            if key != self.key {
                return Err(Error::Crypto("wrong test key"));
            }

            Ok(rest.iter().map(|byte| byte ^ self.key).collect())
        }
    }

    fn encryption(key: u8) -> EncryptionConfig {
        EncryptionConfig::new(TaggedXorCryptoProvider { key }, EncryptionScope::Value)
    }

    #[derive(Clone, Default)]
    struct RecordingAuditSink {
        events: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }

    impl RecordingAuditSink {
        fn failing() -> Self {
            Self {
                events: Arc::default(),
                fail: true,
            }
        }

        fn events(&self) -> Vec<String> {
            match self.events.lock() {
                Ok(events) => events.clone(),
                Err(err) => panic!("audit events lock: {err}"),
            }
        }
    }

    impl AuditSink<String> for RecordingAuditSink {
        fn record(&self, event: AuditEvent<'_, String>) -> crate::Result<()> {
            if self.fail {
                return Err(Error::Audit("test audit failure"));
            }

            let label = match event {
                AuditEvent::AuthenticationSucceeded { .. } => "auth-succeeded".to_string(),
                AuditEvent::AuthenticationFailed => "auth-failed".to_string(),
                AuditEvent::AuthorizationDenied { keyspace, .. } => {
                    format!("authorization-denied:{keyspace}")
                }
                AuditEvent::PolicyViolation { keyspace } => {
                    format!("policy-violation:{keyspace}")
                }
                AuditEvent::CompactionDeleted { keyspace, reason } => {
                    format!("compaction-deleted:{keyspace}:{reason:?}")
                }
                AuditEvent::KeyspaceAccess { keyspace, .. } => {
                    format!("keyspace-access:{keyspace}")
                }
            };

            match self.events.lock() {
                Ok(mut events) => events.push(label),
                Err(err) => panic!("audit events lock: {err}"),
            }
            Ok(())
        }
    }

    fn row_prefix() -> CompositePrefix {
        CompositePrefix {
            row: Some(Slice::from("row")),
            family: None,
            qualifier: None,
            visibility: None,
        }
    }

    fn unix_seconds_now() -> i64 {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());

        i64::try_from(seconds).unwrap_or(i64::MAX)
    }

    #[test]
    fn missing_providers_fail_closed() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;

        assert!(SecureDatabase::<String>::builder(&folder).open().is_err());

        Ok(())
    }

    #[test]
    fn rejects_bad_credentials() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;

        assert!(matches!(
            db.authenticate(&Credentials::new("alice", "wrong")),
            Err(Error::AuthenticationDenied),
        ));

        Ok(())
    }

    #[test]
    fn permission_denial_blocks_writes() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(StaticPermissionHandler::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", SecureKeyspaceOptions::default)?;

        assert!(matches!(
            keyspace.insert_version(&session, &cell("admin", 1), "value"),
            Err(Error::PermissionDenied("keyspace:write")),
        ));

        Ok(())
    }

    #[test]
    fn scans_filter_unauthorized_records() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(
                StaticPermissionHandler::new()
                    .with_keyspace_permission("events", KeyspacePermission::Read)
                    .with_keyspace_permission("events", KeyspacePermission::Write),
            )
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", SecureKeyspaceOptions::default)?;

        keyspace.insert_version(&session, &cell("admin", 2), "admin")?;
        keyspace.insert_version(&session, &cell("admin|audit", 1), "audit-or-admin")?;
        keyspace.inner.insert(cell("audit", 3).encode()?, "audit")?;

        let entries = keyspace.scan_versioned_prefix(
            &session,
            &CompositePrefix {
                row: Some(Slice::from("row")),
                family: None,
                qualifier: None,
                visibility: None,
            },
            &VersionScan::default(),
        )?;

        assert_eq!(2, entries.len());
        assert!(entries
            .iter()
            .all(|entry| entry.cell.cell.visibility.as_ref() != b"audit"));

        Ok(())
    }

    #[test]
    fn raw_open_of_secure_physical_keyspace_is_rejected() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;

        db.secure_keyspace("events", SecureKeyspaceOptions::default)?;

        assert!(matches!(
            db.inner.keyspace(
                "$fjall.secure.events",
                crate::KeyspaceCreateOptions::default
            ),
            Err(Error::ReservedKeyspaceName),
        ));

        Ok(())
    }

    #[test]
    fn writes_require_canonical_visibility() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin", "audit"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", SecureKeyspaceOptions::default)?;

        assert!(matches!(
            keyspace.insert_version(&session, &cell("audit&admin", 1), "value"),
            Err(Error::InvalidVisibilityExpression(_)),
        ));
        keyspace.insert_version(&session, &cell("admin&audit", 1), "value")?;

        Ok(())
    }

    #[test]
    fn encrypted_values_are_not_stored_as_plaintext_and_decrypt_on_read() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_encryption(encryption(0x5a))
        })?;
        let cell = cell("admin", 7);

        keyspace.insert_version(&session, &cell, "plaintext")?;

        let encoded_key = cell.encode()?;
        let stored = keyspace
            .inner
            .get(&encoded_key)?
            .expect("value should exist");
        assert_ne!(stored.as_ref(), b"plaintext");
        assert_eq!(
            Some(UserValue::from("plaintext")),
            keyspace.get_version(&session, &cell)?,
        );

        Ok(())
    }

    #[test]
    fn wrong_encryption_provider_fails_closed() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let writer = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_encryption(encryption(0x5a))
        })?;
        let reader = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_encryption(encryption(0x33))
        })?;
        let cell = cell("admin", 7);

        writer.insert_version(&session, &cell, "plaintext")?;

        assert!(matches!(
            reader.get_version(&session, &cell),
            Err(Error::Crypto("wrong test key")),
        ));

        Ok(())
    }

    #[test]
    fn malformed_retention_policy_rejects_keyspace_configuration() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;

        assert!(matches!(
            db.secure_keyspace("events", || SecureKeyspaceOptions::default()
                .with_retention(RetentionPolicy {
                    max_versions: Some(0),
                    ttl: None,
                })),
            Err(Error::InvalidPolicy(
                "max_versions must be greater than zero"
            )),
        ));

        Ok(())
    }

    #[test]
    fn retention_compaction_enforces_max_versions_per_visibility_group() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let audit = RecordingAuditSink::default();
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .audit_sink(audit.clone(), AuditFailureMode::FailClosed)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_retention(RetentionPolicy {
                max_versions: Some(2),
                ttl: None,
            })
        })?;

        for timestamp in [1, 2, 3] {
            keyspace.insert_version(&session, &cell("admin", timestamp), timestamp.to_string())?;
            keyspace.inner.rotate_memtable_and_wait()?;
        }

        keyspace.inner.major_compact()?;

        let timestamps = keyspace
            .scan_versioned_prefix(&session, &row_prefix(), &VersionScan::default())?
            .into_iter()
            .map(|entry| entry.cell.timestamp)
            .collect::<Vec<_>>();
        assert_eq!(vec![3, 2], timestamps);
        assert_eq!(None, keyspace.get_version(&session, &cell("admin", 1))?);
        assert!(audit
            .events()
            .contains(&"compaction-deleted:events:MaxVersions".to_string()));

        Ok(())
    }

    #[test]
    fn retention_compaction_enforces_ttl() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_retention(RetentionPolicy {
                max_versions: None,
                ttl: Some(Duration::from_secs(1)),
            })
        })?;
        let fresh_timestamp = unix_seconds_now().saturating_add(3_600);

        keyspace.insert_version(&session, &cell("admin", 0), "expired")?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.insert_version(&session, &cell("admin", fresh_timestamp), "fresh")?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.inner.major_compact()?;

        assert_eq!(None, keyspace.get_version(&session, &cell("admin", 0))?);
        assert_eq!(
            Some(UserValue::from("fresh")),
            keyspace.get_version(&session, &cell("admin", fresh_timestamp))?,
        );

        Ok(())
    }

    #[test]
    fn retention_compaction_preserves_tombstone_correctness() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_retention(RetentionPolicy {
                max_versions: Some(1),
                ttl: None,
            })
        })?;
        let cell = cell("admin", 1);

        keyspace.insert_version(&session, &cell, "deleted")?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.delete_version(&session, &cell)?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.inner.major_compact()?;

        assert_eq!(None, keyspace.get_version(&session, &cell)?);

        Ok(())
    }

    #[test]
    fn retention_compaction_is_independent_from_session_authorizations() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default().with_retention(RetentionPolicy {
                max_versions: Some(1),
                ttl: None,
            })
        })?;
        let old_hidden = cell("audit", 1).encode()?;
        let new_hidden = cell("audit", 2).encode()?;

        keyspace.inner.insert(old_hidden.clone(), "old-hidden")?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.inner.insert(new_hidden.clone(), "new-hidden")?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.inner.major_compact()?;

        assert_eq!(None, keyspace.inner.get(old_hidden)?);
        assert_eq!(
            Some(UserValue::from("new-hidden")),
            keyspace.inner.get(new_hidden)?,
        );

        Ok(())
    }

    #[test]
    fn audit_sink_records_allowed_and_denied_keyspace_operations() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let audit = RecordingAuditSink::default();
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(
                StaticPermissionHandler::new()
                    .with_keyspace_permission("events", KeyspacePermission::Read),
            )
            .authorizor(authorizor(&["admin"])?)
            .audit_sink(audit.clone(), AuditFailureMode::FailClosed)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", SecureKeyspaceOptions::default)?;

        assert_eq!(None, keyspace.get_version(&session, &cell("admin", 1))?);
        assert!(matches!(
            keyspace.insert_version(&session, &cell("admin", 1), "blocked"),
            Err(Error::PermissionDenied("keyspace:write")),
        ));

        let events = audit.events();
        assert!(events.contains(&"auth-succeeded".to_string()));
        assert!(events.contains(&"keyspace-access:events".to_string()));
        assert!(events.contains(&"authorization-denied:events".to_string()));

        Ok(())
    }

    #[test]
    fn audit_failure_mode_controls_operation_failure() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let fail_closed = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .audit_sink(RecordingAuditSink::failing(), AuditFailureMode::FailClosed)
            .open()?;

        assert!(matches!(
            fail_closed.authenticate(&Credentials::new("alice", "secret")),
            Err(Error::Audit("audit sink failed")),
        ));

        let folder = tempfile::tempdir()?;
        let best_effort = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .audit_sink(RecordingAuditSink::failing(), AuditFailureMode::BestEffort)
            .open()?;

        assert!(best_effort
            .authenticate(&Credentials::new("alice", "secret"))
            .is_ok());

        Ok(())
    }

    #[test]
    fn compaction_preserves_decryptability() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SecureDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(AllowAllPermissions::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let session = db.authenticate(&Credentials::new("alice", "secret"))?;
        let keyspace = db.secure_keyspace("events", || {
            SecureKeyspaceOptions::default()
                .with_encryption(encryption(0x5a))
                .with_retention(RetentionPolicy {
                    max_versions: Some(2),
                    ttl: None,
                })
        })?;
        let cell = cell("admin", 7);

        keyspace.insert_version(&session, &cell, "plaintext")?;
        keyspace.inner.rotate_memtable_and_wait()?;
        keyspace.inner.major_compact()?;

        assert_eq!(
            Some(UserValue::from("plaintext")),
            keyspace.get_version(&session, &cell)?,
        );

        Ok(())
    }
}
