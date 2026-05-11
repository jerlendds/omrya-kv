// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Session-aware secure transaction wrappers.

use crate::{
    Conflict, DatabaseBuilder, Error, OptimisticTxDatabase, OptimisticTxKeyspace,
    OptimisticWriteTx, SingleWriterTxDatabase, SingleWriterTxKeyspace, SingleWriterWriteTx,
    UserValue,
};
use std::{path::Path, sync::Arc};

use super::{
    crypto::{maybe_decrypt_entry, maybe_encrypt_value, SecureKeyspaceOptions, ValueEncryption},
    keyspace::{canonicalize_cell, install_retention_policy, is_visible, physical_keyspace_name},
    Authorizations, CompositeKey, CompositePrefix, KeyspacePermission, SecurityProviders, Session,
    VersionScan, VersionedCell, VersionedEntry,
};

/// Create options for secure transactional keyspaces.
pub type SecureTxKeyspaceOptions = SecureKeyspaceOptions;

/// Secure wrapper around [`SingleWriterTxDatabase`].
#[derive(Clone)]
pub struct SingleWriterSecureTxDatabase<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: SingleWriterTxDatabase,
    security: Arc<SecurityProviders<I>>,
}

impl<I> SingleWriterSecureTxDatabase<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates a builder for a secure single-writer transactional database.
    pub fn builder(path: impl AsRef<Path>) -> SingleWriterSecureTxDatabaseBuilder<I> {
        SingleWriterSecureTxDatabaseBuilder::new(path.as_ref())
    }

    /// Returns the wrapped transactional database.
    #[must_use]
    pub fn inner(&self) -> &SingleWriterTxDatabase {
        &self.inner
    }

    /// Starts a session-aware secure transaction.
    #[must_use]
    pub fn begin_secure_tx(
        &self,
        session: &Session<I>,
    ) -> SingleWriterSecureWriteTransaction<'_, I> {
        SingleWriterSecureWriteTransaction {
            inner: self.inner.write_tx(),
            session: session.clone(),
            security: self.security.clone(),
        }
    }

    /// Creates or opens a secure transactional keyspace.
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
        create_options: impl FnOnce() -> SecureTxKeyspaceOptions,
    ) -> crate::Result<SingleWriterSecureTxKeyspace<I>> {
        let SecureTxKeyspaceOptions {
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
        let raw = self
            .inner
            .inner()
            .raw_keyspace(&physical_keyspace_name(name), || create_options)?;

        Ok(SingleWriterSecureTxKeyspace {
            inner: SingleWriterTxKeyspace {
                inner: raw,
                db: self.inner.clone(),
            },
            name: name.to_owned(),
            encryption,
            _identity: std::marker::PhantomData,
        })
    }
}

/// Builder for [`SingleWriterSecureTxDatabase`].
pub struct SingleWriterSecureTxDatabaseBuilder<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: DatabaseBuilder<SingleWriterTxDatabase>,
    authenticator: Option<Arc<dyn super::Authenticator<Identity = I>>>,
    permission_handler: Option<Arc<dyn super::PermissionHandler<I>>>,
    authorizor: Option<Arc<dyn super::Authorizor<I>>>,
    audit: Option<super::audit::AuditConfig<I>>,
}

impl<I> SingleWriterSecureTxDatabaseBuilder<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn new(path: &Path) -> Self {
        Self {
            inner: SingleWriterTxDatabase::builder(path),
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

    /// Opens the secure transactional database.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider is missing or the raw database cannot
    /// be opened.
    pub fn open(self) -> crate::Result<SingleWriterSecureTxDatabase<I>> {
        let security = providers_from_parts(
            self.authenticator,
            self.permission_handler,
            self.authorizor,
            self.audit,
        )?;

        Ok(SingleWriterSecureTxDatabase {
            inner: self.inner.open()?,
            security: Arc::new(security),
        })
    }
}

/// Secure keyspace handle for single-writer transactions.
#[derive(Clone)]
pub struct SingleWriterSecureTxKeyspace<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: SingleWriterTxKeyspace,
    name: String,
    encryption: Option<ValueEncryption>,
    _identity: std::marker::PhantomData<I>,
}

impl<I> SingleWriterSecureTxKeyspace<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Returns the secure logical keyspace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Session-aware single-writer secure transaction.
pub struct SingleWriterSecureWriteTransaction<'tx, I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: SingleWriterWriteTx<'tx>,
    session: Session<I>,
    security: Arc<SecurityProviders<I>>,
}

impl<I> SingleWriterSecureWriteTransaction<'_, I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Inserts or replaces one versioned cell after checking captured permissions.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied or key validation fails.
    pub fn insert_version<V>(
        &mut self,
        keyspace: &SingleWriterSecureTxKeyspace<I>,
        cell: &VersionedCell,
        value: V,
    ) -> crate::Result<()>
    where
        V: Into<UserValue>,
    {
        check_keyspace_permission(
            &self.security,
            &self.session.identity,
            keyspace.name(),
            KeyspacePermission::Write,
        )?;
        let cell = canonicalize_cell(cell)?;
        let encoded_key = cell.encode()?;
        let stored_value = maybe_encrypt_value(keyspace.encryption.as_ref(), &encoded_key, value)?;

        self.inner
            .insert(&keyspace.inner, encoded_key, stored_value);
        Ok(())
    }

    /// Retrieves one exact version if visible to the captured session.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, key encoding fails, or the
    /// stored visibility expression is invalid.
    pub fn get_version(
        &self,
        keyspace: &SingleWriterSecureTxKeyspace<I>,
        cell: &VersionedCell,
    ) -> crate::Result<Option<UserValue>> {
        secure_get_version(
            &self.inner,
            &self.security,
            &self.session.identity,
            &self.session.auths,
            keyspace.name(),
            &keyspace.inner.inner,
            keyspace.encryption.as_ref(),
            cell,
        )
    }

    /// Scans versioned cells matching a prefix and captured authorizations.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, prefix encoding fails,
    /// storage rejects the scan, or a stored visibility expression is invalid.
    pub fn scan_versioned_prefix(
        &self,
        keyspace: &SingleWriterSecureTxKeyspace<I>,
        prefix: &CompositePrefix,
        scan: &VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>> {
        secure_scan_versioned_prefix(
            &self.inner,
            &self.security,
            &self.session.identity,
            &self.session.auths,
            keyspace.name(),
            &keyspace.inner.inner,
            keyspace.encryption.as_ref(),
            prefix,
            scan,
        )
    }

    /// Deletes one exact version after checking captured delete permission.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied or key validation fails.
    pub fn delete_version(
        &mut self,
        keyspace: &SingleWriterSecureTxKeyspace<I>,
        cell: &VersionedCell,
    ) -> crate::Result<()> {
        check_keyspace_permission(
            &self.security,
            &self.session.identity,
            keyspace.name(),
            KeyspacePermission::Delete,
        )?;
        let cell = canonicalize_cell(cell)?;

        self.inner.remove(&keyspace.inner, cell.encode()?);
        Ok(())
    }

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying transaction commit fails.
    pub fn commit(self) -> crate::Result<()> {
        self.inner.commit()
    }

    /// Rolls the transaction back.
    pub fn rollback(self) {
        self.inner.rollback();
    }
}

/// Secure wrapper around [`OptimisticTxDatabase`].
#[derive(Clone)]
pub struct OptimisticSecureTxDatabase<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: OptimisticTxDatabase,
    security: Arc<SecurityProviders<I>>,
}

impl<I> OptimisticSecureTxDatabase<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates a builder for a secure optimistic transactional database.
    pub fn builder(path: impl AsRef<Path>) -> OptimisticSecureTxDatabaseBuilder<I> {
        OptimisticSecureTxDatabaseBuilder::new(path.as_ref())
    }

    /// Returns the wrapped transactional database.
    #[must_use]
    pub fn inner(&self) -> &OptimisticTxDatabase {
        &self.inner
    }

    /// Starts a session-aware secure transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying optimistic transaction cannot begin.
    pub fn begin_secure_tx(
        &self,
        session: &Session<I>,
    ) -> crate::Result<OptimisticSecureWriteTransaction<I>> {
        Ok(OptimisticSecureWriteTransaction {
            inner: self.inner.write_tx()?,
            session: session.clone(),
            security: self.security.clone(),
        })
    }

    /// Creates or opens a secure transactional keyspace.
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
        create_options: impl FnOnce() -> SecureTxKeyspaceOptions,
    ) -> crate::Result<OptimisticSecureTxKeyspace<I>> {
        let SecureTxKeyspaceOptions {
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
        let raw = self
            .inner
            .inner()
            .raw_keyspace(&physical_keyspace_name(name), || create_options)?;

        Ok(OptimisticSecureTxKeyspace {
            inner: OptimisticTxKeyspace {
                inner: raw,
                db: self.inner.clone(),
            },
            name: name.to_owned(),
            encryption,
            _identity: std::marker::PhantomData,
        })
    }
}

/// Builder for [`OptimisticSecureTxDatabase`].
pub struct OptimisticSecureTxDatabaseBuilder<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: DatabaseBuilder<OptimisticTxDatabase>,
    authenticator: Option<Arc<dyn super::Authenticator<Identity = I>>>,
    permission_handler: Option<Arc<dyn super::PermissionHandler<I>>>,
    authorizor: Option<Arc<dyn super::Authorizor<I>>>,
    audit: Option<super::audit::AuditConfig<I>>,
}

impl<I> OptimisticSecureTxDatabaseBuilder<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn new(path: &Path) -> Self {
        Self {
            inner: OptimisticTxDatabase::builder(path),
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

    /// Opens the secure transactional database.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider is missing or the raw database cannot
    /// be opened.
    pub fn open(self) -> crate::Result<OptimisticSecureTxDatabase<I>> {
        let security = providers_from_parts(
            self.authenticator,
            self.permission_handler,
            self.authorizor,
            self.audit,
        )?;

        Ok(OptimisticSecureTxDatabase {
            inner: self.inner.open()?,
            security: Arc::new(security),
        })
    }
}

/// Secure keyspace handle for optimistic transactions.
#[derive(Clone)]
pub struct OptimisticSecureTxKeyspace<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: OptimisticTxKeyspace,
    name: String,
    encryption: Option<ValueEncryption>,
    _identity: std::marker::PhantomData<I>,
}

impl<I> OptimisticSecureTxKeyspace<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Returns the secure logical keyspace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Session-aware optimistic secure transaction.
pub struct OptimisticSecureWriteTransaction<I>
where
    I: Clone + Send + Sync + 'static,
{
    inner: OptimisticWriteTx,
    session: Session<I>,
    security: Arc<SecurityProviders<I>>,
}

impl<I> OptimisticSecureWriteTransaction<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Inserts or replaces one versioned cell after checking captured permissions.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied or key validation fails.
    pub fn insert_version<V>(
        &mut self,
        keyspace: &OptimisticSecureTxKeyspace<I>,
        cell: &VersionedCell,
        value: V,
    ) -> crate::Result<()>
    where
        V: Into<UserValue>,
    {
        check_keyspace_permission(
            &self.security,
            &self.session.identity,
            keyspace.name(),
            KeyspacePermission::Write,
        )?;
        let cell = canonicalize_cell(cell)?;
        let encoded_key = cell.encode()?;
        let stored_value = maybe_encrypt_value(keyspace.encryption.as_ref(), &encoded_key, value)?;

        self.inner
            .insert(&keyspace.inner, encoded_key, stored_value);
        Ok(())
    }

    /// Retrieves one exact version if visible to the captured session.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, key encoding fails, or the
    /// stored visibility expression is invalid.
    pub fn get_version(
        &self,
        keyspace: &OptimisticSecureTxKeyspace<I>,
        cell: &VersionedCell,
    ) -> crate::Result<Option<UserValue>> {
        secure_get_version(
            &self.inner,
            &self.security,
            &self.session.identity,
            &self.session.auths,
            keyspace.name(),
            &keyspace.inner.inner,
            keyspace.encryption.as_ref(),
            cell,
        )
    }

    /// Scans versioned cells matching a prefix and captured authorizations.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied, prefix encoding fails,
    /// storage rejects the scan, or a stored visibility expression is invalid.
    pub fn scan_versioned_prefix(
        &self,
        keyspace: &OptimisticSecureTxKeyspace<I>,
        prefix: &CompositePrefix,
        scan: &VersionScan,
    ) -> crate::Result<Vec<VersionedEntry>> {
        secure_scan_versioned_prefix(
            &self.inner,
            &self.security,
            &self.session.identity,
            &self.session.auths,
            keyspace.name(),
            &keyspace.inner.inner,
            keyspace.encryption.as_ref(),
            prefix,
            scan,
        )
    }

    /// Deletes one exact version after checking captured delete permission.
    ///
    /// # Errors
    ///
    /// Returns an error when permission is denied or key validation fails.
    pub fn delete_version(
        &mut self,
        keyspace: &OptimisticSecureTxKeyspace<I>,
        cell: &VersionedCell,
    ) -> crate::Result<()> {
        check_keyspace_permission(
            &self.security,
            &self.session.identity,
            keyspace.name(),
            KeyspacePermission::Delete,
        )?;
        let cell = canonicalize_cell(cell)?;

        self.inner.remove(&keyspace.inner, cell.encode()?);
        Ok(())
    }

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying transaction commit fails.
    pub fn commit(self) -> crate::Result<Result<(), Conflict>> {
        self.inner.commit()
    }

    /// Rolls the transaction back.
    pub fn rollback(self) {
        self.inner.rollback();
    }
}

fn providers_from_parts<I>(
    authenticator: Option<Arc<dyn super::Authenticator<Identity = I>>>,
    permission_handler: Option<Arc<dyn super::PermissionHandler<I>>>,
    authorizor: Option<Arc<dyn super::Authorizor<I>>>,
    audit: Option<super::audit::AuditConfig<I>>,
) -> crate::Result<SecurityProviders<I>>
where
    I: Clone + Send + Sync + 'static,
{
    Ok(SecurityProviders {
        authenticator: authenticator.ok_or(Error::MissingSecurityProvider("authenticator"))?,
        permission_handler: permission_handler
            .ok_or(Error::MissingSecurityProvider("permission_handler"))?,
        authorizor: authorizor.ok_or(Error::MissingSecurityProvider("authorizor"))?,
        audit,
    })
}

fn check_keyspace_permission<I>(
    security: &SecurityProviders<I>,
    identity: &I,
    keyspace: &str,
    permission: KeyspacePermission,
) -> crate::Result<()>
where
    I: Clone + Send + Sync + 'static,
{
    security.check_keyspace_permission(identity, keyspace, permission)
}

#[expect(clippy::too_many_arguments)]
fn secure_get_version<I, R>(
    reader: &R,
    security: &SecurityProviders<I>,
    identity: &I,
    auths: &Authorizations,
    keyspace_name: &str,
    keyspace: &crate::Keyspace,
    encryption: Option<&ValueEncryption>,
    cell: &VersionedCell,
) -> crate::Result<Option<UserValue>>
where
    I: Clone + Send + Sync + 'static,
    R: crate::Readable,
{
    check_keyspace_permission(security, identity, keyspace_name, KeyspacePermission::Read)?;

    let encoded_key = cell.encode()?;
    let value = reader.get(keyspace, &encoded_key)?;

    if !is_visible(cell.cell.visibility.as_ref(), auths)? {
        return Ok(None);
    }

    value
        .map(|stored| maybe_decrypt_entry(encryption, &encoded_key, stored))
        .transpose()
}

#[expect(clippy::too_many_arguments)]
fn secure_scan_versioned_prefix<I, R>(
    reader: &R,
    security: &SecurityProviders<I>,
    identity: &I,
    auths: &Authorizations,
    keyspace_name: &str,
    keyspace: &crate::Keyspace,
    encryption: Option<&ValueEncryption>,
    prefix: &CompositePrefix,
    scan: &VersionScan,
) -> crate::Result<Vec<VersionedEntry>>
where
    I: Clone + Send + Sync + 'static,
    R: crate::Readable,
{
    check_keyspace_permission(security, identity, keyspace_name, KeyspacePermission::Read)?;

    let range = prefix.range()?;
    let mut entries = Vec::new();

    for guard in reader.range(keyspace, range) {
        let (key, stored_value) = guard.into_inner()?;
        let cell = VersionedCell::from(CompositeKey::decode(&key)?);

        if scan.includes(cell.timestamp) && is_visible(cell.cell.visibility.as_ref(), auths)? {
            let value = maybe_decrypt_entry(encryption, &key, stored_value)?;
            entries.push(VersionedEntry { cell, value });
        }

        if scan.is_satisfied_by(entries.len()) {
            break;
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure::{
            Cell, CryptoContext, CryptoProvider, EncryptionConfig, EncryptionScope,
            StaticAuthenticator, StaticAuthorizor, StaticPermissionHandler,
        },
        Slice,
    };
    use test_log::test;

    fn authenticator() -> StaticAuthenticator<String> {
        StaticAuthenticator::new().with_principal("alice", "secret", "alice".to_string())
    }

    fn session(auths: &[&str]) -> crate::Result<Session<String>> {
        Ok(Session {
            identity: "alice".to_string(),
            auths: super::super::Authorizations::from_labels(auths.iter().copied())?,
        })
    }

    fn authorizor(auths: &[&str]) -> crate::Result<StaticAuthorizor> {
        Ok(StaticAuthorizor::new(
            super::super::Authorizations::from_labels(auths.iter().copied())?,
        ))
    }

    fn permissions() -> StaticPermissionHandler<String> {
        StaticPermissionHandler::new()
            .with_keyspace_permission("events", KeyspacePermission::Read)
            .with_keyspace_permission("events", KeyspacePermission::Write)
            .with_keyspace_permission("events", KeyspacePermission::Delete)
    }

    fn cell(visibility: &str, timestamp: i64) -> VersionedCell {
        Cell {
            row: "row".into(),
            family: "family".into(),
            qualifier: "qualifier".into(),
            visibility: visibility.into(),
        }
        .version(timestamp)
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

    #[test]
    fn single_writer_secure_tx_reads_own_visible_writes() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SingleWriterSecureTxDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(permissions())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", SecureTxKeyspaceOptions::default)?;
        let session = session(&["admin"])?;

        let mut tx = db.begin_secure_tx(&session);
        tx.insert_version(&keyspace, &cell("admin", 1), "visible")?;
        tx.insert_version(&keyspace, &cell("audit", 1), "hidden")?;

        assert_eq!(
            Some(UserValue::from("visible")),
            tx.get_version(&keyspace, &cell("admin", 1))?,
        );
        assert_eq!(None, tx.get_version(&keyspace, &cell("audit", 1))?);

        let entries = tx.scan_versioned_prefix(
            &keyspace,
            &CompositePrefix {
                row: Some(Slice::from("row")),
                family: None,
                qualifier: None,
                visibility: None,
            },
            &VersionScan::default(),
        )?;
        assert_eq!(1, entries.len());

        tx.commit()?;

        Ok(())
    }

    #[test]
    fn single_writer_secure_tx_encrypts_and_decrypts_values() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SingleWriterSecureTxDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(permissions())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", || {
            SecureTxKeyspaceOptions::default().with_encryption(encryption(0x5a))
        })?;
        let session = session(&["admin"])?;
        let cell = cell("admin", 1);

        let mut tx = db.begin_secure_tx(&session);
        tx.insert_version(&keyspace, &cell, "plaintext")?;
        assert_eq!(
            Some(UserValue::from("plaintext")),
            tx.get_version(&keyspace, &cell)?,
        );
        tx.commit()?;

        let encoded_key = cell.encode()?;
        let stored = keyspace
            .inner
            .inner
            .get(&encoded_key)?
            .expect("value should exist");
        assert_ne!(stored.as_ref(), b"plaintext");

        let tx = db.begin_secure_tx(&session);
        assert_eq!(
            Some(UserValue::from("plaintext")),
            tx.get_version(&keyspace, &cell)?,
        );

        Ok(())
    }

    #[test]
    fn single_writer_permission_denial_happens_before_staging() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = SingleWriterSecureTxDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(StaticPermissionHandler::new())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", SecureTxKeyspaceOptions::default)?;
        let session = session(&["admin"])?;

        let mut tx = db.begin_secure_tx(&session);
        assert!(matches!(
            tx.insert_version(&keyspace, &cell("admin", 1), "blocked"),
            Err(Error::PermissionDenied("keyspace:write")),
        ));
        tx.commit()?;

        assert!(keyspace.inner.inner.is_empty()?);

        Ok(())
    }

    #[test]
    fn optimistic_secure_tx_reads_and_commits_visible_writes() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = OptimisticSecureTxDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(permissions())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", SecureTxKeyspaceOptions::default)?;
        let session = session(&["admin"])?;

        let mut tx = db.begin_secure_tx(&session)?;
        tx.insert_version(&keyspace, &cell("admin", 1), "visible")?;
        assert_eq!(
            Some(UserValue::from("visible")),
            tx.get_version(&keyspace, &cell("admin", 1))?,
        );
        assert!(tx.commit()?.is_ok());

        Ok(())
    }

    #[test]
    fn optimistic_secure_tx_conflicts_on_unauthorized_physical_key() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = OptimisticSecureTxDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(permissions())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", SecureTxKeyspaceOptions::default)?;
        let admin_session = session(&["admin"])?;
        let hidden_session = session(&[])?;

        let mut tx1 = db.begin_secure_tx(&admin_session)?;
        let mut tx2 = db.begin_secure_tx(&hidden_session)?;

        assert_eq!(None, tx2.get_version(&keyspace, &cell("admin", 1))?);

        tx1.insert_version(&keyspace, &cell("admin", 1), "tx1")?;
        assert!(tx1.commit()?.is_ok());

        tx2.insert_version(&keyspace, &cell("admin", 1), "tx2")?;
        assert!(matches!(tx2.commit()?, Err(Conflict)));

        Ok(())
    }

    #[test]
    fn optimistic_begin_captures_authorizations() -> crate::Result<()> {
        let folder = tempfile::tempdir()?;
        let db = OptimisticSecureTxDatabase::<String>::builder(&folder)
            .authenticator(authenticator())
            .permission_handler(permissions())
            .authorizor(authorizor(&["admin"])?)
            .open()?;
        let keyspace = db.secure_keyspace("events", SecureTxKeyspaceOptions::default)?;
        let mut session = session(&["admin"])?;

        let mut tx = db.begin_secure_tx(&session)?;
        session.auths = super::super::Authorizations::empty();

        tx.insert_version(&keyspace, &cell("admin", 1), "visible")?;
        assert_eq!(
            Some(UserValue::from("visible")),
            tx.get_version(&keyspace, &cell("admin", 1))?,
        );

        Ok(())
    }
}
