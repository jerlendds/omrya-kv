// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Security provider traits and minimal built-in providers.

use crate::{Error, Slice};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::Arc,
};

/// Authentication material passed to an [`Authenticator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    principal: String,
    secret: Slice,
}

impl Credentials {
    /// Creates credentials from a principal and secret bytes.
    #[must_use]
    pub fn new(principal: impl Into<String>, secret: impl Into<Slice>) -> Self {
        Self {
            principal: principal.into(),
            secret: secret.into(),
        }
    }

    /// Returns the principal name.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Returns the secret bytes.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Authenticates credentials into an application identity.
pub trait Authenticator: Send + Sync + 'static {
    /// Authenticated identity type.
    type Identity: Clone + Send + Sync + 'static;

    /// Authenticates credentials.
    ///
    /// Returning `Ok(None)` denies authentication without exposing whether the
    /// principal or secret was wrong.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot evaluate the credentials.
    fn authenticate(&self, credentials: &Credentials) -> crate::Result<Option<Self::Identity>>;
}

/// Checks system-level and keyspace-level permissions.
pub trait PermissionHandler<I>: Send + Sync + 'static
where
    I: Clone + Send + Sync + 'static,
{
    /// Returns `true` if `identity` has a system permission.
    fn has_system_permission(&self, identity: &I, permission: SystemPermission) -> bool;

    /// Returns `true` if `identity` has a permission on `keyspace`.
    fn has_keyspace_permission(
        &self,
        identity: &I,
        keyspace: &str,
        permission: KeyspacePermission,
    ) -> bool;
}

/// Resolves authorization labels for an authenticated identity.
pub trait Authorizor<I>: Send + Sync + 'static
where
    I: Clone + Send + Sync + 'static,
{
    /// Returns the authorization label set for `identity`.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot resolve the identity's
    /// authorizations.
    fn authorizations(&self, identity: &I) -> crate::Result<super::Authorizations>;
}

/// System-level permissions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SystemPermission {
    /// Create a secure keyspace.
    CreateKeyspace,

    /// Drop a secure keyspace.
    DropKeyspace,

    /// Manage identities or users.
    ManageUsers,

    /// Manage security policies.
    ManagePolicies,

    /// Compact keyspaces.
    Compact,
}

/// Keyspace-level permissions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KeyspacePermission {
    /// Read records.
    Read,

    /// Write records.
    Write,

    /// Delete records.
    Delete,

    /// Compact the keyspace.
    Compact,

    /// Alter keyspace configuration.
    Alter,
}

impl KeyspacePermission {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "keyspace:read",
            Self::Write => "keyspace:write",
            Self::Delete => "keyspace:delete",
            Self::Compact => "keyspace:compact",
            Self::Alter => "keyspace:alter",
        }
    }
}

/// Configured provider set for secure keyspace APIs.
pub struct SecurityProviders<I>
where
    I: Clone + Send + Sync + 'static,
{
    pub(crate) authenticator: Arc<dyn Authenticator<Identity = I>>,
    pub(crate) permission_handler: Arc<dyn PermissionHandler<I>>,
    pub(crate) authorizor: Arc<dyn Authorizor<I>>,
    pub(super) audit: Option<super::audit::AuditConfig<I>>,
}

impl<I> SecurityProviders<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates a provider set from concrete providers.
    #[must_use]
    pub fn new<A, P, Z>(authenticator: A, permission_handler: P, authorizor: Z) -> Self
    where
        A: Authenticator<Identity = I>,
        P: PermissionHandler<I>,
        Z: Authorizor<I>,
    {
        Self {
            authenticator: Arc::new(authenticator),
            permission_handler: Arc::new(permission_handler),
            authorizor: Arc::new(authorizor),
            audit: None,
        }
    }

    /// Installs an audit sink.
    #[must_use]
    pub fn with_audit_sink(
        mut self,
        sink: impl super::AuditSink<I>,
        failure_mode: super::AuditFailureMode,
    ) -> Self {
        self.audit = Some(super::audit::AuditConfig::new(sink, failure_mode));
        self
    }

    pub(crate) fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> crate::Result<super::Session<I>> {
        let Some(identity) = self.authenticator.authenticate(credentials)? else {
            self.record_audit(super::AuditEvent::AuthenticationFailed)?;
            return Err(Error::AuthenticationDenied);
        };

        let auths = self.authorizor.authorizations(&identity)?;
        self.record_audit(super::AuditEvent::AuthenticationSucceeded {
            identity: &identity,
        })?;

        Ok(super::Session { identity, auths })
    }

    pub(crate) fn check_keyspace_permission(
        &self,
        identity: &I,
        keyspace: &str,
        permission: KeyspacePermission,
    ) -> crate::Result<()> {
        if self
            .permission_handler
            .has_keyspace_permission(identity, keyspace, permission)
        {
            self.record_audit(super::AuditEvent::KeyspaceAccess { identity, keyspace })?;
            Ok(())
        } else {
            self.record_audit(super::AuditEvent::AuthorizationDenied { identity, keyspace })?;
            Err(Error::PermissionDenied(permission.as_str()))
        }
    }

    pub(super) fn audit_config(&self) -> Option<super::audit::AuditConfig<I>> {
        self.audit.clone()
    }

    fn record_audit(&self, event: super::AuditEvent<'_, I>) -> crate::Result<()> {
        if let Some(audit) = &self.audit {
            audit.record(event)?;
        }

        Ok(())
    }
}

/// In-memory authenticator keyed by principal.
pub struct StaticAuthenticator<I>
where
    I: Clone + Send + Sync + 'static,
{
    identities: BTreeMap<String, (Slice, I)>,
}

impl<I> StaticAuthenticator<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates an empty static authenticator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            identities: BTreeMap::new(),
        }
    }

    /// Adds one principal, secret, and identity mapping.
    #[must_use]
    pub fn with_principal(
        mut self,
        principal: impl Into<String>,
        secret: impl Into<Slice>,
        identity: I,
    ) -> Self {
        self.identities
            .insert(principal.into(), (secret.into(), identity));
        self
    }
}

impl<I> Default for StaticAuthenticator<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<I> Authenticator for StaticAuthenticator<I>
where
    I: Clone + Send + Sync + 'static,
{
    type Identity = I;

    fn authenticate(&self, credentials: &Credentials) -> crate::Result<Option<Self::Identity>> {
        Ok(self
            .identities
            .get(credentials.principal())
            .and_then(|(secret, identity)| {
                (secret.as_ref() == credentials.secret()).then(|| identity.clone())
            }))
    }
}

/// Permission handler that grants every permission.
pub struct AllowAllPermissions<I>
where
    I: Clone + Send + Sync + 'static,
{
    _identity: PhantomData<I>,
}

impl<I> AllowAllPermissions<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates an allow-all permission handler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _identity: PhantomData,
        }
    }
}

impl<I> Default for AllowAllPermissions<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<I> PermissionHandler<I> for AllowAllPermissions<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn has_system_permission(&self, _identity: &I, _permission: SystemPermission) -> bool {
        true
    }

    fn has_keyspace_permission(
        &self,
        _identity: &I,
        _keyspace: &str,
        _permission: KeyspacePermission,
    ) -> bool {
        true
    }
}

/// Static permission handler that grants the same permissions to every identity.
pub struct StaticPermissionHandler<I>
where
    I: Clone + Send + Sync + 'static,
{
    system_permissions: BTreeSet<SystemPermission>,
    keyspace_permissions: BTreeMap<String, BTreeSet<KeyspacePermission>>,
    _identity: PhantomData<I>,
}

impl<I> StaticPermissionHandler<I>
where
    I: Clone + Send + Sync + 'static,
{
    /// Creates a static permission handler with no permissions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            system_permissions: BTreeSet::new(),
            keyspace_permissions: BTreeMap::new(),
            _identity: PhantomData,
        }
    }

    /// Grants a system permission.
    #[must_use]
    pub fn with_system_permission(mut self, permission: SystemPermission) -> Self {
        self.system_permissions.insert(permission);
        self
    }

    /// Grants a keyspace permission.
    #[must_use]
    pub fn with_keyspace_permission(
        mut self,
        keyspace: impl Into<String>,
        permission: KeyspacePermission,
    ) -> Self {
        self.keyspace_permissions
            .entry(keyspace.into())
            .or_default()
            .insert(permission);
        self
    }
}

impl<I> Default for StaticPermissionHandler<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<I> PermissionHandler<I> for StaticPermissionHandler<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn has_system_permission(&self, _identity: &I, permission: SystemPermission) -> bool {
        self.system_permissions.contains(&permission)
    }

    fn has_keyspace_permission(
        &self,
        _identity: &I,
        keyspace: &str,
        permission: KeyspacePermission,
    ) -> bool {
        self.keyspace_permissions
            .get(keyspace)
            .is_some_and(|permissions| permissions.contains(&permission))
    }
}

/// Authorizor that returns the same authorization labels for every identity.
#[derive(Clone, Debug)]
pub struct StaticAuthorizor {
    auths: super::Authorizations,
}

impl StaticAuthorizor {
    /// Creates a static authorizor.
    #[must_use]
    pub fn new(auths: super::Authorizations) -> Self {
        Self { auths }
    }
}

impl<I> Authorizor<I> for StaticAuthorizor
where
    I: Clone + Send + Sync + 'static,
{
    fn authorizations(&self, _identity: &I) -> crate::Result<super::Authorizations> {
        Ok(self.auths.clone())
    }
}
