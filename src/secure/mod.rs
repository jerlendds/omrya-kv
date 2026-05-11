// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Secure keyspace APIs.
//!
//! This module is the feature-gated landing zone for the Fjall secure storage
//! roadmap described in `work/rfcs/0000-fjall-secure-storage-roadmap.md`.
//! It is intentionally additive: enabling `secure-keyspaces` must not change
//! the behavior of raw [`crate::Database`], [`crate::Keyspace`],
//! [`crate::SingleWriterTxDatabase`], or [`crate::OptimisticTxDatabase`] APIs.

mod audit;
mod cell;
mod composite;
mod crypto;
mod keyspace;
mod policy;
mod providers;
mod tx;
mod visibility;

pub use audit::{AuditEvent, AuditFailureMode, AuditSink};
pub use cell::{
    Cell, VersionScan, VersionedCell, VersionedCellKeyspaceExt, VersionedCellReadExt,
    VersionedEntry,
};
pub use composite::{CompositeKey, CompositePrefix};
pub use crypto::{
    CryptoContext, CryptoProvider, EncryptionConfig, EncryptionScope, SecureKeyspaceOptions,
};
pub use keyspace::{SecureDatabase, SecureDatabaseBuilder, SecureKeyspace, Session};
pub use policy::{CompactionDeleteReason, RetentionPolicy};
pub use providers::{
    AllowAllPermissions, Authenticator, Authorizor, Credentials, KeyspacePermission,
    PermissionHandler, SecurityProviders, StaticAuthenticator, StaticAuthorizor,
    StaticPermissionHandler, SystemPermission,
};
pub use tx::{
    OptimisticSecureTxDatabase, OptimisticSecureTxDatabaseBuilder, OptimisticSecureTxKeyspace,
    OptimisticSecureWriteTransaction, SecureTxKeyspaceOptions, SingleWriterSecureTxDatabase,
    SingleWriterSecureTxDatabaseBuilder, SingleWriterSecureTxKeyspace,
    SingleWriterSecureWriteTransaction,
};
pub use visibility::{Authorizations, VisibilityExpr};

const RAW_KEYSPACE_PREFIX: &str = "$fjall.secure.";

pub(crate) fn is_reserved_raw_keyspace_name(name: &str) -> bool {
    name.starts_with(RAW_KEYSPACE_PREFIX)
}
