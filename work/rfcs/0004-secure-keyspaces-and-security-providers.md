# RFC 0004: Secure Keyspaces and Pluggable Security Providers

## Status

Draft

## Summary

Add secure keyspaces that enforce authenticated sessions, permissions, and visibility filtering through dedicated APIs. Add pluggable authenticator, permission handler, and authorizor traits.

## Motivation

Visibility expressions alone do not enforce security. Fjall needs API boundaries that require session context for secure reads and writes.

Because Fjall is embedded, this security model protects only operations performed through the secure API. It does not prevent arbitrary in-process code from bypassing the API unless raw access is blocked by design and sensitive data is encrypted with externally controlled keys.

## Proposed API Sketch

```rust
pub struct SecureDatabase<I> {
    inner: Database,
    security: Arc<SecurityProviders<I>>,
}

pub struct SecureKeyspace<I> {
    inner: Keyspace,
    security: Arc<SecurityProviders<I>>,
}

pub struct Session<I> {
    pub identity: I,
    pub auths: Authorizations,
}
```

```rust
let db = SecureDatabase::builder(path)
    .authenticator(authenticator)
    .permission_handler(permission_handler)
    .authorizor(authorizor)
    .open()?;

let session = db.authenticate(credentials)?;
let events = db.secure_keyspace("events", SecureKeyspaceOptions::default())?;
```

## Provider Traits

```rust
pub trait Authenticator {
    type Identity;

    fn authenticate(&self, credentials: Credentials) -> Result<Self::Identity>;
}

pub trait PermissionHandler<I> {
    fn has_system_permission(&self, identity: &I, permission: SystemPermission) -> bool;

    fn has_keyspace_permission(
        &self,
        identity: &I,
        keyspace: &str,
        permission: KeyspacePermission,
    ) -> bool;
}

pub trait Authorizor<I> {
    fn authorizations(&self, identity: &I) -> Result<Authorizations>;
}
```

The exact trait bounds for `Send`, `Sync`, `Clone`, `'static`, and error handling should follow Fjall's existing API style.

## Permissions

```rust
pub enum SystemPermission {
    CreateKeyspace,
    DropKeyspace,
    ManageUsers,
    ManagePolicies,
    Compact,
}

pub enum KeyspacePermission {
    Read,
    Write,
    Delete,
    Compact,
    Alter,
}
```

## Secure Writes

```rust
events.put(
    &session,
    CompositeKey {
        row,
        family,
        qualifier,
        visibility,
        timestamp,
    },
    value,
)?;
```

Writes must check:

1. the session has `Write` permission for the keyspace
2. the visibility expression is valid and canonical
3. the encoded composite key is valid

## Secure Reads

```rust
for item in events.scan(&session, scan_spec) {
    let (key, value) = item?;
}
```

Reads must check:

1. the session has `Read` permission for the keyspace
2. scan bounds are valid
3. returned records satisfy the session's authorizations

## Raw Access Boundary

Secure keyspace data must not be silently exposed through ordinary `Keyspace` handles. The implementation should choose one of:

- store secure keyspaces in reserved internal keyspaces inaccessible through public raw APIs
- mark secure keyspaces in metadata and refuse raw opening
- physically separate secure storage from raw keyspaces

This boundary is required for the secure API to be meaningful.

## Metadata Keyspaces

The security subsystem may reserve internal keyspaces:

| Keyspace | Purpose |
| --- | --- |
| `_users` | user identities |
| `_roles` | role mappings |
| `_permissions` | ACLs |
| `_auths` | authorization tokens |
| `_policies` | retention and security policies |

Names and layout should be considered internal until stabilized.

## Built-In Providers

Initial built-ins should be minimal:

- in-memory/static authenticator for tests
- password authenticator if password storage is in scope
- static permission handler
- static authorizor

JWT, mTLS, Kerberos, and LDAP should remain optional future provider crates unless a concrete embedding requires them.

## Validation

Tests should prove:

- missing providers fail closed
- unauthenticated access is rejected
- permission denial blocks reads and writes
- raw keyspace bypass is blocked for secure keyspaces
- unauthorized records are not exposed by scans

## Open Questions

- Should `Identity` be generic, a trait object, or a concrete string-like type?
- Should provider errors be distinguishable from denials?
- Should security metadata be stored in Fjall itself or supplied entirely by application providers?

