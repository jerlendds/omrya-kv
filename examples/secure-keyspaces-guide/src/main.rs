use fjall::secure::{
    AuditEvent, AuditFailureMode, AuditSink, Authorizations, Cell, Credentials, CryptoContext,
    CryptoProvider, EncryptionConfig, EncryptionScope, KeyspacePermission, RetentionPolicy,
    SecureDatabase, SecureKeyspaceOptions, StaticAuthenticator, StaticAuthorizor,
    StaticPermissionHandler, VersionScan,
};
use std::{
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct User {
    name: String,
}

#[derive(Clone, Default)]
struct RecordingAuditSink {
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingAuditSink {
    fn events(&self) -> Vec<String> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(err) => panic!("audit events lock: {err}"),
        }
    }
}

impl AuditSink<User> for RecordingAuditSink {
    fn record(&self, event: AuditEvent<'_, User>) -> fjall::Result<()> {
        let label = match event {
            AuditEvent::AuthenticationSucceeded { identity } => {
                format!("auth:succeeded:{}", identity.name)
            }
            AuditEvent::AuthenticationFailed => "auth:failed".to_string(),
            AuditEvent::AuthorizationDenied { identity, keyspace } => {
                format!("authorization:denied:{}:{keyspace}", identity.name)
            }
            AuditEvent::PolicyViolation { keyspace } => {
                format!("policy:violation:{keyspace}")
            }
            AuditEvent::CompactionDeleted { keyspace, reason } => {
                format!("compaction:deleted:{keyspace}:{reason:?}")
            }
            AuditEvent::KeyspaceAccess { identity, keyspace } => {
                format!("keyspace:access:{}:{keyspace}", identity.name)
            }
        };

        match self.events.lock() {
            Ok(mut events) => events.push(label),
            Err(err) => panic!("audit events lock: {err}"),
        }

        Ok(())
    }
}

#[derive(Clone)]
struct XorCryptoProvider {
    key: u8,
}

impl CryptoProvider for XorCryptoProvider {
    fn encrypt(&self, _context: CryptoContext<'_>, plaintext: &[u8]) -> fjall::Result<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ self.key).collect())
    }

    fn decrypt(&self, _context: CryptoContext<'_>, ciphertext: &[u8]) -> fjall::Result<Vec<u8>> {
        Ok(ciphertext.iter().map(|byte| byte ^ self.key).collect())
    }
}

fn main() -> fjall::Result<()> {
    let folder = example_folder();
    let audit = RecordingAuditSink::default();

    let authenticator = StaticAuthenticator::new().with_principal(
        "alice",
        "correct-horse-battery-staple",
        User {
            name: "alice".to_string(),
        },
    );
    let authorizor = StaticAuthorizor::new(Authorizations::from_labels(["admin"])?);
    let permissions = StaticPermissionHandler::new()
        .with_keyspace_permission("events", KeyspacePermission::Read)
        .with_keyspace_permission("events", KeyspacePermission::Write)
        .with_keyspace_permission("events", KeyspacePermission::Delete);

    let db = SecureDatabase::builder(&folder)
        .authenticator(authenticator)
        .authorizor(authorizor)
        .permission_handler(permissions)
        .audit_sink(audit.clone(), AuditFailureMode::FailClosed)
        .open()?;

    assert!(db
        .authenticate(&Credentials::new("alice", "wrong-password"))
        .is_err());

    let session = db.authenticate(&Credentials::new(
        "alice",
        "correct-horse-battery-staple",
    ))?;

    let keyspace = db.secure_keyspace("events", || {
        SecureKeyspaceOptions::default()
            .with_encryption(EncryptionConfig::new(
                XorCryptoProvider { key: 0x5a },
                EncryptionScope::Value,
            ))
            .with_retention(RetentionPolicy {
                max_versions: Some(2),
                ttl: Some(Duration::from_secs(60 * 60 * 24)),
            })
    })?;

    let admin_cell = Cell {
        row: "account:123".into(),
        family: "profile".into(),
        qualifier: "email".into(),
        visibility: "admin".into(),
    };
    let audit_cell = Cell {
        visibility: "audit".into(),
        ..admin_cell.clone()
    };
    let base_timestamp = unix_seconds_now();

    keyspace.insert_version(&session, &admin_cell.version(base_timestamp), "old@example.com")?;
    keyspace.inner().rotate_memtable_and_wait()?;
    keyspace.insert_version(
        &session,
        &admin_cell.version(base_timestamp + 1),
        "new@example.com",
    )?;
    keyspace.inner().rotate_memtable_and_wait()?;
    keyspace.insert_version(
        &session,
        &admin_cell.version(base_timestamp + 2),
        "newest@example.com",
    )?;
    keyspace.inner().rotate_memtable_and_wait()?;

    keyspace.insert_version(&session, &audit_cell.version(base_timestamp), "hidden@example.com")?;

    let stored = keyspace
        .inner()
        .get(&admin_cell.version(base_timestamp + 2).encode()?)?
        .expect("stored encrypted value");
    assert_ne!(stored.as_ref(), b"newest@example.com");

    assert_eq!(
        Some("newest@example.com".into()),
        keyspace.get_version(&session, &admin_cell.version(base_timestamp + 2))?,
    );
    assert_eq!(
        None,
        keyspace.get_version(&session, &audit_cell.version(base_timestamp))?
    );

    keyspace.inner().major_compact()?;

    let versions = keyspace.scan_versioned_prefix(
        &session,
        &fjall::secure::CompositePrefix {
            row: Some("account:123".into()),
            family: Some("profile".into()),
            qualifier: Some("email".into()),
            visibility: Some("admin".into()),
        },
        &VersionScan::default(),
    )?;
    let timestamps = versions
        .iter()
        .map(|entry| entry.cell.timestamp)
        .collect::<Vec<_>>();

    assert_eq!(vec![base_timestamp + 2, base_timestamp + 1], timestamps);
    assert_eq!(
        None,
        keyspace.get_version(&session, &admin_cell.version(base_timestamp))?
    );

    assert!(audit
        .events()
        .iter()
        .any(|event| event == "compaction:deleted:events:MaxVersions"));

    println!("secure keyspaces guide OK");

    Ok(())
}

fn example_folder() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());

    std::env::temp_dir().join(format!(
        "fjall-secure-keyspaces-guide-{}-{nanos}",
        process::id()
    ))
}

fn unix_seconds_now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    i64::try_from(seconds).unwrap_or(i64::MAX)
}
