// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Secure retention policies and policy-aware compaction filters.

use crate::{Error, UserValue};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::CompositeKey;

/// Keyspace-scope retention policy for secure versioned cells.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RetentionPolicy {
    /// Maximum versions to retain per physical `(row, family, qualifier, visibility)` group.
    pub max_versions: Option<usize>,

    /// Maximum age to retain, comparing cell timestamps as Unix seconds.
    pub ttl: Option<Duration>,
}

impl RetentionPolicy {
    /// Validates this retention policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy is malformed.
    pub fn validate(&self) -> crate::Result<()> {
        if matches!(self.max_versions, Some(0)) {
            return Err(Error::InvalidPolicy(
                "max_versions must be greater than zero",
            ));
        }

        if matches!(self.ttl, Some(ttl) if ttl.is_zero()) {
            return Err(Error::InvalidPolicy("ttl must be greater than zero"));
        }

        Ok(())
    }
}

/// Reason a secure compaction policy deleted a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionDeleteReason {
    /// Version exceeded [`RetentionPolicy::max_versions`].
    MaxVersions,

    /// Version exceeded [`RetentionPolicy::ttl`].
    Ttl,
}

#[derive(Clone)]
pub(super) struct SecureCompactionPolicy<I>
where
    I: Clone + Send + Sync + 'static,
{
    logical_keyspace: Arc<str>,
    retention: RetentionPolicy,
    audit: Option<super::audit::AuditConfig<I>>,
}

impl<I> SecureCompactionPolicy<I>
where
    I: Clone + Send + Sync + 'static,
{
    pub(super) fn new(
        logical_keyspace: &str,
        retention: RetentionPolicy,
        audit: Option<super::audit::AuditConfig<I>>,
    ) -> crate::Result<Self> {
        retention.validate()?;

        Ok(Self {
            logical_keyspace: Arc::from(logical_keyspace),
            retention,
            audit,
        })
    }

    pub(super) fn install_on(
        self,
        create_options: crate::KeyspaceCreateOptions,
    ) -> crate::KeyspaceCreateOptions {
        create_options
            .with_compaction_filter_factory(Arc::new(SecureRetentionFactory { policy: self }))
    }
}

struct SecureRetentionFactory<I>
where
    I: Clone + Send + Sync + 'static,
{
    policy: SecureCompactionPolicy<I>,
}

impl<I> std::panic::RefUnwindSafe for SecureRetentionFactory<I> where
    I: Clone + Send + Sync + 'static
{
}

impl<I> lsm_tree::compaction::filter::Factory for SecureRetentionFactory<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "fjall-secure-retention"
    }

    fn make_filter(
        &self,
        _ctx: &lsm_tree::compaction::filter::Context,
    ) -> Box<dyn lsm_tree::compaction::filter::CompactionFilter> {
        Box::new(SecureRetentionFilter {
            policy: self.policy.clone(),
            current_group: None,
            versions_seen: 0,
            now_unix_seconds: unix_seconds_now(),
        })
    }
}

struct SecureRetentionFilter<I>
where
    I: Clone + Send + Sync + 'static,
{
    policy: SecureCompactionPolicy<I>,
    current_group: Option<VersionGroup>,
    versions_seen: usize,
    now_unix_seconds: i64,
}

impl<I> lsm_tree::compaction::filter::CompactionFilter for SecureRetentionFilter<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn filter_item(
        &mut self,
        item: lsm_tree::compaction::filter::ItemAccessor<'_>,
        _ctx: &lsm_tree::compaction::filter::Context,
    ) -> lsm_tree::Result<lsm_tree::compaction::filter::Verdict> {
        let key = CompositeKey::decode(item.key()).map_err(|err| to_lsm_error(&err))?;
        let group = VersionGroup::from(&key);

        if self.current_group.as_ref() != Some(&group) {
            self.current_group = Some(group);
            self.versions_seen = 0;
        }

        self.versions_seen += 1;

        if self
            .policy
            .retention
            .max_versions
            .is_some_and(|max| self.versions_seen > max)
        {
            self.audit_delete(CompactionDeleteReason::MaxVersions)
                .map_err(|err| to_lsm_error(&err))?;
            return Ok(lsm_tree::compaction::filter::Verdict::Remove);
        }

        if self.is_expired(key.timestamp) {
            self.audit_delete(CompactionDeleteReason::Ttl)
                .map_err(|err| to_lsm_error(&err))?;
            return Ok(lsm_tree::compaction::filter::Verdict::Remove);
        }

        Ok(lsm_tree::compaction::filter::Verdict::Keep)
    }
}

impl<I> SecureRetentionFilter<I>
where
    I: Clone + Send + Sync + 'static,
{
    fn is_expired(&self, timestamp: i64) -> bool {
        let Some(ttl) = self.policy.retention.ttl else {
            return false;
        };
        let Ok(ttl_seconds) = i64::try_from(ttl.as_secs()) else {
            return false;
        };

        timestamp <= self.now_unix_seconds.saturating_sub(ttl_seconds)
    }

    fn audit_delete(&self, reason: CompactionDeleteReason) -> crate::Result<()> {
        if let Some(audit) = &self.policy.audit {
            audit.record(super::AuditEvent::CompactionDeleted {
                keyspace: &self.policy.logical_keyspace,
                reason,
            })?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VersionGroup {
    row: UserValue,
    family: UserValue,
    qualifier: UserValue,
    visibility: UserValue,
}

impl From<&CompositeKey> for VersionGroup {
    fn from(key: &CompositeKey) -> Self {
        Self {
            row: key.row.clone(),
            family: key.family.clone(),
            qualifier: key.qualifier.clone(),
            visibility: key.visibility.clone(),
        }
    }
}

fn unix_seconds_now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    i64::try_from(seconds).unwrap_or(i64::MAX)
}

fn to_lsm_error(err: &Error) -> lsm_tree::Error {
    log::warn!("secure retention compaction failed closed: {err:?}");
    lsm_tree::Error::Unrecoverable
}
