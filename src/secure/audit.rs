// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Audit hooks for secure APIs.

use crate::Error;
use std::sync::Arc;

/// Controls how audit sink failures affect audited operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditFailureMode {
    /// Log audit errors and allow the operation to continue.
    BestEffort,

    /// Reject the audited operation if audit recording fails.
    FailClosed,
}

/// Secure audit event.
#[derive(Clone, Copy, Debug)]
pub enum AuditEvent<'a, I> {
    /// Authentication succeeded.
    AuthenticationSucceeded {
        /// Authenticated identity.
        identity: &'a I,
    },

    /// Authentication failed.
    AuthenticationFailed,

    /// Authorization was denied for a keyspace operation.
    AuthorizationDenied {
        /// Authenticated identity.
        identity: &'a I,

        /// Logical secure keyspace name.
        keyspace: &'a str,
    },

    /// A configured security policy was violated.
    PolicyViolation {
        /// Logical secure keyspace name.
        keyspace: &'a str,
    },

    /// Compaction deleted a version due to policy.
    CompactionDeleted {
        /// Logical secure keyspace name.
        keyspace: &'a str,

        /// Deletion reason.
        reason: super::CompactionDeleteReason,
    },

    /// A keyspace operation passed authorization.
    KeyspaceAccess {
        /// Authenticated identity.
        identity: &'a I,

        /// Logical secure keyspace name.
        keyspace: &'a str,
    },
}

/// Audit sink for secure API events.
pub trait AuditSink<I>: Send + Sync + 'static
where
    I: Clone + Send + Sync + 'static,
{
    /// Records one audit event.
    ///
    /// # Errors
    ///
    /// Returns an error when the sink cannot record the event.
    fn record(&self, event: AuditEvent<'_, I>) -> crate::Result<()>;
}

#[derive(Clone)]
pub(super) struct AuditConfig<I>
where
    I: Clone + Send + Sync + 'static,
{
    sink: Arc<dyn AuditSink<I>>,
    failure_mode: AuditFailureMode,
}

impl<I> AuditConfig<I>
where
    I: Clone + Send + Sync + 'static,
{
    pub(super) fn new(sink: impl AuditSink<I>, failure_mode: AuditFailureMode) -> Self {
        Self {
            sink: Arc::new(sink),
            failure_mode,
        }
    }

    pub(super) fn record(&self, event: AuditEvent<'_, I>) -> crate::Result<()> {
        match self.sink.record(event) {
            Ok(()) => Ok(()),
            Err(err) if self.failure_mode == AuditFailureMode::BestEffort => {
                log::warn!("secure audit sink failed in best-effort mode: {err:?}");
                Ok(())
            }
            Err(_) => Err(Error::Audit("audit sink failed")),
        }
    }
}
