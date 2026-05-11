// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Value encryption hooks for secure keyspaces.

use crate::{Error, KeyspaceCreateOptions, UserValue};
use std::sync::Arc;

const VALUE_ENCRYPTION_MAGIC: &[u8] = b"fjall:secure:v1:";

/// Encryption scope requested for a secure keyspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionScope {
    /// Encrypt values before storing them.
    Value,

    /// Reserved for lower-level block encryption.
    Block,

    /// Keyspace-level policy scope.
    Keyspace,
}

/// Context passed to encryption providers.
#[derive(Clone, Copy, Debug)]
pub struct CryptoContext<'a> {
    /// Logical secure keyspace name.
    pub keyspace: &'a str,

    /// Encoded physical key.
    pub key: &'a [u8],

    /// Requested encryption scope.
    pub scope: EncryptionScope,
}

/// Pluggable encryption provider for secure keyspace values.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Encrypts plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when key lookup or encryption fails.
    fn encrypt(&self, context: CryptoContext<'_>, plaintext: &[u8]) -> crate::Result<Vec<u8>>;

    /// Decrypts ciphertext bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when key lookup or decryption fails.
    fn decrypt(&self, context: CryptoContext<'_>, ciphertext: &[u8]) -> crate::Result<Vec<u8>>;
}

/// Encryption configuration for a secure keyspace.
#[derive(Clone)]
pub struct EncryptionConfig {
    pub(crate) provider: Arc<dyn CryptoProvider>,

    /// Requested encryption scope.
    pub scope: EncryptionScope,
}

impl EncryptionConfig {
    /// Creates value encryption config from a provider.
    #[must_use]
    pub fn new(provider: impl CryptoProvider, scope: EncryptionScope) -> Self {
        Self {
            provider: Arc::new(provider),
            scope,
        }
    }
}

/// Options to create or open a secure keyspace.
#[derive(Clone, Default)]
pub struct SecureKeyspaceOptions {
    /// Raw Fjall keyspace creation options.
    pub create_options: KeyspaceCreateOptions,

    /// Optional value encryption configuration.
    pub encryption: Option<EncryptionConfig>,

    /// Optional keyspace-scope retention policy.
    pub retention: Option<super::RetentionPolicy>,
}

impl SecureKeyspaceOptions {
    /// Sets raw keyspace creation options.
    #[must_use]
    pub fn with_create_options(mut self, create_options: KeyspaceCreateOptions) -> Self {
        self.create_options = create_options;
        self
    }

    /// Enables value encryption for this secure keyspace.
    #[must_use]
    pub fn with_encryption(mut self, encryption: EncryptionConfig) -> Self {
        self.encryption = Some(encryption);
        self
    }

    /// Enables retention policy compaction for this secure keyspace.
    #[must_use]
    pub fn with_retention(mut self, retention: super::RetentionPolicy) -> Self {
        self.retention = Some(retention);
        self
    }
}

#[derive(Clone)]
pub(crate) struct ValueEncryption {
    logical_keyspace: Arc<str>,
    config: EncryptionConfig,
}

impl ValueEncryption {
    pub(crate) fn new(logical_keyspace: &str, config: EncryptionConfig) -> Self {
        Self {
            logical_keyspace: Arc::from(logical_keyspace),
            config,
        }
    }

    pub(crate) fn encrypt_value(
        &self,
        encoded_key: &[u8],
        value: UserValue,
    ) -> crate::Result<UserValue> {
        let context = self.context(encoded_key);
        let ciphertext = self.config.provider.encrypt(context, value.as_ref())?;
        let ciphertext_len = u32::try_from(ciphertext.len())
            .map_err(|_| Error::Crypto("ciphertext exceeds u32 length"))?;

        let mut stored = Vec::with_capacity(
            VALUE_ENCRYPTION_MAGIC.len() + std::mem::size_of::<u32>() + ciphertext.len(),
        );
        stored.extend_from_slice(VALUE_ENCRYPTION_MAGIC);
        stored.extend_from_slice(&ciphertext_len.to_be_bytes());
        stored.extend_from_slice(&ciphertext);

        Ok(stored.into())
    }

    pub(crate) fn decrypt_value(
        &self,
        encoded_key: &[u8],
        stored: UserValue,
    ) -> crate::Result<UserValue> {
        let ciphertext = parse_stored_ciphertext(stored.as_ref())?;
        let plaintext = self
            .config
            .provider
            .decrypt(self.context(encoded_key), ciphertext)?;

        Ok(plaintext.into())
    }

    fn context<'a>(&'a self, encoded_key: &'a [u8]) -> CryptoContext<'a> {
        CryptoContext {
            keyspace: &self.logical_keyspace,
            key: encoded_key,
            scope: self.config.scope,
        }
    }
}

pub(crate) fn maybe_encrypt_value(
    encryption: Option<&ValueEncryption>,
    encoded_key: &[u8],
    value: impl Into<UserValue>,
) -> crate::Result<UserValue> {
    let value = value.into();

    if let Some(encryption) = encryption {
        encryption.encrypt_value(encoded_key, value)
    } else {
        Ok(value)
    }
}

pub(crate) fn maybe_decrypt_entry(
    encryption: Option<&ValueEncryption>,
    encoded_key: &[u8],
    value: UserValue,
) -> crate::Result<UserValue> {
    if let Some(encryption) = encryption {
        encryption.decrypt_value(encoded_key, value)
    } else {
        Ok(value)
    }
}

fn parse_stored_ciphertext(stored: &[u8]) -> crate::Result<&[u8]> {
    let rest = stored
        .strip_prefix(VALUE_ENCRYPTION_MAGIC)
        .ok_or(Error::Crypto("encrypted value marker missing"))?;
    let (len, ciphertext) = rest
        .split_first_chunk::<4>()
        .ok_or(Error::Crypto("encrypted value length missing"))?;
    let len = u32::from_be_bytes(*len) as usize;

    if ciphertext.len() != len {
        return Err(Error::Crypto("encrypted value length mismatch"));
    }

    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct XorCryptoProvider {
        key: u8,
    }

    impl CryptoProvider for XorCryptoProvider {
        fn encrypt(&self, _context: CryptoContext<'_>, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
            Ok(plaintext.iter().map(|byte| byte ^ self.key).collect())
        }

        fn decrypt(&self, context: CryptoContext<'_>, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
            self.encrypt(context, ciphertext)
        }
    }

    pub(super) fn xor_config(key: u8) -> EncryptionConfig {
        EncryptionConfig::new(XorCryptoProvider { key }, EncryptionScope::Value)
    }

    #[test]
    fn value_encryption_roundtrips_with_marker() -> crate::Result<()> {
        let encryption = ValueEncryption::new("events", xor_config(0x5a));
        let encrypted = encryption.encrypt_value(b"key", UserValue::from("plaintext"))?;

        assert_ne!(encrypted.as_ref(), b"plaintext");
        assert!(encrypted.as_ref().starts_with(VALUE_ENCRYPTION_MAGIC));
        assert_eq!(
            UserValue::from("plaintext"),
            encryption.decrypt_value(b"key", encrypted)?,
        );

        Ok(())
    }
}
