# RFC 0006: Encryption Providers

## Status

Draft

## Summary

Add optional encryption provider hooks for secure keyspaces. Encryption is not required for visibility filtering, but it is required if secure keyspace data must remain confidential from raw file access or raw keyspace bypass.

## Motivation

In an embedded database, in-process authorization is only as strong as the API boundary. Encryption with externally managed keys can protect data at rest when storage files are copied or when raw storage paths are exposed.

Fjall's crypto service architecture motivates a pluggable provider model instead of hard-coding one key management system.

## Proposed API Sketch

```rust
pub struct EncryptionConfig<P> {
    pub provider: P,
    pub scope: EncryptionScope,
}

pub enum EncryptionScope {
    Value,
    Block,
    Keyspace,
}

pub trait CryptoProvider {
    fn encrypt(&self, context: CryptoContext<'_>, plaintext: &[u8]) -> Result<Vec<u8>>;

    fn decrypt(&self, context: CryptoContext<'_>, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

The implementation may need streaming or buffer-oriented APIs to avoid unnecessary allocations.

## Secure Keyspace Options

```rust
pub struct SecureKeyspaceOptions<P> {
    pub encryption: Option<EncryptionConfig<P>>,
}
```

Encryption initialization failures must fail `open` or secure-keyspace creation.

## Encryption Granularity

Initial implementation should prefer value encryption unless lower-level block encryption can be integrated cleanly with the underlying LSM tree.

Tradeoffs:

| Granularity | Benefit | Cost |
| --- | --- | --- |
| value | simple API boundary | leaks key metadata and value sizes |
| block | better locality and metadata hiding | requires deeper storage integration |
| keyspace | simpler policy model | may still map to block or value implementation |

## Key Encryption

Composite keys include row, family, qualifier, visibility, and timestamp. If keys remain plaintext, an attacker with file access may infer metadata. Key encryption is out of scope for the first implementation unless it preserves ordering, which ordinary AEAD encryption does not.

The RFC should explicitly document that value encryption does not hide key metadata.

## Wire Encryption

Fjall is embedded and does not provide a wire protocol. Remote embeddings should use TLS, QUIC, mTLS, or their host framework's transport security. This RFC does not add network encryption to Fjall itself.

## Failure Semantics

Security failures must fail closed:

- missing required provider fails database or secure-keyspace open
- key lookup failure denies read/write
- decrypt failure denies value exposure
- encrypt failure rejects write

## Validation

Tests should cover:

- encrypted writes are not stored as plaintext values
- decrypting reads return original values
- wrong key/provider fails closed
- compaction preserves decryptability
- snapshots and transactions work with encrypted values

## Open Questions

- Should encryption be implemented in Fjall or delegated to the underlying `lsm-tree` crate?
- Should key metadata be authenticated as AEAD associated data?
- Should key rotation be supported in the first version?
- Should encryption policies be per keyspace, per family, or per value?
