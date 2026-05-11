# secure-keyspaces-guide

This example demonstrates the secure keyspace RFC work:

- secure database construction with authentication, authorization, permissions, and audit hooks
- versioned cells with visibility labels
- value encryption through a pluggable `CryptoProvider`
- keyspace-scope retention policy enforced during compaction
- best-effort versus fail-closed audit behavior

Run it from the repository root:

```sh
cargo run --manifest-path examples/secure-keyspaces-guide/Cargo.toml
```

The example stores three versions of one secure cell, runs major compaction, and shows that the retention policy keeps only the two newest versions. It also verifies that values are encrypted at rest, hidden labels are filtered by session authorizations, and audit events are recorded without including keys or values.
