# RFC 0003: Visibility Expressions and Authorizations

## Status

Draft - initial visibility expression implementation landed behind `secure-keyspaces`

## Summary

Add Fjall-style visibility expressions and authorization sets. A record is visible when its visibility expression evaluates to true for the session's authorization labels.

## Motivation

Multi-tenant and policy-sensitive embedded applications need record-level access control during scans. Filtering must happen lazily during iteration and before values are exposed.

## Visibility Grammar

```ebnf
expr      = or_expr ;
or_expr   = and_expr { "|" and_expr } ;
and_expr  = primary { "&" primary } ;
primary   = IDENT | "(" expr ")" ;
```

Example expressions:

```text
admin
admin&audit
(admin|support)&audit
```

## Proposed API Sketch

```rust
pub struct VisibilityExpr {
    // canonical compiled representation
}

pub struct Authorizations {
    labels: BTreeSet<String>,
}

impl VisibilityExpr {
    pub fn parse(input: &str) -> Result<Self>;

    pub fn evaluate(&self, auths: &Authorizations) -> bool;
}
```

The implementation should avoid parsing expressions during scans. Writes should parse, validate, and canonicalize expressions before storage.

## Canonicalization

Visibility expressions should have a canonical byte representation so equivalent expressions do not fragment storage unnecessarily.

For example, the implementation may normalize:

```text
audit&admin
admin&audit
```

to the same canonical representation.

Canonicalization must preserve semantics and must not reorder expressions in a way that changes parse precedence.

## Empty Visibility

The empty visibility expression should be allowed and should evaluate to true for all sessions. It represents public data in a secure keyspace.

## Failure Semantics

Security failures must fail closed:

- parse errors reject writes
- invalid stored visibility rejects exposure of that record
- authorizations lookup failures deny reads
- missing security providers deny operations that require them

## Iterator Semantics

Visibility filtering must occur:

- lazily
- during iteration
- after snapshot selection
- before value exposure

The iterator may skip unauthorized keys without returning an error. Provider failures should return an error item and stop or poison the iterator according to the existing Fjall iterator error style.

## Performance

Expected costs:

- parsing and canonicalization on writes
- expression evaluation on scans
- authorization label lookup

Mitigations:

- compiled AST or bytecode
- interned labels
- cached authorization bitsets
- canonical expression memoization

## Validation

Tests should cover:

- parser precedence
- parentheses
- invalid syntax
- empty visibility
- canonicalization
- evaluation against different authorization sets
- lazy iterator filtering

## Open Questions

- Should visibility expressions be stored as raw canonical strings, compiled bytecode, or interned IDs?
- Should labels permit arbitrary UTF-8, ASCII identifiers only, or escaped binary tokens?
- Should expression evaluation be implemented in this crate or delegated to a small dedicated crate?
