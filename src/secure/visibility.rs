// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! Visibility expressions and authorization labels.

use crate::Error;
use std::collections::BTreeSet;

/// A parsed, canonicalized visibility expression.
///
/// Empty expressions are public and evaluate to `true` for every
/// authorization set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibilityExpr {
    expr: Expr,
    canonical: String,
}

impl VisibilityExpr {
    /// Parses and canonicalizes a visibility expression.
    ///
    /// Supported operators are `&` for conjunction, `|` for disjunction, and
    /// parentheses for grouping. `&` has higher precedence than `|`.
    ///
    /// # Errors
    ///
    /// Returns an error if the expression is syntactically invalid.
    pub fn parse(input: &str) -> crate::Result<Self> {
        if input.is_empty() {
            return Ok(Self::public());
        }

        let mut parser = Parser::new(input);
        let expr = parser.parse_expr()?;

        if !parser.is_empty() {
            return Err(Error::InvalidVisibilityExpression(
                "unexpected trailing visibility token",
            ));
        }

        let expr = expr.normalized();
        let canonical = expr.canonical();

        Ok(Self { expr, canonical })
    }

    /// Returns the public empty visibility expression.
    #[must_use]
    pub fn public() -> Self {
        Self {
            expr: Expr::Public,
            canonical: String::new(),
        }
    }

    /// Returns `true` when this is the empty public visibility expression.
    #[must_use]
    pub fn is_public(&self) -> bool {
        matches!(self.expr, Expr::Public)
    }

    /// Evaluates the expression against an authorization label set.
    #[must_use]
    pub fn evaluate(&self, auths: &Authorizations) -> bool {
        self.expr.evaluate(auths)
    }

    /// Returns the canonical expression string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the canonical expression bytes to store in composite keys.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Consumes the expression and returns its canonical string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.canonical
    }
}

impl std::fmt::Display for VisibilityExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl std::str::FromStr for VisibilityExpr {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// A set of authorization labels used to evaluate visibility expressions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Authorizations {
    labels: BTreeSet<String>,
}

impl Authorizations {
    /// Returns an empty authorization set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds an authorization set from labels.
    ///
    /// # Errors
    ///
    /// Returns an error if any label is not a valid visibility identifier.
    pub fn from_labels<I, S>(labels: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut auths = Self::default();

        for label in labels {
            auths.insert(label)?;
        }

        Ok(auths)
    }

    /// Inserts one authorization label.
    ///
    /// Returns whether the label was newly inserted.
    ///
    /// # Errors
    ///
    /// Returns an error if the label is not a valid visibility identifier.
    pub fn insert(&mut self, label: impl Into<String>) -> crate::Result<bool> {
        let label = label.into();

        if !is_valid_label(&label) {
            return Err(Error::InvalidVisibilityExpression(
                "authorization label must be a valid identifier",
            ));
        }

        Ok(self.labels.insert(label))
    }

    /// Returns `true` if the set contains `label`.
    #[must_use]
    pub fn contains(&self, label: &str) -> bool {
        self.labels.contains(label)
    }

    /// Iterates authorization labels in stable sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.labels.iter().map(String::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expr {
    Public,
    Label(String),
    And(Vec<Self>),
    Or(Vec<Self>),
}

impl Expr {
    fn normalized(self) -> Self {
        match self {
            Self::And(children) => normalize_children(children, Operator::And),
            Self::Or(children) => normalize_children(children, Operator::Or),
            other => other,
        }
    }

    fn evaluate(&self, auths: &Authorizations) -> bool {
        match self {
            Self::Public => true,
            Self::Label(label) => auths.contains(label),
            Self::And(children) => children.iter().all(|child| child.evaluate(auths)),
            Self::Or(children) => children.iter().any(|child| child.evaluate(auths)),
        }
    }

    fn canonical(&self) -> String {
        let mut canonical = String::new();
        self.write_canonical(0, &mut canonical);
        canonical
    }

    fn write_canonical(&self, parent_precedence: u8, canonical: &mut String) {
        let precedence = self.precedence();
        let wrap = precedence < parent_precedence;

        if wrap {
            canonical.push('(');
        }

        match self {
            Self::Public => {}
            Self::Label(label) => canonical.push_str(label),
            Self::And(children) => write_joined(children, '&', precedence, canonical),
            Self::Or(children) => write_joined(children, '|', precedence, canonical),
        }

        if wrap {
            canonical.push(')');
        }
    }

    fn precedence(&self) -> u8 {
        match self {
            Self::Public | Self::Label(_) => 3,
            Self::And(_) => 2,
            Self::Or(_) => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operator {
    And,
    Or,
}

fn normalize_children(children: Vec<Expr>, operator: Operator) -> Expr {
    let mut pairs = Vec::new();

    for child in children {
        let normalized = child.normalized();

        match (operator, normalized) {
            (Operator::And, Expr::And(grandchildren)) | (Operator::Or, Expr::Or(grandchildren)) => {
                for grandchild in grandchildren {
                    let canonical = grandchild.canonical();
                    pairs.push((canonical, grandchild));
                }
            }
            (operator, Expr::Public) => match operator {
                Operator::And => {}
                Operator::Or => return Expr::Public,
            },
            (_, normalized) => {
                let canonical = normalized.canonical();
                pairs.push((canonical, normalized));
            }
        }
    }

    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs.dedup_by(|left, right| left.0 == right.0);

    let mut children = pairs.into_iter().map(|(_canonical, child)| child);
    let Some(first) = children.next() else {
        return Expr::Public;
    };
    let Some(second) = children.next() else {
        return first;
    };

    let mut all = vec![first, second];
    all.extend(children);

    match operator {
        Operator::And => Expr::And(all),
        Operator::Or => Expr::Or(all),
    }
}

fn write_joined(children: &[Expr], separator: char, precedence: u8, canonical: &mut String) {
    let mut first = true;

    for child in children {
        if first {
            first = false;
        } else {
            canonical.push(separator);
        }

        child.write_canonical(precedence, canonical);
    }
}

struct Parser<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().peekable(),
        }
    }

    fn parse_expr(&mut self) -> crate::Result<Expr> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> crate::Result<Expr> {
        let mut children = vec![self.parse_and_expr()?];

        while self.consume('|') {
            children.push(self.parse_and_expr()?);
        }

        Ok(if children.len() == 1 {
            remove_only_child(children)
        } else {
            Expr::Or(children)
        })
    }

    fn parse_and_expr(&mut self) -> crate::Result<Expr> {
        let mut children = vec![self.parse_primary()?];

        while self.consume('&') {
            children.push(self.parse_primary()?);
        }

        Ok(if children.len() == 1 {
            remove_only_child(children)
        } else {
            Expr::And(children)
        })
    }

    fn parse_primary(&mut self) -> crate::Result<Expr> {
        if self.consume('(') {
            let expr = self.parse_expr()?;

            if !self.consume(')') {
                return Err(Error::InvalidVisibilityExpression(
                    "expected closing parenthesis",
                ));
            }

            return Ok(expr);
        }

        let label = self.parse_label();

        if label.is_empty() {
            return Err(Error::InvalidVisibilityExpression(
                "expected label or parenthesized expression",
            ));
        }

        Ok(Expr::Label(label))
    }

    fn parse_label(&mut self) -> String {
        let mut label = String::new();

        while self.peek().is_some_and(is_label_char) {
            if let Some(next) = self.chars.next() {
                label.push(next);
            }
        }

        label
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek().is_some_and(|next| next == expected) {
            self.chars.next();
            return true;
        }

        false
    }

    fn is_empty(&mut self) -> bool {
        self.chars.peek().is_none()
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }
}

fn remove_only_child(mut children: Vec<Expr>) -> Expr {
    children.pop().map_or(Expr::Public, |child| child)
}

fn is_valid_label(label: &str) -> bool {
    !label.is_empty() && label.chars().all(is_label_char)
}

fn is_label_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    fn canonical(input: &str) -> crate::Result<String> {
        Ok(VisibilityExpr::parse(input)?.into_string())
    }

    fn auths(labels: &[&str]) -> crate::Result<Authorizations> {
        Authorizations::from_labels(labels.iter().copied())
    }

    #[test]
    fn empty_visibility_is_public() -> crate::Result<()> {
        let expr = VisibilityExpr::parse("")?;

        assert!(expr.is_public());
        assert_eq!("", expr.as_str());
        assert!(expr.evaluate(&Authorizations::empty()));

        Ok(())
    }

    #[test]
    fn evaluates_labels_conjunctions_and_disjunctions() -> crate::Result<()> {
        let admin = auths(&["admin"])?;
        let audit = auths(&["audit"])?;
        let admin_audit = auths(&["admin", "audit"])?;

        assert!(VisibilityExpr::parse("admin")?.evaluate(&admin));
        assert!(!VisibilityExpr::parse("admin")?.evaluate(&audit));
        assert!(VisibilityExpr::parse("admin&audit")?.evaluate(&admin_audit));
        assert!(!VisibilityExpr::parse("admin&audit")?.evaluate(&admin));
        assert!(VisibilityExpr::parse("admin|audit")?.evaluate(&admin));
        assert!(VisibilityExpr::parse("admin|audit")?.evaluate(&audit));

        Ok(())
    }

    #[test]
    fn parser_honors_precedence_and_parentheses() -> crate::Result<()> {
        let admin = auths(&["admin"])?;
        let audit = auths(&["audit"])?;
        let support_audit = auths(&["support", "audit"])?;

        let precedence = VisibilityExpr::parse("admin|support&audit")?;
        assert!(precedence.evaluate(&admin));
        assert!(!precedence.evaluate(&audit));
        assert!(precedence.evaluate(&support_audit));

        let grouped = VisibilityExpr::parse("(admin|support)&audit")?;
        assert!(!grouped.evaluate(&admin));
        assert!(grouped.evaluate(&support_audit));

        Ok(())
    }

    #[test]
    fn canonicalizes_commutative_associative_expressions() -> crate::Result<()> {
        assert_eq!("admin&audit", canonical("audit&admin")?);
        assert_eq!("admin&audit", canonical("admin&(audit&admin)")?);
        assert_eq!("admin|audit|support", canonical("support|admin|audit")?);
        assert_eq!("(admin|support)&audit", canonical("audit&(support|admin)")?);
        assert_eq!("admin|audit&support", canonical("support&audit|admin")?);

        Ok(())
    }

    #[test]
    fn rejects_invalid_syntax() {
        for input in [
            "&admin",
            "admin|",
            "admin&&audit",
            "()",
            "(admin",
            "admin)",
            "admin audit",
        ] {
            assert!(
                VisibilityExpr::parse(input).is_err(),
                "{input:?} should be invalid",
            );
        }
    }

    #[test]
    fn authorization_sets_validate_labels() -> crate::Result<()> {
        let mut auths = Authorizations::empty();

        assert!(auths.insert("admin")?);
        assert!(!auths.insert("admin")?);
        assert!(auths.contains("admin"));
        assert!(auths.insert("tenant:acme")?);
        assert!(auths.insert("policy.v1")?);
        assert!(auths.insert("break-glass")?);
        assert!(auths.insert("_system")?);
        assert!(auths.insert("bad label").is_err());
        assert!(auths.insert("").is_err());

        assert_eq!(
            vec![
                "_system",
                "admin",
                "break-glass",
                "policy.v1",
                "tenant:acme"
            ],
            auths.iter().collect::<Vec<_>>(),
        );

        Ok(())
    }
}
