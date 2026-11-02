use crate::error::Error;

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Accept `table` or `schema.table`; reject everything else.
///
/// Both parts must match `[A-Za-z_][A-Za-z0-9_]*`. No quoting or `$` is
/// allowed, so the names can be interpolated into DDL directly.
pub fn validate_table_name(name: &str) -> Result<(), Error> {
    let ok = match name.split_once('.') {
        Some((schema, bare)) => is_valid_ident(schema) && is_valid_ident(bare),
        None => is_valid_ident(name),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidTableName(name.to_owned()))
    }
}

/// Split `"schema.table"` into `(Some("schema"), "table")`; a bare name
/// gives `(None, name)`.
pub fn split_table(name: &str) -> (Option<&str>, &str) {
    match name.split_once('.') {
        Some((s, t)) => (Some(s), t),
        None => (None, name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_plain() { assert!(validate_table_name("audit_log").is_ok()); }

    #[test]
    fn valid_schema_qualified() {
        assert!(validate_table_name("fasten.audit_log").is_ok());
    }

    #[test]
    fn rejects_hyphen() {
        assert!(validate_table_name("bad-name").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_table_name("").is_err());
    }

    #[test]
    fn rejects_leading_digit() {
        assert!(validate_table_name("1bad").is_err());
    }

    #[test]
    fn rejects_sql_injection() {
        assert!(validate_table_name("audit; DROP TABLE users--").is_err());
    }

    #[test]
    fn split_returns_parts() {
        assert_eq!(split_table("fasten.logs"), (Some("fasten"), "logs"));
        assert_eq!(split_table("logs"), (None, "logs"));
    }
}
