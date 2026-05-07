use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Table or schema name contains characters outside [A-Za-z_][A-Za-z0-9_]*.
    #[error(
        "invalid table name {0:?}: must match \
         ^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?$"
    )]
    InvalidTableName(String),

    /// The `backend` string passed to `fasten_store_open` is not recognised.
    #[error("unknown backend {0:?}: expected \"sqlite\" or \"postgres\"")]
    UnknownBackend(String),

    /// A pointer argument was null where a non-null value was required.
    #[error("null pointer argument")]
    NullArg,

    /// A C string argument contained invalid UTF-8.
    #[error("argument is not valid UTF-8")]
    InvalidUtf8,

    /// Row JSON passed to `fasten_store_insert` could not be deserialised.
    #[error("row JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// SQLite backend error.
    #[cfg(feature = "sqlite")]
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// PostgreSQL backend error.
    #[cfg(feature = "postgres")]
    #[error("postgres: {0}")]
    Postgres(#[from] ::postgres::Error),
}

// When neither sqlite nor postgres feature is active, the #[from] impls above
// are absent but Error still compiles; callers get UnknownBackend at runtime.
