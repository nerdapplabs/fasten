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
    Postgres(#[from] pg::Error),
}

// When neither sqlite nor postgres feature is active, the #[from] impls above
// are absent but Error still compiles; callers get UnknownBackend at runtime.

/// Typed error codes returned by all `fasten_store_*` C ABI functions.
///
/// C callers compare the return value to `FASTEN_OK` (== 0) for success.
/// Non-zero values indicate the error category; the `out_err` string provides
/// the human-readable detail.
///
/// The discriminant values are stable across library versions; new variants
/// will only ever be added with new values (never renumbering existing ones).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastenErrorCode {
    Ok           = 0,
    ErrBackend   = 1,  // SQLite or PostgreSQL backend error
    ErrBadTable  = 2,  // invalid table/schema name
    ErrBadJson   = 3,  // JSON parse or schema validation error
    ErrNullArg   = 4,  // null pointer or invalid UTF-8 argument
    ErrBadBackend = 5, // unknown backend string
    ErrUnknown   = 99, // internal panic or unexpected error
}

impl From<&Error> for FastenErrorCode {
    fn from(e: &Error) -> Self {
        match e {
            Error::InvalidTableName(_) => FastenErrorCode::ErrBadTable,
            Error::UnknownBackend(_)   => FastenErrorCode::ErrBadBackend,
            Error::NullArg             => FastenErrorCode::ErrNullArg,
            Error::InvalidUtf8         => FastenErrorCode::ErrNullArg,
            Error::Json(_)             => FastenErrorCode::ErrBadJson,
            #[cfg(feature = "sqlite")]
            Error::Sqlite(_)           => FastenErrorCode::ErrBackend,
            #[cfg(feature = "postgres")]
            Error::Postgres(_)         => FastenErrorCode::ErrBackend,
        }
    }
}
