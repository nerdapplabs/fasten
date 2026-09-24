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

    // ── Catalog errors ───────────────────────────────────────────────────────

    /// Code key does not match UPPER_SNAKE_CASE (`^[A-Z][A-Z0-9_]*$`).
    #[error(
        "register: code key {0:?} must be UPPER_SNAKE_CASE \
         (letters, digits, underscores; starts with a letter)"
    )]
    InvalidKey(String),

    /// `Meta.id` was set but does not match the dict key.
    #[error(
        "register: dict key {key:?} disagrees with Meta.id={id:?}; \
         drop Meta.id (it fills from the key) or fix the mismatch"
    )]
    IdMismatch { key: String, id: String },

    /// `Meta.domain` does not match the `domain` argument passed to `register`.
    #[error(
        "register: code {key:?} declares domain={declared:?} \
         but registered under {registered:?}"
    )]
    DomainMismatch { key: String, declared: String, registered: String },

    /// A code with this key was already registered.
    #[error("register: duplicate code {0:?}")]
    DuplicateCode(String),

    /// `fasten_drainer_enqueue` called with no drainer installed.
    #[error("no drainer installed; call fasten_drainer_install first")]
    DrainerNotInstalled,

    /// The DSN requested TLS (`sslmode=require|verify-*`) but this binary
    /// was built without the `postgres-tls` feature — fail loud rather
    /// than silently downgrade to plaintext (P1-43).
    #[error("{0}")]
    TlsUnavailable(String),

    /// Building the TLS connector itself failed (system CA store missing,
    /// bad protocol setting, etc.). Rare, distinct from
    /// `TlsUnavailable` so it doesn't get misread as a config error.
    #[error("tls connector build failed: {0}")]
    TlsConnector(String),

    /// A host-language insert callback (installed via
    /// `fasten_store_open_callback`) returned a non-zero rc. The actual
    /// exception lives on the host side; this variant carries only the
    /// rc so log lines aren't misattributed (issue #36 — previously
    /// reported as `InvalidTableName("insert callback rc=1")`).
    #[error("insert callback returned non-zero rc={0}")]
    CallbackFailed(i32),
}

// When neither sqlite nor postgres feature is active, the #[from] impls above
// are absent but Error still compiles; callers get UnknownBackend at runtime.

/// Typed error codes returned by all `fasten_*` C ABI functions.
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
    Ok              = 0,
    ErrBackend      = 1,   // SQLite or PostgreSQL backend error
    ErrBadTable     = 2,   // invalid table/schema name
    ErrBadJson      = 3,   // JSON parse or schema validation error
    ErrNullArg      = 4,   // null pointer or invalid UTF-8 argument
    ErrBadBackend   = 5,   // unknown backend string
    ErrInvalidKey   = 6,   // code key not UPPER_SNAKE_CASE
    ErrIdMismatch   = 7,   // Meta.id disagrees with dict key
    ErrDomainMismatch = 8, // Meta.domain disagrees with register(domain, ...)
    ErrDuplicateCode  = 9, // duplicate code already registered
    ErrUnknown      = 99,  // internal panic or unexpected error
}

impl From<&Error> for FastenErrorCode {
    fn from(e: &Error) -> Self {
        match e {
            Error::InvalidTableName(_) => FastenErrorCode::ErrBadTable,
            Error::UnknownBackend(_)   => FastenErrorCode::ErrBadBackend,
            Error::NullArg             => FastenErrorCode::ErrNullArg,
            Error::InvalidUtf8         => FastenErrorCode::ErrNullArg,
            Error::Json(_)             => FastenErrorCode::ErrBadJson,
            Error::InvalidKey(_)       => FastenErrorCode::ErrInvalidKey,
            Error::IdMismatch { .. }   => FastenErrorCode::ErrIdMismatch,
            Error::DomainMismatch { .. } => FastenErrorCode::ErrDomainMismatch,
            Error::DuplicateCode(_)    => FastenErrorCode::ErrDuplicateCode,
            Error::DrainerNotInstalled => FastenErrorCode::ErrNullArg,
            Error::CallbackFailed(_)   => FastenErrorCode::ErrBackend,
            Error::TlsUnavailable(_)   => FastenErrorCode::ErrBackend,
            Error::TlsConnector(_)     => FastenErrorCode::ErrBackend,
            #[cfg(feature = "sqlite")]
            Error::Sqlite(_)           => FastenErrorCode::ErrBackend,
            #[cfg(feature = "postgres")]
            Error::Postgres(_)         => FastenErrorCode::ErrBackend,
        }
    }
}
