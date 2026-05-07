use crate::{error::Error, row::Row};

/// Minimal write-path contract shared by all storage backends.
///
/// Both methods must be thread-safe; the implementations wrap their
/// internals in a `Mutex` and implement `Send + Sync`.
pub trait Store: Send + Sync {
    /// Persist `row`.  Duplicate IDs are silently ignored
    /// (`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING`).
    fn insert(&self, row: &Row) -> Result<(), Error>;

    /// Verify the backend is reachable. Used by health-check callers and
    /// the doctor endpoint. A lightweight query (`SELECT 1`) is sufficient.
    fn ping(&self) -> Result<(), Error>;
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;
