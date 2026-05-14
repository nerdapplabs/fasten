//! `fasten-core` — shared audit-store library with a stable C ABI.
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────┐
//!  │  Language SDK  (Python · Node · Go · C++ · Swift · Java)     │
//!  │                                                              │
//!  │  fasten_store_open / fasten_store_insert / fasten_store_ping │
//!  └────────────────────────┬─────────────────────────────────────┘
//!                           │  C ABI  (cdylib / staticlib)
//!  ┌────────────────────────▼─────────────────────────────────────┐
//!  │  ffi::mod  (panic guard · null check · JSON deserialise)     │
//!  └────────────────────────┬─────────────────────────────────────┘
//!                           │  Rust trait  Store::insert / ping
//!  ┌──────────────┬─────────▼──────────┐
//!  │  SqliteStore │  PostgresStore      │
//!  │  (rusqlite,  │  (postgres 0.19,   │
//!  │   bundled)   │   pure-Rust proto, │
//!  │              │   auto-reconnect)  │
//!  └──────────────┴────────────────────┘
//! ```
//!
//! # Cross-compilation targets
//!
//! | Target                       | Notes                                    |
//! |------------------------------|------------------------------------------|
//! | `x86_64-unknown-linux-gnu`   | primary CI target                        |
//! | `aarch64-unknown-linux-gnu`  | AWS Graviton, Ampere, Raspberry Pi 4/5   |
//! | `x86_64-apple-darwin`        | macOS Intel                              |
//! | `aarch64-apple-darwin`       | macOS Apple Silicon (M-series)           |
//! | `x86_64-pc-windows-msvc`     | Windows (DLL)                            |
//!
//! SQLite is bundled (no system dep); PostgreSQL uses the pure-Rust wire
//! protocol (no libpq required on any target).
//!
//! # Feature flags
//!
//! | Feature    | Enabled by default | Adds                        |
//! |------------|--------------------|-----------------------------|
//! | `sqlite`   | yes                | `SqliteStore`, bundled SQLite|
//! | `postgres` | no                 | `PostgresStore`             |
//! | `all`      | no                 | both backends               |

// Pedantic lints — keep the library clean, but allow a few known patterns.
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used
)]
// Deliberate exceptions:
#![allow(
    clippy::module_name_repetitions, // e.g. SqliteStore in store::sqlite
    clippy::missing_errors_doc,      // internal types; C header is the contract
    clippy::must_use_candidate       // FFI return values are inherently ignored
)]

pub mod catalog;
pub mod drainer;
pub mod error;
pub mod redact;
pub mod row;
pub mod store;
pub mod validate;

pub(crate) mod ffi;

// Re-export the most used types at crate root for Rust callers.
pub use catalog::{CodeRegistry, Meta, GLOBAL_REGISTRY};
pub use error::{Error, FastenErrorCode};
pub use redact::{Redactor, REDACTOR};
pub use row::Row;
pub use store::{Filter, Store};

#[cfg(feature = "sqlite")]
pub use store::sqlite::SqliteStore;

#[cfg(feature = "postgres")]
pub use store::postgres::PostgresStore;
