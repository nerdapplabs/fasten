//! Running the sync `postgres` client from async code. The client runs its
//! own runtime and panics on a thread that drives a tokio runtime ("Cannot
//! start a runtime from within a runtime"), on every call and when it is
//! dropped. Shared by the audit and stream stores.

/// True on a thread that drives a tokio runtime.
pub(crate) fn in_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

/// Runs `f` here, or on a scoped thread when this thread drives a tokio
/// runtime, so a store opened or called from async code works.
pub(crate) fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    if !in_runtime() {
        return f();
    }
    std::thread::scope(|s| s.spawn(f).join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
}

/// A store's connection. Dropping a sync client closes it through the
/// client's runtime, so on a runtime thread it is closed on a thread of its
/// own instead. `None` only once dropped.
pub(crate) struct Conn(pub(crate) Option<pg::Client>);

/// Closes `client` on a new thread. If the OS refuses one, the client is
/// leaked rather than dropped here: dropping it on the runtime thread
/// panics, and a panic in drop during unwinding aborts the process.
fn close_off_runtime(client: pg::Client) {
    let client = std::mem::ManuallyDrop::new(client);
    let spawned = std::thread::Builder::new()
        .name("fasten-pg-close".into())
        .spawn(move || drop(std::mem::ManuallyDrop::into_inner(client)));
    if spawned.is_err() {
        eprintln!("fasten: no thread to close a Postgres connection on; it was left open");
    }
}

impl std::ops::Deref for Conn {
    type Target = pg::Client;
    fn deref(&self) -> &pg::Client {
        self.0.as_ref().expect("the connection is taken only on drop")
    }
}

impl std::ops::DerefMut for Conn {
    fn deref_mut(&mut self) -> &mut pg::Client {
        self.0.as_mut().expect("the connection is taken only on drop")
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Some(client) = self.0.take().filter(|_| in_runtime()) {
            close_off_runtime(client);
        }
    }
}
