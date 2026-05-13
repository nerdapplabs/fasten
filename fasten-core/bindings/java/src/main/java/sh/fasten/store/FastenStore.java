package sh.fasten.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.io.IOException;
import java.util.Map;

/**
 * Thread-safe Java client for an audit store backed by libfasten_store_core.
 *
 * <p>Implements {@link AutoCloseable} for use with try-with-resources:
 * <pre>{@code
 * try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
 *     store.insert(rowMap);
 * }
 * }</pre>
 *
 * <p>Library loading: set {@code FASTEN_STORE_CORE_LIB} to the absolute path of
 * the .so/.dylib/.dll, or ensure {@code libfasten_store_core} is on
 * {@code LD_LIBRARY_PATH} / {@code DYLD_LIBRARY_PATH} / the system library path.
 */
public final class FastenStore implements AutoCloseable {

    private static final FastenStoreLib LIB = FastenStoreLib.INSTANCE;
    private static final ObjectMapper   JSON = new ObjectMapper();

    private volatile Pointer handle;

    private FastenStore(Pointer handle) {
        this.handle = handle;
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    /**
     * Open an audit store.
     *
     * @param backend  {@code "sqlite"} or {@code "postgres"}
     * @param connstr  SQLite path / {@code ":memory:"} or PostgreSQL DSN
     * @param table    plain or schema-qualified table name
     * @throws FastenStoreException if the backend cannot be opened
     */
    public static FastenStore open(String backend, String connstr, String table) {
        var errRef = new PointerByReference(Pointer.NULL);
        Pointer h = LIB.fasten_store_open(backend, connstr, table, errRef);
        if (h == null) {
            throw new FastenStoreException(takeError(errRef));
        }
        return new FastenStore(h);
    }

    /** Convenience overload — uses {@code "audit_log"} as the table name. */
    public static FastenStore open(String backend, String connstr) {
        return open(backend, connstr, "audit_log");
    }

    // ── Write path ────────────────────────────────────────────────────────────

    /**
     * Insert one audit row.  Accepts any {@link Map} or POJO that Jackson
     * can serialise.  Duplicate IDs are silently ignored.
     *
     * @throws FastenStoreException on backend error
     */
    public void insert(Object row) {
        String json;
        try {
            json = JSON.writeValueAsString(row);
        } catch (IOException e) {
            throw new FastenStoreException("JSON serialisation failed", e);
        }
        insertJson(json);
    }

    /**
     * Insert from a pre-serialised JSON string.
     *
     * @throws FastenStoreException on backend error
     */
    public void insertJson(String rowJson) {
        var errRef = new PointerByReference(Pointer.NULL);
        int rc = LIB.fasten_store_insert(handle, rowJson, errRef);
        if (rc != 0) {
            throw new FastenStoreException(takeError(errRef));
        }
    }

    // ── Health ────────────────────────────────────────────────────────────────

    /**
     * Verify the backend is reachable (runs {@code SELECT 1}).
     *
     * @throws FastenStoreException if unreachable
     */
    public void ping() {
        var errRef = new PointerByReference(Pointer.NULL);
        int rc = LIB.fasten_store_ping(handle, errRef);
        if (rc != 0) {
            throw new FastenStoreException(takeError(errRef));
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /** Release all resources.  Safe to call multiple times. */
    @Override
    public synchronized void close() {
        if (handle != null) {
            LIB.fasten_store_close(handle);
            handle = null;
        }
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    /** Return the library version string, e.g. {@code "0.1.0"}. */
    public static String version() {
        return LIB.fasten_store_version();
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private static String takeError(PointerByReference errRef) {
        Pointer p = errRef.getValue();
        if (p == null || p.equals(Pointer.NULL)) {
            return "(no detail)";
        }
        String msg = p.getString(0);
        LIB.fasten_store_free_str(p);
        return msg;
    }
}
