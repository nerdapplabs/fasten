package sh.fasten.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Tests for {@link FastenStore}.
 *
 * <p>Requires libfasten_store_core to be built and findable:
 * <pre>
 *   cd fasten/store-core
 *   cargo build --release --features all
 *   cd bindings/java
 *   FASTEN_STORE_CORE_LIB=../../../../target/release/libfasten_store_core.so \
 *     mvn test
 * </pre>
 *
 * <p>All tests are skipped gracefully when the native library is absent so
 * the Java SDK's own CI passes without Rust being installed.
 *
 * <p>PostgreSQL tests are additionally skipped when
 * {@code FASTEN_TEST_POSTGRES_DSN} is absent.
 */
class FastenStoreTest {

    private static boolean libAvailable;

    @BeforeAll
    static void checkLibrary() {
        try {
            // Trigger JNA load; if it throws the library isn't present.
            FastenStoreLib.INSTANCE.fasten_store_version();
            libAvailable = true;
        } catch (UnsatisfiedLinkError | ExceptionInInitializerError e) {
            libAvailable = false;
        }
    }

    void requireLib() {
        assumeTrue(libAvailable,
            "libfasten_store_core not found — build with `cargo build --release --features all`");
    }

    String pgDsn() {
        String dsn = System.getenv("FASTEN_TEST_POSTGRES_DSN");
        assumeTrue(dsn != null && !dsn.isBlank(), "FASTEN_TEST_POSTGRES_DSN not set");
        return dsn;
    }

    static Map<String, Object> makeRow(String id, String code) {
        return Map.of(
            "wire_version",   "1",
            "id",             id,
            "origin_id",      id,
            "monotonic_seq",  1,
            "timestamp",      "2026-05-07T00:00:00.000Z",
            "code",           code,
            "action",         "test",
            "severity",       "info",
            "service_id",     "test-svc",
            "source_node_id", "node-1",
            "actor",          "tester",
            "actor_kind",     "user",
            "target",         "res-1",
            "category",       "test",
            "domain",         "test",
            "method",         "sdk",
            "request_id",     "req-001",
            "detail",         Map.of("key", "value")
        );
    }

    // ── Version ───────────────────────────────────────────────────────────────

    @Test
    void version_returnsNonEmpty() {
        requireLib();
        String v = FastenStore.version();
        assertNotNull(v);
        assertFalse(v.isBlank());
    }

    // ── SQLite ────────────────────────────────────────────────────────────────

    @Test
    void sqlite_openMemoryAndPing() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            assertDoesNotThrow(store::ping);
        }
    }

    @Test
    void sqlite_insertRow() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            assertDoesNotThrow(() -> store.insert(makeRow("evt-java-sqlite-001", "TEST")));
        }
    }

    @Test
    void sqlite_insertIdempotent() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            var row = makeRow("evt-java-idem-001", "TEST");
            store.insert(row);
            assertDoesNotThrow(() -> store.insert(row)); // INSERT OR IGNORE
        }
    }

    @Test
    void sqlite_insertJsonString() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            var json = assertDoesNotThrow(
                () -> new ObjectMapper().writeValueAsString(makeRow("evt-java-json-001", "TEST")));
            assertDoesNotThrow(() -> store.insertJson(json));
        }
    }

    @Test
    void sqlite_nullableColumns() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            // Map.of doesn't support null values; use a mutable map
            var row = new java.util.HashMap<>(makeRow("evt-java-null-001", "TEST"));
            row.put("tenant_id", "tenant-abc");
            row.put("shipped_at", "2026-05-07T01:00:00.000Z");
            assertDoesNotThrow(() -> store.insert(row));
        }
    }

    @Test
    void sqlite_piiInDetail() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            var row = new java.util.HashMap<>(makeRow("evt-java-pii-001", "TEST"));
            row.put("pii_in_detail", true);
            assertDoesNotThrow(() -> store.insert(row));
        }
    }

    @Test
    void sqlite_invalidTableNameThrows() {
        requireLib();
        assertThrows(FastenStoreException.class,
            () -> FastenStore.open("sqlite", ":memory:", "bad-name!"));
    }

    @Test
    void sqlite_unknownBackendThrows() {
        requireLib();
        assertThrows(FastenStoreException.class,
            () -> FastenStore.open("nope", ":memory:", "audit_log"));
    }

    @Test
    void sqlite_tryWithResources_closesCleanly() {
        requireLib();
        try (var store = FastenStore.open("sqlite", ":memory:", "audit_log")) {
            store.insert(makeRow("evt-java-twr-001", "TEST"));
        }
        // close() must be idempotent — no crash after try block exits
    }

    // ── PostgreSQL ────────────────────────────────────────────────────────────

    @Test
    void postgres_openAndPing() {
        requireLib();
        String dsn = pgDsn();
        try (var store = FastenStore.open("postgres", dsn, "fasten_java_sc_test")) {
            assertDoesNotThrow(store::ping);
        }
    }

    @Test
    void postgres_insertIdempotent() {
        requireLib();
        String dsn = pgDsn();
        try (var store = FastenStore.open("postgres", dsn, "fasten_java_sc_test")) {
            var row = makeRow("evt-java-pg-001", "TEST");
            store.insert(row);
            assertDoesNotThrow(() -> store.insert(row)); // ON CONFLICT DO NOTHING
        }
    }

    @Test
    void postgres_schemaQualifiedTable() {
        requireLib();
        String dsn = pgDsn();
        try (var store = FastenStore.open("postgres", dsn, "fasten_java_sc_schema.audit_rows")) {
            assertDoesNotThrow(() -> store.insert(makeRow("evt-java-schema-001", "TEST")));
        }
    }
}
