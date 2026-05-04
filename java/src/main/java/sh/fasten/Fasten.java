package sh.fasten;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * fasten — audit + correlation SDK for Java services.
 *
 * <p>Same shape as Python / Go / Node.js / Rust references: 6 audit anchors
 * (5 Ws + H) + correlation, opt-in shims per transport, pluggable store +
 * transport, mountable reader.
 *
 * <p><b>v1.0-beta status: PLACEHOLDER.</b> Every public method below
 * throws {@link UnsupportedOperationException} so adopters get a loud
 * fix-it message at the first call site instead of silently no-op'ing
 * through {@code register} / {@code init} / {@code metaOf} / {@code dump}
 * and only failing later at emit time. Use Python, Go, JS, Rust, or C++
 * SDKs in the meantime; their wire format is the same one defined in
 * {@code spec/row-schema.json}.
 *
 * <p>Type definitions ({@link Row}, {@link Meta}, {@link Filter},
 * {@link Config}, {@link AuditRepository}, {@link AuditOutboxRepository})
 * are wire-compatible with the spec — adopters can build adapters
 * against them today, knowing they will keep their shape when the
 * runtime lands.
 *
 * <p>See {@code ../README.md} for the full design.
 */
public final class Fasten {

    private static final String NOT_IMPLEMENTED =
        "fasten-java is a v1.0-beta placeholder; runtime is not implemented. "
        + "Use the Python, Go, JS, Rust, or C++ SDK in the meantime — their "
        + "wire format is compatible (one shared spec/row-schema.json across "
        + "all SDKs). Track progress at https://github.com/nerdapplabs/fasten/issues.";

// ── FASTEN GENERATED ─ source: spec/row-schema.json ─ run: python spec/codegen.py ──
    public enum Severity {
        DEBUG, INFO, WARN, ERROR, CRITICAL;

        @Override public String toString() {
            switch (this) {
                case DEBUG: return "debug";
                case INFO: return "info";
                case WARN: return "warn";
                case ERROR: return "error";
                case CRITICAL: return "critical";
                default: throw new IllegalStateException();
            }
        }
    }

    public enum RetentionClass {
        SHORT, MEDIUM, LONG;

        @Override public String toString() {
            switch (this) {
                case SHORT: return "short";
                case MEDIUM: return "medium";
                case LONG: return "long";
                default: throw new IllegalStateException();
            }
        }
    }

    // WHO anchor wire values.
    public static final String ACTOR_USER = "user";  // Human user (browser, mobile, CLI on behalf of a user)
    public static final String ACTOR_SERVICE = "service";  // Internal service or daemon
    public static final String ACTOR_SCHEDULE = "schedule";  // Cron job or task scheduler
    public static final String ACTOR_AGENT = "agent";  // AI agent

    // HOW anchor wire values.
    public static final String METHOD_HTTP = "http";  // HTTP/HTTPS request (REST, GraphQL, gRPC-web, webhook)
    public static final String METHOD_MQTT = "mqtt";  // MQTT message (IoT telemetry, device command)
    public static final String METHOD_CLI = "cli";  // CLI command typed by a human
    public static final String METHOD_SCHEDULER = "scheduler";  // Automated cron or task scheduler
    public static final String METHOD_UI = "ui";  // Web or desktop UI action, human-initiated
    public static final String METHOD_AGENT_TOOL = "agent_tool";  // AI agent tool call
    public static final String METHOD_SDK = "sdk";  // Direct SDK call, no transport shim active. Default.

    public static final String REDACT_REPLACEMENT = "***";
    public static final String[] REDACT_PATTERNS = {
        "api[_-]?key",
        "password",
        "passwd",
        "token",
        "secret",
        "authorization",
        "bearer",
        "m2m[_-]?key",
        "cert[_-]?private",
        "private[_-]?key",
        "access_key",
        "session_id",
        "cookie",
        "credential",
    };
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

    // ---------------------------------------------------------------------
    // Wire-compatible type definitions (no runtime impl yet).
    //
    // Field names match spec/row-schema.json so adapters built against
    // these records will not need to be retrofitted when the runtime
    // lands. Domain is a free string per spec (adopter-defined, e.g.
    // "user", "billing", "node") — not a closed enum.
    // ---------------------------------------------------------------------

    /** Canonical audit row — wire shape matches spec/row-schema.json. */
    public record Row(
            String id,
            String originId,
            long monotonicSeq,
            Instant timestamp,
            String code,
            String action,
            Severity severity,
            String serviceId,
            String sourceNodeId,
            Optional<String> tenantId,
            String actor,
            String actorKind,
            String target,
            String category,
            String domain,
            String method,
            String requestId,
            Map<String, Object> detail,
            boolean piiInDetail,
            Optional<Instant> shippedAt
    ) {}

    /** Per-code metadata. */
    public record Meta(
            String id,
            String domain,
            String category,
            String action,
            Severity severity,
            String description,
            String emitter,
            RetentionClass retentionClass,
            boolean highVolume,
            boolean piiInDetail,
            boolean declaredUnused
    ) {}

    /** Query filter for reader implementations. */
    public record Filter(
            Optional<String> requestId,
            Optional<String> code,
            Optional<String> domain,
            Optional<String> sourceNodeId,
            Optional<Instant> since,
            Optional<Instant> until,
            int limit
    ) {}

    /** Runtime config. Pass once at init. */
    public record Config(
            String serviceId,
            String nodeId,
            Optional<String> tenantId,
            Optional<AuditRepository> auditStore,
            Optional<AuditRepository> apiStore
    ) {}

    /** Long-term audit store — adopter implements per chosen backend. */
    public interface AuditRepository {
        void insert(Row row);
        List<Row> query(Filter filter);
        List<Row> listUnshipped(int limit);
        void markShipped(List<String> ids);
        int purge(Instant before, boolean respectUnshipped);
    }

    /** Drain-to-remote outbox — edge-sync, relay patterns. */
    public interface AuditOutboxRepository {
        void enqueue(Row row);
        List<Row> nextBatch(int n);
        void ack(List<String> ids);
        void requeue(List<String> ids);
        int depth();
    }

    // ---------------------------------------------------------------------
    // Public API — every entry point throws until the runtime lands.
    // ---------------------------------------------------------------------

    /** Initialise fasten. Call once at startup. */
    public static void init(Config cfg) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    /** Register a batch of codes under a domain. */
    public static void register(String domain, Map<String, Meta> codes) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    /** Look up registered metadata for a code. */
    public static Optional<Meta> metaOf(String code) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    /** {@code id,domain,severity} sorted — feeds the cross-language consistency gate. */
    public static String dump() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    // ---------------------------------------------------------------------
    // Correlation context.
    //
    // The request-id helpers throw too: a working request_id mint /
    // get / set surface without a working emit() implies "you can use
    // it" — exactly the wrong-thing-says-correct trap this placeholder
    // is meant to avoid. They land together when the runtime lands.
    // ---------------------------------------------------------------------

    public static String mintId() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    public static String currentRequestId() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    public static void setRequestId(String id) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    public static void clearRequestId() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    /** Run {@code r} with request_id set; restore previous on exit. */
    public static void withRequestId(String id, Runnable r) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    // ---------------------------------------------------------------------
    // Emit factory.
    //
    // No fluent {@code Emit} builder is exposed: returning a builder
    // that can never write() would still let adopters chain configure
    // calls before failing — exactly the half-implemented experience
    // this placeholder is meant to avoid.
    // ---------------------------------------------------------------------

    public static void emit(String code, String target) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED);
    }

    private Fasten() {}
}
