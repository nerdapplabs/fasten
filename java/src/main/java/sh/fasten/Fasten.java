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
 * <p>See ../README.md for the full design.
 */
public final class Fasten {

    // ---------------------------------------------------------------------
    // 6 audit anchors as typed row
    // ---------------------------------------------------------------------

    public enum Anchor {
        WHO, WHAT, WHEN, WHERE, WHOM, HOW, CORRELATION
    }

    public enum Domain {
        NODE, SYNC, FLEET, AGENT
    }

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
        "auth",
    };
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

    /** Canonical audit row. Lossless conversion to CloudEvent + OTel LogRecord. */
    public record Row(
            String id,
            String edgeRowId,
            long monotonicSeq,
            Instant timestamp,
            String code,
            String action,
            Severity severity,
            String serviceId,
            String sourceNodeId,
            Optional<String> siteId,
            String actor,
            String actorKind,
            String target,
            String category,
            Domain domain,
            String method,
            String requestId,
            Map<String, Object> detail,
            Optional<Instant> shippedAt
    ) {}

    /** Per-code metadata. */
    public record Meta(
            String id,
            Domain domain,
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

    // ---------------------------------------------------------------------
    // Code catalog
    // ---------------------------------------------------------------------

    /** Register a batch of codes under a domain. Called once at startup. */
    public static void register(Domain domain, Map<String, Meta> codes) {
        // TODO: thread-safe registry with duplicate-detection
    }

    public static Optional<Meta> metaOf(String code) {
        // TODO
        return Optional.empty();
    }

    /** `id,domain,severity` sorted — feeds cross-language consistency gate. */
    public static String dump() {
        // TODO
        return "";
    }

    // ---------------------------------------------------------------------
    // Correlation context — ThreadLocal/InheritableThreadLocal + ScopedValue for JDK 21+
    // ---------------------------------------------------------------------

    private static final ThreadLocal<String> REQUEST_ID = new InheritableThreadLocal<>();

    public static String mintId() {
        return java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    public static String currentRequestId() {
        String id = REQUEST_ID.get();
        return id == null ? "" : id;
    }

    public static void setRequestId(String id) {
        REQUEST_ID.set(id);
    }

    public static void clearRequestId() {
        REQUEST_ID.remove();
    }

    /** Run `r` with request_id set; restore previous value on exit. */
    public static void withRequestId(String id, Runnable r) {
        String prev = REQUEST_ID.get();
        REQUEST_ID.set(id);
        try {
            r.run();
        } finally {
            if (prev == null) REQUEST_ID.remove();
            else REQUEST_ID.set(prev);
        }
    }

    // ---------------------------------------------------------------------
    // Init + Emit
    // ---------------------------------------------------------------------

    /** Config. Most values come from env vars (FASTEN_*). */
    public record Config(
            String serviceId,
            String nodeId,
            Optional<String> siteId,
            Optional<AuditRepository> auditStore,
            Optional<AuditRepository> apiStore
    ) {}

    /** Initialise fasten. Call once at startup. */
    public static void init(Config cfg) {
        // TODO: validate, wire transport, construct stores from FASTEN_*_DSN
    }

    /** Fluent emit builder. */
    public static final class Emit {
        private final String code;
        private String target = "";
        private String actor = "system";
        private String actorKind = "service";
        private String method = "sdk";
        private Map<String, Object> detail = Map.of();
        private Severity severityOverride;

        public Emit(String code, String target) {
            this.code = code;
            this.target = target;
        }

        public Emit actor(String a, String kind) { this.actor = a; this.actorKind = kind; return this; }
        public Emit method(String m) { this.method = m; return this; }
        public Emit detail(Map<String, Object> d) { this.detail = d; return this; }
        public Emit severity(Severity s) { this.severityOverride = s; return this; }

        public Row write() {
            // TODO: lookup Meta, populate anchors from ctx/config, redact, insert
            throw new UnsupportedOperationException("TODO");
        }
    }

    public static Emit emit(String code, String target) {
        return new Emit(code, target);
    }

    // ---------------------------------------------------------------------
    // Store interfaces
    // ---------------------------------------------------------------------

    /** Long-term audit store — EM, adopter default. */
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

    public record Filter(
            Optional<String> requestId,
            Optional<String> code,
            Optional<Domain> domain,
            Optional<String> sourceNodeId,
            Optional<Instant> since,
            Optional<Instant> until,
            int limit
    ) {}

    private Fasten() {}
}
