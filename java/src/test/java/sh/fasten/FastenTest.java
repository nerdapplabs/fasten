package sh.fasten;

import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Java SDK has no runtime yet, so every public entry point must throw
 * {@link UnsupportedOperationException} with a message pointing to a working
 * SDK. Replace these with behavioural tests once the runtime exists.
 */
class FastenTest {

    @Test
    void initThrows() {
        var cfg = new Fasten.Config(
            "svc", "node", Optional.empty(), Optional.empty(), Optional.empty());
        var e = assertThrows(UnsupportedOperationException.class,
            () -> Fasten.init(cfg));
        assertFixItMessage(e);
    }

    @Test
    void registerThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            () -> Fasten.register("user", Map.of()));
        assertFixItMessage(e);
    }

    @Test
    void metaOfThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            () -> Fasten.metaOf("USER_CREATED"));
        assertFixItMessage(e);
    }

    @Test
    void dumpThrows() {
        var e = assertThrows(UnsupportedOperationException.class, Fasten::dump);
        assertFixItMessage(e);
    }

    @Test
    void emitThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            () -> Fasten.emit("USER_CREATED", "u-1"));
        assertFixItMessage(e);
    }

    @Test
    void mintIdThrows() {
        var e = assertThrows(UnsupportedOperationException.class, Fasten::mintId);
        assertFixItMessage(e);
    }

    @Test
    void currentRequestIdThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            Fasten::currentRequestId);
        assertFixItMessage(e);
    }

    @Test
    void setRequestIdThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            () -> Fasten.setRequestId("rid"));
        assertFixItMessage(e);
    }

    @Test
    void clearRequestIdThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            Fasten::clearRequestId);
        assertFixItMessage(e);
    }

    @Test
    void withRequestIdThrows() {
        var e = assertThrows(UnsupportedOperationException.class,
            () -> Fasten.withRequestId("rid", () -> { /* never reached */ }));
        assertFixItMessage(e);
    }

    @Test
    void rowRecordHasSpecCompatibleFields() {
        // Constructing a Row makes the compiler check the field list.
        Fasten.Row r = new Fasten.Row(
            "evt-00000000000000000000",
            "evt-00000000000000000000",
            1L,
            java.time.Instant.EPOCH,
            "USER_CREATED",
            "create",
            Fasten.Severity.INFO,
            "svc", "node",
            Optional.empty(),       // tenantId
            "system", "service",
            "u-1", "account", "user",
            Fasten.METHOD_SDK,
            "abc123def456",
            Map.of(),
            false,                  // piiInDetail
            Optional.empty()        // shippedAt
        );
        assertTrue(r.originId().equals(r.id()));
        assertTrue(r.tenantId().isEmpty());
        assertTrue(!r.piiInDetail());
    }

    private static void assertFixItMessage(UnsupportedOperationException e) {
        String msg = e.getMessage();
        assertTrue(msg != null && msg.contains("placeholder"),
            "message must include 'placeholder'; got: " + msg);
        assertTrue(msg.contains("Python") || msg.contains("Go")
                || msg.contains("Rust"),
            "message must point adopters to a working SDK; got: " + msg);
    }
}
