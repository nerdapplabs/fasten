package sh.fasten.store;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * JNA interface declaration — maps directly to libfasten_store_core symbols.
 *
 * <p>Internal; use {@link FastenStore} instead of this interface directly.
 *
 * <p>Library loading order:
 * <ol>
 *   <li>{@code FASTEN_STORE_CORE_LIB} env var — full path to the .so/.dylib/.dll</li>
 *   <li>{@code jna.library.path} / {@code LD_LIBRARY_PATH} / system paths</li>
 * </ol>
 */
interface FastenStoreLib extends Library {

    FastenStoreLib INSTANCE = load();

    // ── C ABI ─────────────────────────────────────────────────────────────────

    Pointer fasten_store_open(
        String backend,
        String connstr,
        String table,
        PointerByReference outErr
    );

    int fasten_store_insert(Pointer store, String rowJson, PointerByReference outErr);

    int fasten_store_ping(Pointer store, PointerByReference outErr);

    void fasten_store_close(Pointer store);

    void fasten_store_free_str(Pointer s);

    String fasten_store_version();

    // ── Loading ───────────────────────────────────────────────────────────────

    private static FastenStoreLib load() {
        String explicit = System.getenv("FASTEN_STORE_CORE_LIB");
        if (explicit != null && !explicit.isBlank()) {
            Path p = Path.of(explicit);
            if (!Files.exists(p)) {
                throw new UnsatisfiedLinkError(
                    "FASTEN_STORE_CORE_LIB points to a file that does not exist: " + explicit);
            }
            // JNA accepts absolute paths as library names when the path is absolute.
            return Native.load(explicit, FastenStoreLib.class);
        }
        // Fall back to JNA's standard search (jna.library.path, LD_LIBRARY_PATH, etc.)
        return Native.load("fasten_store_core", FastenStoreLib.class);
    }
}
