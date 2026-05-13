package sh.fasten.store;

/**
 * Thrown when the native store backend returns an error.
 * Wraps the error string produced by libfasten_store_core so callers
 * never need to deal with raw JNA pointers or native memory.
 */
public class FastenStoreException extends RuntimeException {

    public FastenStoreException(String message) {
        super(message);
    }

    public FastenStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
