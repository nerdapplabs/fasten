"""ARCH #4 — catalog registry has a read-side race.

Prior state: ``meta_of()`` did a bare ``dict.get`` with no lock;
``register()`` mutated the dict with no lock; ``codes_yaml.reload()``
held a lock that neither reader used, and its ``clear()`` + ``update()``
sequence briefly left ``_registry`` empty. An unlucky concurrent
``emit()`` observed the empty dict and raised "unknown audit code" —
the exact "misconfig ships as green" class the P1-45 auth fix closed.

The fix funnels every read AND write through a single reentrant lock
exported by ``fasten.codes``. This test pins the invariant: while a
tight reload-swap loop runs in one thread, thousands of ``meta_of()``
lookups in another must NEVER return None for a known code.
"""
from __future__ import annotations

import threading
import time

from fasten import codes as fasten_codes
from fasten.codes import Meta, RetentionClass, Severity, meta_of, register


def _reset_registry():
    from fasten import core_ffi
    core_ffi.registry_clear()
    with fasten_codes._lock:
        fasten_codes._registry.clear()


def _register_batch():
    register("user", {
        "USER_CREATED": Meta(
            id="USER_CREATED", domain="user", category="account",
            action="create", severity=Severity.INFO,
            description="test", emitter="test",
            retention_class=RetentionClass.LONG,
        ),
        "USER_DELETED": Meta(
            id="USER_DELETED", domain="user", category="account",
            action="delete", severity=Severity.WARN,
            description="test", emitter="test",
            retention_class=RetentionClass.LONG,
        ),
    })


def test_meta_of_never_misses_known_code_under_concurrent_reload_swap():
    """The reproducer: a writer thread simulates codes_yaml.reload()'s
    clear-and-rebuild swap on _registry; a reader hammers meta_of().

    Pre-fix, meta_of used a bare dict.get with no lock, so the reader
    intermittently observed the empty dict mid-swap and returned None
    for a known code (which emit() surfaces as "unknown audit code").

    Post-fix, both paths funnel through the shared reentrant _lock in
    fasten.codes and the reader never sees the empty state, no matter
    how tight the swap cadence.
    """
    _reset_registry()
    _register_batch()
    snapshot = dict(fasten_codes._registry)

    stop = threading.Event()
    misses = 0
    lookups = 0
    writer_error: list[BaseException] = []

    def writer():
        # Emulate reload()'s critical section shape: clear + update inside
        # the same lock the reader now respects. This is the exact swap
        # sequence at codes_yaml.py:273-274.
        try:
            while not stop.is_set():
                with fasten_codes._lock:
                    fasten_codes._registry.clear()
                    fasten_codes._registry.update(snapshot)
        except BaseException as e:  # pragma: no cover — surface via join
            writer_error.append(e)

    def reader():
        nonlocal misses, lookups
        while not stop.is_set():
            m = meta_of("USER_CREATED")
            lookups += 1
            if m is None:
                misses += 1

    tw = threading.Thread(target=writer)
    tr = threading.Thread(target=reader)
    tw.start()
    tr.start()
    time.sleep(0.4)
    stop.set()
    tw.join()
    tr.join()

    assert not writer_error, f"writer died: {writer_error[0]!r}"
    assert lookups > 1000, f"reader didn't run enough iterations: {lookups}"
    assert misses == 0, (
        f"meta_of returned None for a known code {misses}/{lookups} times — "
        "the registry lock is torn and emit() would raise 'unknown code'"
    )


def test_meta_of_lock_is_reentrant():
    """Register calls meta_of via unrelated paths in some tests / callbacks
    (e.g. a code-registration hook that verifies the just-registered code
    is now visible). RLock lets the caller re-enter without deadlock.
    """
    _reset_registry()
    _register_batch()
    with fasten_codes._lock:
        # Would deadlock on a plain threading.Lock.
        assert meta_of("USER_CREATED") is not None
