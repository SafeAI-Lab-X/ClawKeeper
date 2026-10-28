"""Execute learned regexes with an enforceable process and wall-time boundary."""

from __future__ import annotations

import atexit
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

MAX_PATTERNS = 128
MAX_PATTERN_CHARS = 2048
MAX_PATTERN_SET_CHARS = 32 * 1024
MAX_TEXT_CHARS = 65536
MAX_TEXTS = 256
MAX_INPUT_BYTES = 1024 * 1024
MAX_TOTAL_CHARS = 128 * 1024
REGEX_TIMEOUT_SECONDS = 0.5
_slots = threading.BoundedSemaphore(4)
_WORKER = Path(__file__).with_name("_regex_worker.py")
_pool_lock = threading.Lock()
_idle: list[_Worker] = []
_workers: set[_Worker] = set()


class RegexValidationError(ValueError):
    """The pattern is malformed or exceeds the supported pattern limits."""


class RegexResourceError(ValueError):
    """The pattern/input could not be evaluated within the resource boundary."""


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RegexResourceError("matching budget exhausted")
    return remaining


class _Worker:
    """An exclusively leased worker; failed exchanges are never reused."""

    def __init__(self):
        self.process = None
        # Track both endpoints before spawning. A fork must also close sockets
        # belonging to constructors that have not returned to _borrow_worker.
        with _pool_lock:
            self.connection, self._child_connection = socket.socketpair()
            _workers.add(self)
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-I", "-S", str(_WORKER), str(self._child_connection.fileno())],
                pass_fds=(self._child_connection.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if self.connection.fileno() < 0:
                raise RegexResourceError("matching worker closed during startup")
        except BaseException:
            self.close()
            raise
        finally:
            # Keep Python descriptor invalidation and the kernel close atomic
            # with respect to fork, just like the other connection closures.
            with _pool_lock:
                self._child_connection.close()

    def request(self, payload: str, deadline: float) -> bytes:
        self.connection.settimeout(_remaining(deadline))
        self.connection.sendall(payload.encode("ascii") + b"\n")
        response = bytearray()
        # At most 256 indexes (or nulls), plus the small protocol envelope.
        max_response = 4096
        while not response.endswith(b"\n"):
            self.connection.settimeout(_remaining(deadline))
            chunk = self.connection.recv(max_response - len(response))
            if not chunk:
                raise RegexResourceError("matching worker closed connection")
            response.extend(chunk)
            if len(response) >= max_response:
                raise RegexResourceError("invalid matching worker response")
        return bytes(response)

    def close(self):
        # Keep the connection visible to fork cleanup until it is closed.
        with _pool_lock:
            self.connection.close()
            self._child_connection.close()
            _workers.discard(self)
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        process.wait()


def _discard(worker: _Worker) -> None:
    worker.close()


def _borrow_worker() -> _Worker:
    with _pool_lock:
        worker = _idle.pop() if _idle else None
    if worker is not None and worker.process.poll() is not None:
        _discard(worker)
        worker = None
    if worker is None:
        worker = _Worker()
    return worker


def _close_workers() -> None:
    """Release children at host exit (also used by isolated test fixtures)."""
    with _pool_lock:
        workers = list(_workers)
        _idle.clear()
    for worker in workers:
        worker.close()


def _before_fork() -> None:
    _pool_lock.acquire()


def _after_fork_parent() -> None:
    _pool_lock.release()


def _after_fork() -> None:
    # A forked host must not send requests on its parent's live connections,
    # inherit a locked semaphore, or kill its parent's workers at exit.
    global _pool_lock, _slots  # noqa: PLW0603
    for worker in _workers:
        worker.connection.close()
        worker._child_connection.close()
    _workers.clear()
    _idle.clear()
    _pool_lock = threading.Lock()
    _slots = threading.BoundedSemaphore(4)


atexit.register(_close_workers)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_parent,
                        after_in_child=_after_fork)


def _decode_response(raw: bytes | str, pattern_count: int, group_count: int) -> list[int | None]:
    response = json.loads(raw)
    if response.get("error") == "invalid_pattern":
        raise RegexValidationError("invalid regex pattern")
    matches = response.get("matches")
    if (
        not isinstance(matches, list)
        or len(matches) != group_count
        or any(i is not None and (type(i) is not int or not 0 <= i < pattern_count)
               for i in matches)
    ):
        raise RegexResourceError("invalid matching worker response")
    return matches


def _execute(payload: str, deadline: float, pattern_count: int, group_count: int) -> list[int | None]:
    if sys.platform == "win32":
        # pass_fds is POSIX-only. Preserve the existing bounded one-shot path
        # on Windows rather than adding a second persistent transport.
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(_WORKER)], input=payload,
            text=True, capture_output=True, timeout=_remaining(deadline), check=False,
        )
        if result.returncode != 0:
            raise RegexResourceError("matching worker failed")
        return _decode_response(result.stdout, pattern_count, group_count)
    worker = _borrow_worker()
    try:
        matches = _decode_response(worker.request(payload, deadline), pattern_count, group_count)
    except RegexValidationError:
        # Syntax rejection is a complete, valid response; the worker is healthy.
        with _pool_lock:
            _idle.append(worker)
        raise
    except BaseException:
        _discard(worker)
        raise
    else:
        with _pool_lock:
            _idle.append(worker)
        return matches


def search_groups(patterns: list[str], groups: list[list[str]], *, invocation_start: bool = False,
                  modes: list[str] | None = None, pattern_groups: list[int] | None = None) -> list[int | None]:
    if not patterns or len(patterns) > MAX_PATTERNS:
        raise RegexValidationError("invalid pattern count")
    if any(not isinstance(p, str) or not p or len(p) > MAX_PATTERN_CHARS for p in patterns):
        raise RegexValidationError("invalid pattern size")
    if modes is not None and (len(modes) != len(patterns) or any(m not in {"search", "full", "invocation"} for m in modes)):
        raise RegexValidationError("invalid matching modes")
    if pattern_groups is not None and (len(pattern_groups) != len(patterns) or any(type(g) is not int or not 0 <= g < len(groups) for g in pattern_groups)):
        raise RegexValidationError("invalid pattern subjects")
    if len(groups) > MAX_TEXTS or sum(len(g) for g in groups) > MAX_TEXTS:
        raise RegexResourceError("too many matching inputs")
    if any(not isinstance(t, str) or len(t) > MAX_TEXT_CHARS for g in groups for t in g):
        raise RegexResourceError("invalid matching input size")
    if sum(map(len, patterns)) + sum(len(t) for g in groups for t in g) > MAX_TOTAL_CHARS:
        raise RegexResourceError("matching input exceeds total character limit")
    payload = json.dumps({"patterns": patterns, "groups": groups,
                          "invocation_start": invocation_start, "modes": modes, "pattern_groups": pattern_groups}, ensure_ascii=True)
    if len(payload) > MAX_INPUT_BYTES:
        raise RegexResourceError("matching input exceeds byte limit")
    deadline = time.monotonic() + REGEX_TIMEOUT_SECONDS
    if not _slots.acquire(timeout=REGEX_TIMEOUT_SECONDS):
        raise RegexResourceError("matching workers busy")
    try:
        _remaining(deadline)
        return _execute(payload, deadline, len(patterns), len(groups))
    except (RegexValidationError, RegexResourceError):
        raise
    except Exception as exc:
        raise RegexResourceError("regex execution unavailable") from exc
    finally:
        _slots.release()
