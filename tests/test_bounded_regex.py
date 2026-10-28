"""Worker reuse must preserve deadlines, isolation, and resource boundaries."""

# These scenarios intentionally assert concrete worker/resource limits.
# ruff: noqa: PLR2004

import json
import multiprocessing
import os
import select
import signal
import subprocess
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from clawkeeper_core import bounded_regex as regex

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="persistent workers are POSIX-only")


@pytest.fixture
def children(monkeypatch):
    started = []
    real_popen = subprocess.Popen

    def track(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        started.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", track)
    return started


def test_worker_reused_across_matches_and_invalid_pattern(children):
    for i in range(20):
        text = f"CK_REUSE_{i}"
        assert regex.search_groups([text, "other"], [[text], ["other"], ["no hit"]]) == [0, 1, None]
    with pytest.raises(regex.RegexValidationError):
        regex.search_groups(["["], [["sample"]])
    assert regex.search_groups(["CK_NEW"], [["CK_REUSE_19"], ["CK_NEW"]]) == [None, 0]
    assert len(children) == 1 and children[0].poll() is None
    regex._close_workers()
    assert children[0].poll() is not None


def test_invocation_mode_requires_start_and_complete_program_token(children):
    groups = [["ver"], ["echo ver"], ["version-control"], ["ver --help"]]
    assert regex.search_groups(["ver"], groups, invocation_start=True) == [0, None, None, 0]
    # A warm worker must not retain a previous request's matching mode.
    assert regex.search_groups(["ver"], groups) == [0, 0, 0, 0]
    assert len(children) == 1


def test_timeout_kills_warm_worker_and_next_request_has_no_stale_reply(children):
    assert regex.search_groups([r"CK_REUSE_(a+)+$"], [["CK_REUSE_aaa"]]) == [0]
    first = children[0]
    started = time.monotonic()
    with pytest.raises(regex.RegexResourceError):
        regex.search_groups([r"CK_REUSE_(a+)+$"], [["CK_REUSE_" + "a" * 32 + "!"]])
    assert time.monotonic() - started < 2
    assert first.poll() is not None
    assert regex.search_groups(["CK_NEW"], [["CK_NEW"], ["CK_REUSE_aaa"]]) == [0, None]
    assert len(children) == 2


def test_dead_idle_worker_replaced(children):
    assert regex.search_groups(["CK_REUSE"], [["CK_REUSE"]]) == [0]
    children[0].kill()
    children[0].wait()
    assert regex.search_groups(["CK_NEW"], [["CK_NEW"]]) == [0]
    assert len(children) == 2


def test_large_unicode_request_is_framed_without_truncation(children):
    # ASCII JSON escaping makes this larger than a socket buffer. Both writes
    # and reads must handle partial transfers while preserving the next frame.
    groups = [["汉" * 60000 + "CK_LARGE"], ["汉" * 60000]]
    assert regex.search_groups(["CK_LARGE"], groups) == [0, None]
    assert regex.search_groups(["CK_NEXT"], [["CK_NEXT"]]) == [0]
    assert len(children) == 1


def test_deadline_also_bounds_blocked_request_writes(tmp_path, monkeypatch, children):
    stalled = tmp_path / "stalled_worker.py"
    stalled.write_text("import time\ntime.sleep(10)\n")
    started = time.monotonic()
    with monkeypatch.context() as patch:
        patch.setattr(regex, "_WORKER", stalled)
        with pytest.raises(regex.RegexResourceError):
            regex.search_groups(["CK_LARGE"], [["汉" * 60000], ["汉" * 60000]])
    assert time.monotonic() - started < 2
    assert children[0].poll() is not None
    assert regex.search_groups(["CK_NEXT"], [["CK_NEXT"]]) == [0]


def test_concurrent_requests_have_exclusive_workers_and_reuse_at_most_four(children, monkeypatch):
    barrier = threading.Barrier(4, timeout=2)
    request = regex._Worker.request

    def overlap(self, payload, deadline):
        barrier.wait()
        return request(self, payload, deadline)

    def check(i):
        token = f"CK_CONCURRENT_{i}"
        return regex.search_groups([token], [[token], ["different"]])

    with ThreadPoolExecutor(max_workers=4) as executor:
        with monkeypatch.context() as patch:
            patch.setattr(regex._Worker, "request", overlap)
            assert list(executor.map(check, range(4))) == [[0, None]] * 4
        assert list(executor.map(check, range(4, 24))) == [[0, None]] * 20
    assert len(children) == 4
    assert all(child.poll() is None for child in children)


@pytest.mark.parametrize("reply", [b"", b'{"matches":', b'{"matches":[999]}\n', b'{}\n{}\n', b'x' * 5000])
def test_failed_exchange_discards_worker_and_recovers(tmp_path, monkeypatch, children, reply):
    bad = tmp_path / "bad_worker.py"
    bad.write_text(
        "import socket, sys\n"
        "with socket.socket(fileno=int(sys.argv[1])) as sock:\n"
        "    sock.recv(65536)\n"
        f"    sock.sendall({reply!r})\n"
    )
    with monkeypatch.context() as patch:
        patch.setattr(regex, "_WORKER", bad)
        with pytest.raises(regex.RegexResourceError):
            regex.search_groups(["CK_REUSE"], [["CK_REUSE"]])
        assert children[0].poll() is not None
    assert regex.search_groups(["CK_NEW"], [["CK_NEW"]]) == [0]
    assert len(children) == 2


def _forked_check(connection):
    try:
        result = regex.search_groups(["CK_CHILD"], [["CK_CHILD"]])
        connection.send((result, regex._idle[0].process.pid))
    finally:
        regex._close_workers()
        connection.close()


def test_forked_host_gets_own_workers_and_keeps_parent_worker_alive(children):
    assert regex.search_groups(["CK_PARENT"], [["CK_PARENT"]]) == [0]
    parent_worker = children[0]
    context = multiprocessing.get_context("fork")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_forked_check, args=(writer,))
    process.start()
    writer.close()
    try:
        assert reader.poll(3)
        result, child_worker_pid = reader.recv()
        assert result == [0] and child_worker_pid != parent_worker.pid
        process.join(3)
        assert process.exitcode == 0
        assert parent_worker.poll() is None
        assert regex.search_groups(["CK_PARENT"], [["CK_PARENT"]]) == [0]
    finally:
        reader.close()
        if process.is_alive():
            process.kill()
        process.join()


@pytest.mark.parametrize("phase", ["socketpair", "spawn", "registration", "closing"])
def test_fork_during_creation_closes_both_inherited_endpoints(monkeypatch, children, phase):  # noqa: PLR0915 -- keep scoped process/FD cleanup with the scenario
    ready, release = threading.Event(), threading.Event()
    endpoints, results, errors, peers = [], [], [], []
    real_pair, real_spawn, real_init = regex.socket.socketpair, subprocess.Popen, regex._Worker.__init__
    real_close = regex.socket.socket._real_close
    closing_paused = False

    def pause(point):
        if phase == point:
            ready.set()
            if not release.wait(3):
                raise TimeoutError("test did not release worker creation")

    def pair():
        sockets = real_pair()
        endpoints.extend(sock.fileno() for sock in sockets)
        peers.append(sockets[1])
        pause("socketpair")
        return sockets

    def close(sock):
        nonlocal closing_paused
        if phase == "closing" and peers and sock is peers[0] and not closing_paused:
            closing_paused = True
            # Model the real close sequence: invalidate the Python descriptor,
            # then pause before closing the still-open kernel descriptor.
            fd = sock.detach()
            try:
                pause("closing")
            finally:
                os.close(fd)
        else:
            real_close(sock)

    def spawn(*args, **kwargs):
        pause("spawn")
        return real_spawn(*args, **kwargs)

    def initialize(self):
        real_init(self)
        pause("registration")

    def create():
        try:
            results.append(regex.search_groups(["CK_PARENT"], [["CK_PARENT"]]))
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(regex.socket, "socketpair", pair)
    monkeypatch.setattr(regex.socket.socket, "_real_close", close)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(regex._Worker, "__init__", initialize)
    report_r, report_w = os.pipe()
    stop_r, stop_w = os.pipe()
    thread = threading.Thread(target=create)
    thread.start()
    child = None
    timer = None
    try:
        assert ready.wait(3)
        if phase in {"socketpair", "closing"}:
            # Fork must wait for socket creation/registration or kernel close
            # to complete; another thread releases that critical section.
            timer = threading.Timer(0.05, release.set)
            timer.start()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # deliberate threaded fork
            child = os.fork()
        if child == 0:
            try:
                os.close(report_r)
                os.close(stop_w)
                inherited = []
                for fd in endpoints:
                    try:
                        os.fstat(fd)
                    except OSError:
                        continue
                    inherited.append(fd)
                os.write(report_w, json.dumps(inherited).encode())
                os.read(stop_r, 1)  # keep this host alive while the owner disconnects
            finally:
                os._exit(0)
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors and results == [[0]]
        assert select.select([report_r], [], [], 3)[0]
        assert json.loads(os.read(report_r, 4096)) == []
        # Closing the owner's endpoint models abrupt host exit. No inherited
        # endpoint in the still-live fork may prevent the worker seeing EOF.
        regex._idle[0].connection.close()
        assert children[0].wait(timeout=2) == 0
    finally:
        release.set()
        if timer is not None:
            timer.join()
        thread.join(3)
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        for fd in (report_r, report_w, stop_r, stop_w):
            os.close(fd)


def test_cpu_timer_terminates_worker_even_when_host_blocks_sigprof():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGPROF})
    try:
        worker = regex._Worker()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    try:
        payload = json.dumps({"patterns": ["(a+)+$"], "groups": [["a" * 40 + "!"]]})
        # Deliberately let the child's CPU timer act before the parent's wall
        # timeout, as it must when the host has exited and cannot kill it.
        with pytest.raises(regex.RegexResourceError, match="closed connection"):
            worker.request(payload, time.monotonic() + 4)
        assert worker.process.wait(timeout=1) == -signal.SIGPROF
    finally:
        worker.close()


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="uses Linux process CPU accounting")
def test_cpu_budget_resets_for_each_request_in_long_lived_worker(children):
    patterns = [rf"CK_CPU_{i:03d}" for i in range(32)]
    groups = [["ordinary_arguments " * 1700]]
    ticks = os.sysconf("SC_CLK_TCK")
    assert regex.search_groups(patterns, groups) == [None]
    worker = children[0]
    for _ in range(500):
        fields = Path(f"/proc/{worker.pid}/stat").read_text().split()
        cpu_seconds = (int(fields[13]) + int(fields[14])) / ticks
        if cpu_seconds > 1.1:
            break
        assert regex.search_groups(patterns, groups) == [None]
    else:
        pytest.fail("did not exercise more than one cumulative CPU second")
    assert len(children) == 1 and worker.poll() is None


def test_one_shot_worker_remains_available_for_windows():
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(regex._WORKER)],
        input=json.dumps({"patterns": ["CK_ONESHOT"], "groups": [["CK_ONESHOT"], ["other"]]}),
        text=True, capture_output=True, timeout=2, check=True,
    )
    assert json.loads(result.stdout) == {"matches": [0, None]}
