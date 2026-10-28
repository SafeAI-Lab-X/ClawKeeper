"""Private stdlib-only worker. Launched with -I -S; never imports the package."""

import json
import re
import signal
import socket
import sys


def evaluate(request):
    try:
        try:
            patterns = [re.compile(p, re.IGNORECASE) for p in request["patterns"]]
        except (re.error, OverflowError, RecursionError):
            return {"error": "invalid_pattern"}
        modes = request.get("modes") or ["invocation" if request.get("invocation_start", False) else "search"] * len(patterns)
        scopes = request.get("pattern_groups")

        def matches_text(rx, text, mode):
            if mode == "full":
                return rx.fullmatch(text) is not None
            if mode == "search":
                return rx.search(text) is not None
            match = rx.match(text)
            # A learned command rule must cover the complete executable token.
            # `ver` must not match a program named `version-control` either.
            return match is not None and match.end() >= len(text.split(" ", 1)[0])

        matches = [
            next((i for i, rx in enumerate(patterns) if (scopes is None or scopes[i] == group)
                  and any(matches_text(rx, t, modes[i]) for t in texts)), None)
            for group, texts in enumerate(request["groups"])
        ]
        return {"matches": matches}
    except Exception:
        # Never return patterns, source samples, or exception messages.
        return {"error": "unavailable"}


def main():
    if sys.platform != "win32":
        import resource  # noqa: PLC0415 -- unavailable on Windows

        memory = 128 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    if len(sys.argv) == 1:
        print(json.dumps(evaluate(json.load(sys.stdin))))
        return
    # The CPU timer is per request. RLIMIT_CPU is cumulative and would kill a
    # healthy reused worker once many small checks consumed one second in total.
    signal.signal(signal.SIGPROF, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGPROF})
    with socket.socket(fileno=int(sys.argv[1])) as connection, connection.makefile("rwb") as stream:
        for line in stream:
            signal.setitimer(signal.ITIMER_PROF, 1)
            try:
                response = evaluate(json.loads(line))
            finally:
                signal.setitimer(signal.ITIMER_PROF, 0)
            stream.write(json.dumps(response).encode("ascii") + b"\n")
            stream.flush()


if __name__ == "__main__":
    main()
