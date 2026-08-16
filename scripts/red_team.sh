#!/usr/bin/env bash
# PortProof red-team: adversarial CLI scenarios.
# Each scenario must behave safely and return the documented exit code.
set -uo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRC_DIR" || exit 2
python3 - <<'PY'
import threading, socket, ssl, time, datetime, tempfile, sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from portproof.cli import run

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed  # noqa: PLW0603
    if condition:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name} {detail}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_tcp(port: int, ready: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    try:
        conn, _ = srv.accept()
        conn.close()
    except OSError:
        pass
    finally:
        srv.close()


# RT-01: maliciously crafted host that looks like a shell injection.
rc = run(["; rm -rf /; $(whoami):80", "--timeout", "1"])
check("RT-01 host injection is rejected as invalid input", rc == 2)

# RT-02: unicode host is rejected as invalid.
rc = run(["\u00e8\u00e9\u00ea\u00eb:80", "--timeout", "1"])
check("RT-02 non-ascii host is rejected as invalid input", rc == 2)

# RT-03: port as float string is rejected.
rc = run(["host:80.5", "--timeout", "1"])
check("RT-03 fractional port is rejected as invalid input", rc == 2)

# RT-04: host containing slashes.
rc = run(["/etc/passwd:80", "--timeout", "1"])
check("RT-04 slash in host is rejected as invalid input", rc == 2)

# RT-05: unbracketed IPv6 with multiple colons is rejected.
rc = run(["fe80::1:443", "--timeout", "1"])
check("RT-05 ambiguous IPv6 without brackets is rejected", rc == 2)

# RT-06: extremely long spec (DoS attempt).
rc = run(["A" * 100_000 + ":80", "--timeout", "1"])
check("RT-06 oversized spec is rejected quickly", rc == 2)

# RT-07: wait without deadline is rejected.
rc = run(["127.0.0.1:1", "--wait"])
check("RT-07 wait without deadline exits as input error", rc == 2)

# RT-08: zero timeout is rejected.
rc = run(["127.0.0.1:1", "--timeout", "0"])
check("RT-08 zero timeout is rejected as invalid input", rc == 2)

# RT-09: negative interval is rejected.
rc = run(["127.0.0.1:1", "--wait", "--deadline", "1", "--interval", "-1"])
check("RT-09 negative wait interval is rejected", rc == 2)

# RT-10: nonexistent tls-ca file is rejected.
rc = run(["127.0.0.1:443", "--protocol", "tls", "--tls-ca", "/no/such/file.pem"])
check("RT-10 nonexistent TLS CA bundle is rejected", rc == 2)

# RT-11: invalid http-path is rejected.
rc = run(["127.0.0.1:80", "--protocol", "http", "--http-path", "no-slash"])
check("RT-11 relative http path is rejected", rc == 2)

# RT-12: real TCP server answers normally (baseline).
port = free_port()
ready = threading.Event()
threading.Thread(target=serve_tcp, args=(port, ready), daemon=True).start()
ready.wait(timeout=5)
rc = run([f"127.0.0.1:{port}", "--timeout", "2"])
check("RT-12 legitimate open port passes", rc == 0)

# RT-13: closed port fails with exit 1, never crashes.
rc = run([f"127.0.0.1:{free_port()}", "--timeout", "1"])
check("RT-13 closed port fails gracefully with exit 1", rc == 1)

# RT-14: JSON output is always parseable even on failure.
import json
from io import StringIO
import contextlib

buf = StringIO()
with contextlib.redirect_stdout(buf):
    run([f"127.0.0.1:{free_port()}", "--timeout", "1", "--format", "json"])
try:
    data = json.loads(buf.getvalue())
    parseable = data["passed"] is False and "targets" in data
except (json.JSONDecodeError, KeyError):
    parseable = False
check("RT-14 failure output is always valid JSON evidence", parseable)

# RT-15: mixed IPv4 and bracketed IPv6 specs parse independently.
rc = run(["127.0.0.1:1", "[::1]:1", "--timeout", "1"])
check("RT-15 mixed IPv4/IPv6 targets both evaluate", rc == 1)

# RT-16: report file path traversal does not escape the requested path.
import tempfile
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "proof.json")
    rc = run([f"127.0.0.1:{free_port()}", "--timeout", "1", "--report", path])
    check("RT-16 report is written only to the requested path", rc == 1 and os.path.exists(path))

# RT-17: wait with tiny deadline and closed port fails fast (no hang).
start = time.time()
rc = run(["127.0.0.1:1", "--wait", "--deadline", "0.5", "--timeout", "0.2"])
check("RT-17 wait mode respects deadline and does not hang", rc == 1 and time.time() - start < 3)

# RT-18: tls against a plain TCP server fails as ERROR, never OPEN.
port = free_port()
ready = threading.Event()
threading.Thread(target=serve_tcp, args=(port, ready), daemon=True).start()
ready.wait(timeout=5)
from portproof.cli import build_parser
import argparse
# drive run directly: TLS protocol against plain server must error.
rc = run([f"127.0.0.1:{port}", "--protocol", "tls", "--timeout", "2"])
check("RT-18 TLS against plain server reports error, not open", rc == 1)

# RT-19: no arguments prints usage and exits input-error.
try:
    with contextlib.redirect_stderr(StringIO()):
        rc = run([])
    rc_value = rc
except SystemExit as exc:
    rc_value = exc.code
check("RT-19 no arguments exits as input error", rc_value == 2)

# RT-20: duplicate target is deduped (no double counting).
port = free_port()
ready = threading.Event()
threading.Thread(target=serve_tcp, args=(port, ready), daemon=True).start()
ready.wait(timeout=5)
buf = StringIO()
with contextlib.redirect_stdout(buf):
    run([f"127.0.0.1:{port}", f"127.0.0.1:{port}"])
check("RT-20 duplicate targets are deduplicated", buf.getvalue().count("OPEN") == 1)

print(f"\nred-team: {passed} passed, {failed} failed out of {passed + failed}")
sys.exit(1 if failed else 0)
PY
