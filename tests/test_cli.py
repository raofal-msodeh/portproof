"""End-to-end CLI tests with real local TCP and TLS servers."""

from __future__ import annotations

import json
import socket
import ssl
import threading
from contextlib import closing

import pytest

from portproof.cli import EXIT_FAIL, EXIT_INPUT, EXIT_PASS, build_parser, run


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def _serve_tcp(port: int, ready: threading.Event) -> None:
    """Minimal TCP server that accepts one connection then closes."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    ready.set()
    try:
        conn, _ = server.accept()
        conn.close()
    except OSError:
        pass
    finally:
        server.close()


def _serve_tls_real(port: int, ready: threading.Event, tmpdir: str) -> None:
    """TLS server using an on-disk self-signed cert written to tmpdir."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = f"{tmpdir}/cert.pem"
    key_path = f"{tmpdir}/key.pem"
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    ready.set()
    try:
        conn, _ = server.accept()
        with context.wrap_socket(conn, server_side=True) as wrapped:
            wrapped.recv(1)
            wrapped.sendall(b"ok")
    except (OSError, ssl.SSLError):
        pass
    finally:
        server.close()


def test_tcp_open_exit_pass(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}"])
    assert rc == EXIT_PASS
    out = capsys.readouterr().out
    assert "OPEN" in out


def test_tcp_closed_exit_fail(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    rc = run([f"127.0.0.1:{port}", "--timeout", "1"])
    assert rc == EXIT_FAIL
    out = capsys.readouterr().out
    assert "CLOSED" in out


def test_json_output_valid(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}", "--format", "json"])
    assert rc == EXIT_PASS
    data = json.loads(capsys.readouterr().out)
    assert data["portproof_version"] == "1.0.0"
    assert data["passed"] is True
    assert data["targets"][0]["status"] == "open"


def test_mixed_targets_any_mode(capsys: pytest.CaptureFixture[str]) -> None:
    port_open = _free_port()
    port_closed = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port_open, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run(
        [
            f"127.0.0.1:{port_closed}",
            f"127.0.0.1:{port_open}",
            "--timeout",
            "1",
            "--fail-mode",
            "any",
        ],
    )
    assert rc == EXIT_PASS


def test_mixed_targets_all_mode_fails(capsys: pytest.CaptureFixture[str]) -> None:
    port_open = _free_port()
    port_closed = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port_open, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run(
        [
            f"127.0.0.1:{port_closed}",
            f"127.0.0.1:{port_open}",
            "--timeout",
            "1",
            "--fail-mode",
            "all",
        ],
    )
    assert rc == EXIT_FAIL


def test_report_file_written(tmp_path) -> None:  # type: ignore[no-untyped-def]
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    report_path = str(tmp_path / "proof.json")
    rc = run([f"127.0.0.1:{port}", "--report", report_path])
    assert rc == EXIT_PASS
    data = json.loads((tmp_path / "proof.json").read_text())
    assert data["targets"][0]["status"] == "open"


def test_report_unwritable_path_exit_fail(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}", "--report", "/nonexistent/dir/x.json"])
    assert rc == EXIT_FAIL
    assert "report" in capsys.readouterr().err


def test_unwritable_report_returns_fail_exit(capsys: pytest.CaptureFixture[str]) -> None:
    """Regression: report write failure must map to FAIL, never crash."""
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}", "--report", "/nonexistent/x.json"])
    assert rc == EXIT_FAIL


def test_invalid_target_exit_input(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["--", "-bad:0"])
    assert rc == EXIT_INPUT
    assert "input error" in capsys.readouterr().err


def test_invalid_port_exit_input(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["host:70000"])
    assert rc == EXIT_INPUT


def test_wait_requires_deadline_exit_input(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["127.0.0.1:1", "--wait"])
    assert rc == EXIT_INPUT


def test_quiet_mode_no_text(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}", "--quiet"])
    assert rc == EXIT_PASS
    assert capsys.readouterr().out == ""


def test_tls_open_with_real_server(tmp_path) -> None:  # type: ignore[no-untyped-def]
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tls_real, args=(port, ready, str(tmp_path)), daemon=True).start()
    ready.wait(timeout=5)
    rc = run(
        [
            f"127.0.0.1:{port}",
            "--protocol",
            "tls",
            "--timeout",
            "3",
            "--tls-ca",
            str(tmp_path / "cert.pem"),
        ],
    )
    assert rc == EXIT_PASS


def test_tls_handshake_failure_exit_fail(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    # Plain TCP server answering without TLS -> handshake failure.
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}", "--protocol", "tls", "--timeout", "3"])
    assert rc == EXIT_FAIL
    out = capsys.readouterr().out
    assert "ERROR" in out


def test_duplicate_targets_deduped(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    ready = threading.Event()
    threading.Thread(target=_serve_tcp, args=(port, ready), daemon=True).start()
    ready.wait(timeout=5)
    rc = run([f"127.0.0.1:{port}", f"127.0.0.1:{port}"])
    assert rc == EXIT_PASS
    out = capsys.readouterr().out
    assert out.count("OPEN") == 1


def test_timeout_reached_filtered(capsys: pytest.CaptureFixture[str]) -> None:
    """Regression: any target not OPEN must force exit 1 with a reason marker."""
    port = _free_port()
    # A closed port (connection refused) must still fail the run; FILTERED
    # (timeout-on-connect) is covered deterministically by the fake IO engine
    # tests, since a local TCP connect can never time out in user space.
    rc = run([f"127.0.0.1:{port}", "--timeout", "1"])
    assert rc == EXIT_FAIL
    out = capsys.readouterr().out
    assert "CLOSED" in out


def test_parser_version() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])
    assert exc_info.value.code == 0
