"""Tests for the PortProof verification engine using deterministic fake IO."""

from __future__ import annotations

import socket

import pytest

from portproof.engine import FakeClockSockets, _classify, verify_batch, verify_target
from portproof.models import (
    PortStatus,
    ProbeConfig,
    Protocol,
    Target,
    ValidationError,
)

OK_TARGET = Target("10.0.0.1", 80)
CLOSED_TARGET = Target("10.0.0.2", 81)


def _config(
    timeout: float = 5.0,
    total_deadline: float = 0.0,
    wait: bool = False,
    wait_interval: float = 1.0,
    wait_attempts: int = 0,
    protocol: Protocol = Protocol.TCP,
    http_path: str = "/",
    tls_ca: str = "",
) -> ProbeConfig:
    return ProbeConfig(
        timeout=timeout,
        total_deadline=total_deadline,
        wait=wait,
        wait_interval=wait_interval,
        wait_attempts=wait_attempts,
        protocol=protocol,
        http_path=http_path,
        tls_ca=tls_ca,
    )


def test_tcp_open_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.01, _connect_ok=True)
    result = verify_target(OK_TARGET, _config(), io)
    assert result.status is PortStatus.OPEN
    assert result.reason == "tcp connection established"
    assert result.elapsed_ms > 0


def test_tcp_refused_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.005, _connect_ok=False)
    result = verify_target(CLOSED_TARGET, _config(), io)
    assert result.status is PortStatus.CLOSED
    assert "refused" in result.reason


def test_tcp_timeout_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.002, _connect_side_effect=TimeoutError("simulated"))
    result = verify_target(CLOSED_TARGET, _config(), io)
    assert result.status is PortStatus.FILTERED
    assert "no response within timeout" in result.reason


def test_tcp_os_error_classified() -> None:
    status, reason = _classify(socket.gaierror("dns"), OK_TARGET)
    assert status is PortStatus.ERROR
    assert "dns" in reason


def test_tls_open_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.02, _tls_ok=True)
    result = verify_target(OK_TARGET, _config(protocol=Protocol.TLS), io)
    assert result.status is PortStatus.OPEN
    assert result.reason == "tls handshake completed"
    assert result.protocol is Protocol.TLS


def test_tls_failure_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.01, _tls_ok=False)
    result = verify_target(OK_TARGET, _config(protocol=Protocol.TLS), io)
    assert result.status is PortStatus.ERROR
    assert "tls" in result.reason


def test_http_open_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.003, _connect_ok=True, _http_status=200)
    result = verify_target(OK_TARGET, _config(protocol=Protocol.HTTP), io)
    assert result.status is PortStatus.OPEN
    assert result.http_status == 200


def test_http_server_error_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.003, _connect_ok=True, _http_status=503)
    result = verify_target(OK_TARGET, _config(protocol=Protocol.HTTP), io)
    assert result.status is PortStatus.ERROR
    assert result.http_status == 503


def test_http_connection_refused_with_fake_io() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.001, _connect_ok=False)
    result = verify_target(OK_TARGET, _config(protocol=Protocol.HTTP), io)
    assert result.status is PortStatus.CLOSED


def test_batch_sequential_order() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.01)
    targets = [Target("h", 1), Target("h", 2), Target("h", 3)]
    results = verify_batch(targets, _config(), io)
    assert [result.target.port for result in results] == [1, 2, 3]
    assert all(result.status is PortStatus.OPEN for result in results)


def test_batch_deadline_stops_mid_batch() -> None:
    # Deadline is 0.01s from start; each probe advances fake time by 0.005.
    # Target 1 consumes 0.005, target 2 consumes another 0.005 -> 0.01 >=
    # deadline, so the second probe must not run.
    io = FakeClockSockets(_time=0.0, _advance=0.005)
    results = verify_batch(
        [Target("h", 1), Target("h", 2)],
        _config(total_deadline=0.01),
        io,
    )
    assert len(results) == 1
    assert results[0].target.port == 1


def test_wait_mode_stops_on_open() -> None:
    calls = {"n": 0}

    class FlakyIo(FakeClockSockets):
        def connect_tcp(self, target: Target, timeout: float) -> socket.socket:
            calls["n"] += 1
            if calls["n"] >= 3:
                return super().connect_tcp(target, timeout)
            raise ConnectionRefusedError("not ready yet")

    io = FlakyIo(_time=0.0, _advance=0.01)
    results = verify_batch(
        [OK_TARGET],
        _config(wait=True, total_deadline=30.0, wait_interval=0.1),
        io,
    )
    assert calls["n"] == 3
    assert results[-1].status is PortStatus.OPEN


def test_wait_mode_gives_up_on_deadline() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.01, _connect_ok=False)
    results = verify_batch(
        [OK_TARGET],
        _config(wait=True, total_deadline=0.02, wait_interval=0.1),
        io,
    )
    assert results[-1].status is PortStatus.CLOSED


def test_wait_mode_attempts_limit() -> None:
    io = FakeClockSockets(_time=0.0, _advance=0.01, _connect_ok=False)
    connects = {"n": 0}

    class CountingIo(FakeClockSockets):
        def connect_tcp(self, target: Target, timeout: float) -> socket.socket:
            connects["n"] += 1
            return super().connect_tcp(target, timeout)

    counting = CountingIo(**io.__dict__)
    results = verify_batch(
        [OK_TARGET],
        _config(wait=True, total_deadline=60.0, wait_interval=0.1, wait_attempts=2),
        counting,
    )
    # attempt 1 (initial batch) + 1 retry iteration = 2 TCP probes.
    assert connects["n"] == 2
    assert results[-1].status is PortStatus.CLOSED


def test_verify_batch_requires_targets() -> None:
    with pytest.raises(ValueError):
        verify_batch([], _config())


def test_invalid_http_path_rejected() -> None:
    with pytest.raises(ValidationError):
        _config(protocol=Protocol.HTTP, http_path="no-slash")
