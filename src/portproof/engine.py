"""
Verification engine: TCP/TLS/HTTP probes with injectable IO for testing.

All wall-clock and socket interactions go through a `ClockSockets` bundle so
tests can drive probes deterministically without touching the network.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass

from portproof.errors import (
    DeadlineExceededError,
    ProbeTimeoutError,
)
from portproof.models import (
    PortStatus,
    ProbeConfig,
    ProbeResult,
    Protocol,
    Target,
)

__all__ = ["ClockSockets", "verify_batch", "verify_target"]


@dataclass(frozen=True)
class _RealClockSockets:
    """Real production IO bundle."""

    def time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(max(0.0, seconds))

    def connect_tls_ca(self, ca_path: str, target: Target, timeout: float) -> ssl.SSLSocket:
        """TLS handshake with a caller-provided CA bundle."""
        raw = self.connect_tcp(target, timeout)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=ca_path)
            context.check_hostname = False  # caller decides trust via CA only
            server_hostname = target.host if not target.host[0].isdigit() else None
            wrapped = context.wrap_socket(raw, server_hostname=server_hostname)
        except ssl.SSLCertVerificationError:
            raw.close()
            raise
        except TimeoutError as exc:
            raw.close()
            raise ProbeTimeoutError(f"TLS handshake timed out after {timeout:.1f}s") from exc
        except ssl.SSLError as exc:
            raw.close()
            raise ssl.SSLError(f"TLS handshake failed on {target}: {exc}") from exc
        except BaseException:
            raw.close()
            raise
        return wrapped

    def connect_tcp(self, target: Target, timeout: float) -> socket.socket:
        address = (target.host, target.port)
        family = socket.AF_INET
        try:
            socket.inet_pton(socket.AF_INET6, target.host)
            family = socket.AF_INET6
        except (OSError, ValueError):
            pass
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            return sock
        except TimeoutError as exc:
            raise ProbeTimeoutError(f"connection timed out after {timeout:.1f}s") from exc
        except ConnectionRefusedError as exc:
            raise ConnectionRefusedError(f"connection refused on {target}") from exc
        except OSError as exc:
            raise OSError(f"network error on {target}: {exc}") from exc

    def connect_tls(self, target: Target, timeout: float) -> ssl.SSLSocket:
        """TLS handshake only: verify the server accepts a TLS connection."""
        raw = self.connect_tcp(target, timeout)
        try:
            context = ssl.create_default_context()
            if target.host[0].isdigit():
                # IP addresses cannot satisfy hostname checking; verify the
                # certificate chain but skip hostname matching.
                context.check_hostname = False
                server_hostname = None
            else:
                server_hostname = target.host
            wrapped = context.wrap_socket(raw, server_hostname=server_hostname)
        except ssl.SSLCertVerificationError:
            # Certificate validation failure is still proof the TLS stack
            # answered; close the raw socket and re-raise for the caller.
            raw.close()
            raise
        except TimeoutError as exc:
            raw.close()
            raise ProbeTimeoutError(f"TLS handshake timed out after {timeout:.1f}s") from exc
        except ssl.SSLError as exc:
            raw.close()
            raise ssl.SSLError(f"TLS handshake failed on {target}: {exc}") from exc
        except BaseException:
            raw.close()
            raise
        return wrapped

    def http_probe(self, target: Target, timeout: float, path: str) -> tuple[int, str, float]:
        conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
        try:
            deadline = self.time() + timeout
            conn.request("HEAD", path, headers={"Connection": "close"})
            response = conn.getresponse()
            elapsed = deadline - self.time()
            status = response.status
            response.read()
            return status, "http", elapsed
        except TimeoutError as exc:
            raise ProbeTimeoutError(f"HTTP probe timed out after {timeout:.1f}s") from exc
        except OSError as exc:
            raise OSError(f"HTTP probe failed on {target}: {exc}") from exc
        finally:
            conn.close()


@dataclass(frozen=True)
class FakeClockSockets(_RealClockSockets):
    """Test IO bundle with fully controlled time and sockets."""

    _time: float = 0.0
    _advance: float = 0.001
    _connect_ok: bool = True
    _tls_ok: bool = True
    _http_status: int = 200
    _connect_side_effect: BaseException | None = None

    def time(self) -> float:
        current = self._time
        self.__dict__["_time"] = current + self._advance
        return current

    def sleep(self, seconds: float) -> None:
        self.__dict__["_time"] = self._time + max(0.0, seconds)

    def connect_tcp(self, target: Target, timeout: float) -> socket.socket:
        if self._connect_side_effect is not None:
            raise self._connect_side_effect
        if not self._connect_ok:
            raise ConnectionRefusedError(f"refused (fake) on {target}")
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_tls(self, target: Target, timeout: float) -> ssl.SSLSocket:
        if not self._tls_ok:
            raise ssl.SSLError("fake TLS failure")
        return self.connect_tcp(target, timeout)  # type: ignore[return-value]

    def http_probe(self, target: Target, timeout: float, path: str) -> tuple[int, str, float]:
        if not self._connect_ok:
            raise ConnectionRefusedError(f"refused (fake) on {target}")
        return self._http_status, "http", 0.002


# Alias so callers (and tests) can name the injectable IO type.
ClockSockets = _RealClockSockets


def _default_bundle() -> _RealClockSockets:
    return _RealClockSockets()


def _classify(os_error: OSError, target: Target) -> tuple[PortStatus, str]:
    if isinstance(os_error, (TimeoutError, socket.timeout)):
        return PortStatus.FILTERED, "no response within timeout"
    if isinstance(os_error, ConnectionRefusedError):
        return PortStatus.CLOSED, "connection refused"
    return PortStatus.ERROR, f"network error: {os_error}"


def verify_target(
    target: Target,
    config: ProbeConfig,
    io: _RealClockSockets | None = None,
) -> ProbeResult:
    """Verify a single target and return deterministic evidence."""
    io = io if io is not None else _default_bundle()
    start = io.time()
    try:
        if config.protocol is Protocol.TCP:
            with io.connect_tcp(target, config.timeout) as _sock:
                elapsed = io.time() - start
            return ProbeResult(
                target=target,
                protocol=Protocol.TCP,
                status=PortStatus.OPEN,
                reason="tcp connection established",
                elapsed_ms=elapsed * 1000,
            )
        if config.protocol is Protocol.TLS:
            connector = (
                io.connect_tls_ca(config.tls_ca, target, config.timeout)
                if config.tls_ca
                else io.connect_tls(target, config.timeout)
            )
            with connector as _wrapped:
                elapsed = io.time() - start
            return ProbeResult(
                target=target,
                protocol=Protocol.TLS,
                status=PortStatus.OPEN,
                reason="tls handshake completed",
                elapsed_ms=elapsed * 1000,
            )
        http_status, http_scheme, elapsed = io.http_probe(target, config.timeout, config.http_path)
        return ProbeResult(
            target=target,
            protocol=Protocol.HTTP,
            status=PortStatus.OPEN if 200 <= http_status < 400 else PortStatus.ERROR,
            reason=f"http {http_status} {http_scheme.upper() if http_scheme else ''}",
            elapsed_ms=elapsed * 1000,
            http_status=http_status,
            http_scheme=http_scheme,
        )
    except ProbeTimeoutError as exc:
        elapsed = io.time() - start
        return ProbeResult(
            target=target,
            protocol=config.protocol,
            status=PortStatus.FILTERED,
            reason=str(exc),
            elapsed_ms=elapsed * 1000,
        )
    except (ssl.SSLError, ConnectionRefusedError, OSError) as exc:
        elapsed = io.time() - start
        error_status: PortStatus
        error_reason: str
        if isinstance(exc, (TimeoutError, socket.timeout)):
            error_status, error_reason = PortStatus.FILTERED, "no response within timeout"
        elif isinstance(exc, ConnectionRefusedError):
            error_status, error_reason = PortStatus.CLOSED, "connection refused"
        elif isinstance(exc, ssl.SSLError):
            error_status, error_reason = PortStatus.ERROR, f"tls failure: {exc}"
        else:
            error_status, error_reason = _classify(exc, target)
        return ProbeResult(
            target=target,
            protocol=config.protocol,
            status=error_status,
            reason=error_reason,
            elapsed_ms=elapsed * 1000,
        )


def verify_batch(
    targets: list[Target],
    config: ProbeConfig,
    io: _RealClockSockets | None = None,
    reporter: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    """Verify every target in order; in wait mode loop until deadline."""
    io = io if io is not None else _default_bundle()
    if not targets:
        raise ValueError("at least one target is required")

    run_start = io.time()
    deadline = run_start + config.total_deadline if config.total_deadline else 0.0

    def _once() -> list[ProbeResult]:
        results: list[ProbeResult] = []
        for target in targets:
            if config.total_deadline and io.time() >= deadline:
                if not results:
                    raise DeadlineExceededError("total deadline elapsed before first probe")
                return results
            result = verify_target(target, config, io)
            results.append(result)
            if reporter is not None:
                reporter(result)
        return results

    results = _once()
    if not config.wait:
        return results

    interval = max(0.1, config.wait_interval)
    attempts = config.wait_attempts or 0
    attempt = 1
    while True:
        from portproof.models import PortStatus  # noqa: PLC0415

        last = results[-1]
        if last.status is PortStatus.OPEN:
            return results
        if attempts and attempt >= attempts:
            return results
        if config.total_deadline and io.time() >= deadline:
            return results
        io.sleep(interval)
        attempt += 1
        results = _once()
        if not results:
            return results
    # pragma: no cover - unreachable
