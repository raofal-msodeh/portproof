"""
Data models for PortProof targets, probes, and evidence reports.

PortProof models are plain dataclasses with no runtime dependencies so the
evidence schema stays stable and serializable to JSON in any environment.
"""

from __future__ import annotations

import enum
import os
import socket
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PortProofError",
    "PortStatus",
    "ProbeConfig",
    "ProbeResult",
    "Protocol",
    "Report",
    "Target",
    "ValidationError",
]


class PortProofError(Exception):
    """Base class for all PortProof errors."""


class ValidationError(PortProofError):
    """Raised when inputs (targets, config, paths) fail validation."""


class Protocol(str, enum.Enum):
    """Network protocol used to verify a port."""

    TCP = "tcp"
    TLS = "tls"
    HTTP = "http"


class PortStatus(str, enum.Enum):
    """Outcome of verifying a single target."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


class FailMode(str, enum.Enum):
    """How batch results map to the process exit code."""

    ALL = "all"  # exit 0 only if every target is open
    ANY = "any"  # exit 0 if at least one target is open


def _validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValidationError("host must not be empty")
    if len(host) > 253:
        raise ValidationError("host is too long (max 253 characters)")
    if not host.isascii():
        raise ValidationError("host must be plain ASCII")
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        if host.startswith("[") or "%" in host or (":" in host and not host.startswith("[")):
            # Bare IPv6 addresses must be bracketed or unambiguous; keep raw form.
            pass
        return host
    except (OSError, ValueError):
        pass
    if host[0] == "-" or host[-1] == "-":
        raise ValidationError("host must not start or end with a hyphen")
    if ".." in host:
        raise ValidationError("host contains invalid sequence '..'")
    lowered = host if host.startswith("[") else host.split(".")[0]
    first = lowered[0]
    if not (first.isalnum()):
        raise ValidationError("host must start with an alphanumeric character")
    return host


def _validate_port(port: int) -> int:
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValidationError("port must be an integer")
    if not (1 <= port <= 65535):
        raise ValidationError("port must be between 1 and 65535")
    return port


def _validate_positive(value: float, name: str, *, allow_zero: bool = False) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValidationError(f"{name} must be a number")
    if allow_zero and value == 0:
        return 0.0
    if value <= 0:
        raise ValidationError(f"{name} must be greater than 0")
    return float(value)


@dataclass(frozen=True)
class Target:
    """A host:port endpoint to verify."""

    host: str
    port: int

    def __init__(self, host: str, port: int) -> None:
        # object.__setattr__ bypasses frozen __setattr__ during init.
        object.__setattr__(self, "host", _validate_host(host))
        object.__setattr__(self, "port", _validate_port(port))

    @classmethod
    def from_spec(cls, spec: str) -> Target:
        """Parse 'host:port' (IPv6 hosts must be bracketed: '[::1]:80')."""
        if not isinstance(spec, str):
            raise ValidationError("target spec must be a string")
        spec = spec.strip()
        if not spec:
            raise ValidationError("target spec must not be empty")
        if spec.startswith("["):
            bracket = spec.find("]")
            if bracket == -1:
                raise ValidationError("IPv6 target spec is missing closing bracket")
            host_part = spec[1:bracket]
            rest = spec[bracket + 1 :]
            if not rest.startswith(":"):
                raise ValidationError("bracketed IPv6 target must be followed by :port")
            return cls(host_part, int(rest[1:]))
        if spec.count(":") > 1:
            raise ValidationError("unbracketed target must be host:port")
        host_part, _, port_part = spec.partition(":")
        try:
            port = int(port_part)
        except ValueError:
            raise ValidationError("target port must be an integer") from None
        return cls(host_part, port)

    def __str__(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    def as_dict(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port}


@dataclass(frozen=True)
class ProbeConfig:
    """Runtime configuration for a verification run."""

    timeout: float = 5.0
    total_deadline: float = 0.0
    wait: bool = False
    wait_interval: float = 1.0
    wait_attempts: int = 0
    protocol: Protocol = Protocol.TCP
    tls_ca: str = ""
    http_path: str = "/"
    tls_min_seconds: float = 0.0
    tls_max_seconds: float = 0.0
    fail_mode: FailMode = FailMode.ALL

    def __post_init__(self) -> None:
        if self.protocol == Protocol.HTTP and self.http_path[:1] != "/":
            raise ValidationError("http_path must start with '/'")
        if not isinstance(self.http_path, str) or len(self.http_path) > 1024:
            raise ValidationError("http_path must be at most 1024 characters")
        if self.tls_min_seconds < 0:
            raise ValidationError("tls_min_seconds must not be negative")
        if self.tls_max_seconds < 0:
            raise ValidationError("tls_max_seconds must not be negative")
        if (
            self.tls_min_seconds
            and self.tls_max_seconds
            and self.tls_min_seconds > self.tls_max_seconds
        ):
            raise ValidationError("tls_min_seconds must not exceed tls_max_seconds")
        if not isinstance(self.tls_ca, str):
            raise ValidationError("tls_ca must be a string")
        if self.tls_ca and not os.path.isfile(self.tls_ca):
            raise ValidationError(f"tls_ca file does not exist: {self.tls_ca}")
        if self.wait and not (self.total_deadline > 0):
            raise ValidationError("wait mode requires --deadline to be set")

    @classmethod
    def defaults(cls) -> ProbeConfig:
        return cls()


@dataclass(frozen=True)
class ProbeResult:
    """Evidence for a single target verification."""

    target: Target
    protocol: Protocol
    status: PortStatus
    reason: str
    elapsed_ms: float
    tls_seconds: float = 0.0
    http_status: int = 0
    http_scheme: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = {
            "target": self.target.as_dict(),
            "protocol": self.protocol.value,
            "status": self.status.value,
            "reason": self.reason,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }
        if self.protocol in (Protocol.TLS, Protocol.HTTP):
            data["tls_seconds"] = round(self.tls_seconds, 3)
        if self.protocol is Protocol.HTTP and self.http_status:
            data["http_status"] = self.http_status
            data["http_scheme"] = self.http_scheme
        return data


@dataclass(frozen=True)
class Report:
    """Batch verification report: the JSON evidence artifact."""

    targets: list[ProbeResult] = field(default_factory=list)
    deadline_iso: str = ""
    fail_mode: FailMode = FailMode.ALL

    @property
    def passed(self) -> bool:
        if not self.targets:
            return False
        statuses = {result.status for result in self.targets}
        if self.fail_mode is FailMode.ALL:
            return statuses <= {PortStatus.OPEN}
        return PortStatus.OPEN in statuses

    def as_dict(self) -> dict[str, Any]:
        return {
            "portproof_version": "1.0.0",
            "fail_mode": self.fail_mode.value,
            "deadline_iso": self.deadline_iso,
            "targets": [target.as_dict() for target in self.targets],
            "passed": self.passed,
        }
