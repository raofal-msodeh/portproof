"""PortProof: deterministic port and service verification with JSON evidence."""

from portproof.cli import VERSION, run
from portproof.models import (
    FailMode,
    PortProofError,
    PortStatus,
    ProbeConfig,
    ProbeResult,
    Protocol,
    Report,
    Target,
    ValidationError,
)

__version__ = VERSION

__all__ = [
    "VERSION",
    "FailMode",
    "PortProofError",
    "PortStatus",
    "ProbeConfig",
    "ProbeResult",
    "Protocol",
    "Report",
    "Target",
    "ValidationError",
    "run",
]
