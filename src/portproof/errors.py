"""Error hierarchy for PortProof CLI exit-code mapping."""

from __future__ import annotations

from portproof.models import PortProofError

__all__ = [
    "DeadlineExceededError",
    "InputError",
    "PortProofError",
    "ProbeTimeoutError",
    "ReportWriteError",
]

# Re-export the base error so consumers can import it from one module.
PortProofError = PortProofError


class InputError(PortProofError):
    """Invalid CLI inputs. Maps to exit code 2."""


class ProbeTimeoutError(PortProofError):
    """A single probe timed out beyond its per-target timeout."""


class DeadlineExceededError(PortProofError):
    """The total run deadline elapsed in wait mode."""


class ReportWriteError(PortProofError):
    """The JSON evidence report could not be written."""
