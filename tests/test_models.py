"""Tests for PortProof data models: targets, configs, reports."""

from __future__ import annotations

import pytest

from portproof.models import (
    FailMode,
    PortStatus,
    ProbeConfig,
    ProbeResult,
    Protocol,
    Report,
    Target,
    ValidationError,
)


class TestTargetParsing:
    def test_ipv4_host(self) -> None:
        target = Target.from_spec("192.168.1.1:5432")
        assert target.host == "192.168.1.1"
        assert target.port == 5432

    def test_hostname(self) -> None:
        target = Target.from_spec("db.local:3306")
        assert target.host == "db.local"
        assert target.port == 3306

    def test_bracketed_ipv6(self) -> None:
        target = Target.from_spec("[::1]:443")
        assert target.host == "::1"
        assert target.port == 443

    def test_ipv6_full(self) -> None:
        target = Target.from_spec("[2001:db8::1]:8080")
        assert target.host == "2001:db8::1"
        assert target.port == 8080

    def test_str_roundtrip_ipv4(self) -> None:
        assert str(Target.from_spec("10.0.0.1:22")) == "10.0.0.1:22"

    def test_str_roundtrip_ipv6_bracketed(self) -> None:
        assert str(Target.from_spec("[::1]:22")) == "[::1]:22"

    def test_strip_whitespace(self) -> None:
        target = Target.from_spec("  host : 7001 ")
        assert target.host == "host"
        assert target.port == 7001

    def test_empty_spec_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("")

    def test_missing_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("hostonly")

    def test_non_numeric_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("host:abc")

    def test_port_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("host:0")

    def test_port_too_high_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("host:99999")

    def test_negative_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("host:-1")

    def test_unbracketed_ipv6_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("::1:80")

    def test_bracket_missing_close_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("[::1:80")

    def test_bracket_without_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("[::1]")

    def test_host_leading_hyphen_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("-evil:80")

    def test_host_double_dot_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("h..ost:80")

    def test_host_non_alnum_start_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec("!bad:80")

    def test_host_too_long_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target.from_spec(f"{'a' * 254}:80")

    def test_direct_construction_validates(self) -> None:
        with pytest.raises(ValidationError):
            Target(host="host", port=0)

    def test_as_dict(self) -> None:
        assert Target.from_spec("h:1").as_dict() == {"host": "h", "port": 1}


class TestProbeConfig:
    def test_defaults_are_safe(self) -> None:
        config = ProbeConfig.defaults()
        assert config.protocol is Protocol.TCP
        assert config.timeout == 5.0
        assert not config.wait
        assert config.fail_mode is FailMode.ALL

    def test_http_path_must_be_absolute(self) -> None:
        with pytest.raises(ValidationError):
            ProbeConfig(protocol=Protocol.HTTP, http_path="relative")

    def test_http_path_too_long_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProbeConfig(protocol=Protocol.HTTP, http_path="/" + "x" * 1024)

    def test_wait_requires_deadline(self) -> None:
        with pytest.raises(ValidationError):
            ProbeConfig(wait=True, total_deadline=0.0)

    def test_wait_with_deadline_accepted(self) -> None:
        config = ProbeConfig(wait=True, total_deadline=10.0)
        assert config.total_deadline == 10.0

    def test_tls_window_validation(self) -> None:
        with pytest.raises(ValidationError):
            ProbeConfig(tls_min_seconds=5.0, tls_max_seconds=2.0)

    def test_negative_tls_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProbeConfig(tls_min_seconds=-1.0)

    def test_frozen(self) -> None:
        with pytest.raises(AttributeError):
            ProbeConfig().timeout = 99  # type: ignore[misc]


class TestReport:
    def test_passed_all_mode_everything_open(self) -> None:
        report = Report(
            targets=[
                ProbeResult(Target("a", 1), Protocol.TCP, PortStatus.OPEN, "ok", 1.0),
            ],
            fail_mode=FailMode.ALL,
        )
        assert report.passed

    def test_failed_all_mode_one_closed(self) -> None:
        report = Report(
            targets=[
                ProbeResult(Target("a", 1), Protocol.TCP, PortStatus.OPEN, "ok", 1.0),
                ProbeResult(Target("b", 2), Protocol.TCP, PortStatus.CLOSED, "refused", 0.1),
            ],
            fail_mode=FailMode.ALL,
        )
        assert not report.passed

    def test_passed_any_mode_one_open(self) -> None:
        report = Report(
            targets=[
                ProbeResult(Target("a", 1), Protocol.TCP, PortStatus.CLOSED, "refused", 0.1),
                ProbeResult(Target("b", 2), Protocol.TCP, PortStatus.OPEN, "ok", 1.0),
            ],
            fail_mode=FailMode.ANY,
        )
        assert report.passed

    def test_failed_any_mode_all_closed(self) -> None:
        report = Report(
            targets=[
                ProbeResult(Target("a", 1), Protocol.TCP, PortStatus.CLOSED, "refused", 0.1),
            ],
            fail_mode=FailMode.ANY,
        )
        assert not report.passed

    def test_empty_targets_failed(self) -> None:
        report = Report(targets=[], fail_mode=FailMode.ALL)
        assert not report.passed

    def test_as_dict_schema(self) -> None:
        report = Report(
            targets=[ProbeResult(Target("h", 80), Protocol.TCP, PortStatus.OPEN, "ok", 2.5)],
            deadline_iso="2026-08-16T00:00:00+00:00",
            fail_mode=FailMode.ALL,
        )
        data = report.as_dict()
        assert data["portproof_version"] == "1.0.0"
        assert data["passed"] is True
        assert data["targets"][0]["elapsed_ms"] == 2.5
        assert "tls_seconds" not in data["targets"][0]
        tls_result = ProbeResult(
            Target("h", 443), Protocol.TLS, PortStatus.OPEN, "ok", 3.0, tls_seconds=0.125
        )
        assert tls_result.as_dict()["tls_seconds"] == 0.125
        http_result = ProbeResult(
            Target("h", 80),
            Protocol.HTTP,
            PortStatus.OPEN,
            "http 200 HTTP",
            4.0,
            http_status=200,
            http_scheme="http",
        )
        http_dict = http_result.as_dict()
        assert http_dict["http_status"] == 200
        assert http_dict["http_scheme"] == "http"

    def test_http_error_status(self) -> None:
        result = ProbeResult(
            Target("h", 80),
            Protocol.HTTP,
            PortStatus.ERROR,
            "http 500 HTTP",
            4.0,
            http_status=500,
            http_scheme="http",
        )
        assert result.status is PortStatus.ERROR
        assert result.as_dict()["http_status"] == 500
