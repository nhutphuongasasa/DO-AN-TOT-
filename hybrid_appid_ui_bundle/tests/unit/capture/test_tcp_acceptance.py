from types import SimpleNamespace

from appid.domain.models import Evidence, IdentificationMethod, TransportProtocol
from scripts.verify_tcp_appid_acceptance import EXPECTED, validate_replay, validate_traffic_report


def _flow(app, hostname):
    result = SimpleNamespace(
        application=app,
        method=IdentificationMethod.SNI,
        evidence=(Evidence(source="tls_sni", value=hostname),),
    )
    return SimpleNamespace(
        key=SimpleNamespace(protocol=TransportProtocol.TCP),
        identification_result=result,
    )


def _replay(flows):
    stats = SimpleNamespace(
        raw_packets=100,
        parsed_packets=100,
        tracked_packets=100,
        unsupported_packets=0,
        parse_errors=0,
        sni_parse_errors=1,
    )
    return SimpleNamespace(stats=stats, flows=tuple(flows))


def test_acceptance_requires_all_five_tcp_sni_appids():
    result = _replay([_flow(app, hostname) for app, hostname in EXPECTED.items()])
    failures, observed = validate_replay(result)
    assert failures == []
    assert observed == EXPECTED


def test_acceptance_fails_when_one_target_app_is_missing():
    flows = [_flow(app, hostname) for app, hostname in EXPECTED.items() if app != "spotify"]
    failures, observed = validate_replay(_replay(flows))
    assert "spotify" not in observed
    assert any("spotify" in failure for failure in failures)


def test_acceptance_does_not_accept_udp_or_non_sni_identification():
    udp = _flow("chatgpt", "chatgpt.com")
    udp.key.protocol = TransportProtocol.UDP
    no_sni = _flow("facebook", "www.facebook.com")
    no_sni.identification_result.method = IdentificationMethod.DNS
    failures, observed = validate_replay(_replay([udp, no_sni]))
    assert observed == {}
    assert len(failures) == len(EXPECTED)


def test_traffic_report_requires_successful_probe_rows(tmp_path):
    report = tmp_path / "traffic.tsv"
    lines = ["app\texpected_sni\thttp_status\tcurl_exit\tresult"]
    for app, hostname in EXPECTED.items():
        lines.append(f"{app}\t{hostname}\t200\t0\tTCP_HTTP1_REQUEST_COMPLETED")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert validate_traffic_report(report) == []


def test_traffic_report_fails_for_failed_probe(tmp_path):
    report = tmp_path / "traffic.tsv"
    lines = ["app\texpected_sni\thttp_status\tcurl_exit\tresult"]
    for app, hostname in EXPECTED.items():
        status, exit_code = ("000", "7") if app == "tiktok" else ("200", "0")
        lines.append(f"{app}\t{hostname}\t{status}\t{exit_code}\tTCP_REQUEST_FAILED")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("tiktok" in item for item in validate_traffic_report(report))
