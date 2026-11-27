import pytest

from appid.dns.domain_rules import ApplicationDomainRules, DomainRule, normalize_domain


def test_normalization_and_label_aware_suffix():
    rules = ApplicationDomainRules([DomainRule("app", "r1", "Example.COM.", "suffix")])
    assert normalize_domain("API.Example.com.") == "api.example.com"
    assert rules.match("api.example.com")
    assert not rules.match("notexample.com")


def test_exact_precedes_suffix_and_conflicting_equal_priority_is_preserved():
    rules = ApplicationDomainRules([
        DomainRule("broad", "s", "example.com", "suffix"),
        DomainRule("exact", "e", "api.example.com", "exact"),
    ])
    assert [r.application_id for r in rules.match("api.example.com")] == ["exact"]
    conflict = ApplicationDomainRules([
        DomainRule("a", "a", "api.example.com", "exact"),
        DomainRule("b", "b", "api.example.com", "exact"),
    ])
    assert {r.application_id for r in conflict.match("api.example.com")} == {"a", "b"}


def test_invalid_match_rejected():
    with pytest.raises(ValueError):
        ApplicationDomainRules([DomainRule("a", "r", "example.com", "contains")])


def test_dataset_six_class_domain_mapping_loads_and_is_conservative():
    from pathlib import Path

    config = Path(__file__).resolve().parents[3] / "config" / "dns_mapping.yaml"
    rules = ApplicationDomainRules.from_yaml(config.resolve())

    app_ids = {rule.application_id for rule in rules.rules}
    assert app_ids == {"chatgpt", "facebook", "tiktok", "youtube", "spotify"}
    assert len(rules.rules) == 33

    examples = {
        "chatgpt": "api.chatgpt.com",
        "facebook": "static.xx.fbcdn.net",
        "tiktok": "v16-webapp-prime.tiktok.com",
        "youtube": "r1---sn.googlevideo.com",
        "spotify": "audio4.spotifycdn.com",
    }
    for expected_app, domain in examples.items():
        assert {r.application_id for r in rules.match(domain)} == {expected_app}

    # `other-web` is a classifier label, never a DNS catch-all.
    assert "other-web" not in app_ids
    assert rules.match("ordinary-example.net") == ()


def test_dataset_rules_do_not_claim_shared_provider_or_sibling_products():
    from pathlib import Path

    config = Path(__file__).resolve().parents[3] / "config" / "dns_mapping.yaml"
    rules = ApplicationDomainRules.from_yaml(config.resolve())

    for domain in (
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "cloudflare.com",
        "byteoversea.com",
        "instagram.com",
        "whatsapp.com",
        "threads.net",
        "notfacebook.com",
        "notyoutube.com",
    ):
        assert rules.match(domain) == (), domain
