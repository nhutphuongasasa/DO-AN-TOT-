from appid.dns.cache import DNSCache
from appid.dns.domain_rules import ApplicationDomainRules, DomainRule
from appid.dns.identifier import DNSApplicationIdentifier
from appid.dns.models import DNSAnswerRecord, DNSObservation


def obs(client="192.168.1.10", q="chat.example", answers=(), at=100):
    return DNSObservation("s1", 1, at, client, "192.168.1.1", 7, q, "A", 0, tuple(answers))


def test_cname_minimum_ttl_and_domain_candidates():
    cache = DNSCache()
    assert cache.update(obs(answers=[
        DNSAnswerRecord("chat.example", "CNAME", "edge.cdn.net", 60),
        DNSAnswerRecord("edge.cdn.net", "A", "203.0.113.8", 30),
    ])) == 1
    found = cache.lookup(session_id="s1", client_ip="192.168.1.10", destination_ip="203.0.113.8", timestamp=129.9)
    assert found[0].domain_candidates == ("chat.example", "edge.cdn.net")
    assert found[0].expires_at == 130
    assert cache.lookup(session_id="s1", client_ip="192.168.1.10", destination_ip="203.0.113.8", timestamp=130) == ()


def test_client_scope_shared_ip_same_app_identifies():
    cache = DNSCache()
    cache.update(obs(q="one.example", answers=[DNSAnswerRecord("one.example", "A", "203.0.113.8", 60)]))
    cache.update(obs(q="two.example", answers=[DNSAnswerRecord("two.example", "A", "203.0.113.8", 50)]))
    rules = ApplicationDomainRules([
        DomainRule("same", "r1", "one.example", "exact"),
        DomainRule("same", "r2", "two.example", "exact"),
    ])
    result = DNSApplicationIdentifier(cache, rules).identify(
        session_id="s1", flow_id="f1", client_ip="192.168.1.10", destination_ip="203.0.113.8", timestamp=110)
    assert result.status == "DNS_IDENTIFIED"
    assert result.application_id == "same"
    assert set(result.matched_domains) == {"one.example", "two.example"}
    assert cache.lookup(session_id="s1", client_ip="192.168.1.11", destination_ip="203.0.113.8", timestamp=110) == ()


def test_shared_ip_multiple_apps_unresolved_and_client_unknown():
    cache = DNSCache()
    cache.update(obs(q="one.example", answers=[DNSAnswerRecord("one.example", "A", "203.0.113.8", 60)]))
    cache.update(obs(q="two.example", answers=[DNSAnswerRecord("two.example", "A", "203.0.113.8", 60)]))
    rules = ApplicationDomainRules([
        DomainRule("app1", "r1", "one.example", "exact"),
        DomainRule("app2", "r2", "two.example", "exact"),
    ])
    ident = DNSApplicationIdentifier(cache, rules)
    result = ident.identify(session_id="s1", flow_id="f", client_ip="192.168.1.10", destination_ip="203.0.113.8", timestamp=110)
    assert result.reason_code == "DNS_SHARED_IP_AMBIGUOUS"
    assert ident.identify(session_id="s1", flow_id="f", client_ip=None, destination_ip="203.0.113.8", timestamp=110).reason_code == "DNS_CLIENT_UNKNOWN"


def test_ttl_zero_and_cname_loop_do_not_cache():
    cache = DNSCache()
    assert cache.update(obs(answers=[DNSAnswerRecord("chat.example", "A", "203.0.113.8", 0)])) == 0
    assert cache.update(obs(answers=[
        DNSAnswerRecord("chat.example", "CNAME", "edge.example", 30),
        DNSAnswerRecord("edge.example", "CNAME", "chat.example", 30),
    ])) == 0


def test_multiple_a_answers_for_one_domain_are_all_cached():
    cache = DNSCache()
    cache.update(obs(answers=[
        DNSAnswerRecord("chat.example", "A", "203.0.113.8", 60),
        DNSAnswerRecord("chat.example", "A", "203.0.113.9", 45),
    ]))
    assert cache.lookup(session_id="s1", client_ip="192.168.1.10", destination_ip="203.0.113.8", timestamp=110)
    assert cache.lookup(session_id="s1", client_ip="192.168.1.10", destination_ip="203.0.113.9", timestamp=110)
