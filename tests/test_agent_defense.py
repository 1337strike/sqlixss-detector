"""
tests/test_agent_defense.py
---------------------------
Unit tests for the AI-agent defense layer (src/agent_defense.py): client
fingerprint, suspicion score (honeypot, enumeration, error leaks), probation
after repeated distinct blocks, cross-client payload-family memory, and
backend error-leak detection.

Behavioral tests run against both state stores with a virtual clock. The
Redis store needs a server at $WAF_TEST_REDIS_URL (default
redis://127.0.0.1:6379/15); those cases are skipped if none is reachable,
unless REQUIRE_REDIS=1 (set in CI).

Run:
    python -m pytest tests/test_agent_defense.py -v
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agent_defense import (
    AgentDefense, AgentDefenseConfig, MemoryAgentStore, RedisAgentStore, agent_config_from_dict,
    build_agent_defense, compact, fingerprint_signals, has_injection_syntax, leaks_backend_error,
    lsh_keys, shingles, similarity,
)

REDIS_URL = os.environ.get("WAF_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")

ATTACKER = "203.0.113.7"
OTHER = "203.0.113.99"
USER = "198.51.100.20"

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
BROWSER = {"User-Agent": CHROME, "Accept-Language": "en-US,en;q=0.9", "Accept": "text/html"}

# Distinct payloads the ensemble blocks; a real bypass it lets through.
BLOCKED = ["q=1' AND 1=1-- ", "q=<svg onload=alert(1)>", "q=' union select null,null-- "]
MODEL_BYPASS = "q=1 AnD 2>1"


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


def _redis_client():
    try:
        import redis as redis_lib
        client = redis_lib.from_url(REDIS_URL)
        client.ping()
        return client
    except Exception:
        if os.environ.get("REQUIRE_REDIS") == "1":
            raise
        return None


@pytest.fixture(params=["memory", "redis"])
def make_defense(request):
    """Factory: make_defense(**config) -> (AgentDefense, FakeClock)."""
    client = None
    prefix = f"waf-agent-test:{uuid.uuid4().hex}:"
    if request.param == "redis":
        client = _redis_client()
        if client is None:
            pytest.skip(f"no Redis server reachable at {REDIS_URL}")

    def factory(**overrides):
        clock = FakeClock()
        store = RedisAgentStore(client, key_prefix=prefix) if client is not None else MemoryAgentStore()
        config = AgentDefenseConfig(**{"honeypot_paths": ["/admin-backup/"], **overrides})
        return AgentDefense(config, store, clock=clock), clock

    yield factory
    if client is not None:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)


# ── fingerprint ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("headers,expected", [
    (BROWSER, []),
    ({"User-Agent": CHROME}, ["spoofed_browser_ua"]),                      # requests + pasted UA
    ({"User-Agent": CHROME, "Accept-Language": ""}, ["spoofed_browser_ua"]),
    ({"User-Agent": "python-httpx/0.27.0"}, ["automation_client"]),
    ({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0 Safari/537.36",
      "Accept-Language": "en"}, ["automation_client"]),
    ({"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1)"},
     ["declared_ai_agent"]),
    ({"User-Agent": "ClaudeBot/1.0"}, ["declared_ai_agent"]),
    ({"User-Agent": "Mozilla/5.0"}, []),                                   # claims nothing specific
    ({}, []),
])
def test_fingerprint_signals(headers, expected):
    assert fingerprint_signals(headers) == expected


def test_sec_fetch_only_when_expected():
    assert fingerprint_signals(BROWSER) == []
    assert fingerprint_signals(BROWSER, expect_sec_fetch=True) == ["missing_sec_fetch"]
    assert fingerprint_signals({**BROWSER, "Sec-Fetch-Mode": "navigate"}, expect_sec_fetch=True) == []


def test_fingerprint_alone_never_blocks(make_defense):
    """Client-property signals count once per window and sum to < threshold:
    a scripted client with a pasted browser UA is scored, never blocked."""
    defense, clock = make_defense()
    for ua_headers in ({"User-Agent": CHROME}, {"User-Agent": "python-httpx/0.27"},
                       {"User-Agent": "GPTBot/1.1"}) * 50:
        a = defense.assess(ATTACKER, "/search", ua_headers)
        clock.now += 1
    assert not a.flagged and a.score == 80


# ── score: honeypot, declared agents, enumeration ───────────────────────────

def test_honeypot_flags_client_for_the_window(make_defense):
    defense, clock = make_defense()
    assert not defense.assess(ATTACKER, "/search", BROWSER).flagged
    assert defense.assess(ATTACKER, "/Admin-Backup/db.sql", BROWSER).flagged
    assert defense.assess(ATTACKER, "/search", BROWSER).flagged          # every later request
    assert not defense.assess(USER, "/search", BROWSER).flagged          # per client
    clock.now += 601
    assert not defense.assess(ATTACKER, "/search", BROWSER).flagged      # window expired


@pytest.mark.parametrize("policy,flagged,score", [("allow", False, 0), ("flag", False, 30), ("block", True, 30)])
def test_declared_ai_agent_policy(make_defense, policy, flagged, score):
    defense, _ = make_defense(declared_ai_agents=policy)
    a = defense.assess(ATTACKER, "/", {"User-Agent": "PerplexityBot/1.0"})
    assert (a.flagged, a.score) == (flagged, score)


def test_enumeration_flags_after_distinct_error_paths(make_defense):
    defense, clock = make_defense(enumeration_distinct_error_paths=30)
    for i in range(29):
        defense.observe_response(ATTACKER, f"/dir{i}", 404, "text/html", b"not found", [])
    defense.observe_response(ATTACKER, "/dir0", 404, "text/html", b"", [])   # repeat: not distinct
    assert not defense.assess(ATTACKER, "/", BROWSER).flagged
    defense.observe_response(ATTACKER, "/dir29", 404, "text/html", b"", [])
    assert defense.assess(ATTACKER, "/", BROWSER).flagged


def test_error_paths_outside_window_do_not_add_up(make_defense):
    defense, clock = make_defense(enumeration_distinct_error_paths=30)
    for i in range(60):
        defense.observe_response(ATTACKER, f"/dir{i}", 404, "text/html", b"", [])
        clock.now += 30                                                   # 20 per 600 s window
    assert not defense.assess(ATTACKER, "/", BROWSER).flagged


# ── probation ───────────────────────────────────────────────────────────────

def test_probation_after_distinct_blocks(make_defense):
    defense, clock = make_defense()
    for payload in BLOCKED[:2]:
        defense.remember_block(ATTACKER, payload)
    a = defense.assess(ATTACKER, "/search", BROWSER)
    assert not a.on_probation
    assert defense.check_content(ATTACKER, a, [MODEL_BYPASS], []) == ([], None)

    defense.remember_block(ATTACKER, BLOCKED[2])
    a = defense.assess(ATTACKER, "/search", BROWSER)
    assert a.on_probation
    assert defense.check_content(ATTACKER, a, [MODEL_BYPASS], []) == (["probation_injection_syntax"], MODEL_BYPASS)
    assert defense.check_content(ATTACKER, a, ["q=laptop&page=2", "/search"], [CHROME]) == ([], None)

    clock.now += 3601
    assert not defense.assess(ATTACKER, "/search", BROWSER).on_probation


def test_repeating_one_payload_is_not_probation(make_defense):
    """Probation needs DISTINCT payloads: one false positive retried by a
    real user never puts them on probation."""
    defense, _ = make_defense()
    for _ in range(10):
        defense.remember_block(USER, "name=O'Neil")
    assert not defense.assess(USER, "/", BROWSER).on_probation


def test_probation_similarity_covers_headers(make_defense):
    defense, _ = make_defense()
    for payload in BLOCKED + ["' OR sleep(5) OR '"]:
        defense.remember_block(ATTACKER, payload)
    a = defense.assess(ATTACKER, "/", BROWSER)
    reasons, text = defense.check_content(ATTACKER, a, [], ["' Or  SLEEP(5)  oR '"])
    assert reasons == ["probation_similar_to_blocked"]
    assert defense.check_content(ATTACKER, a, [], [CHROME]) == ([], None)


def test_probation_blocks_add_to_score(make_defense):
    defense, _ = make_defense()
    for payload in BLOCKED:
        defense.remember_block(ATTACKER, payload)
    for _ in range(4):
        a = defense.assess(ATTACKER, "/", BROWSER)
        defense.check_content(ATTACKER, a, [MODEL_BYPASS], [])
    assert defense.assess(ATTACKER, "/", BROWSER).flagged                # 4 x 25


# ── cross-client payload families ───────────────────────────────────────────

def test_global_family_blocks_mutation_from_fresh_ip(make_defense):
    """A near-duplicate of a payload blocked from one IP is refused from any
    IP -- IP rotation does not reset what the WAF learned."""
    defense, clock = make_defense()
    mutation = "q=-1 UNION SELxECT 1 INTO @,@,@"
    a = defense.assess(OTHER, "/", BROWSER)
    assert defense.check_content(OTHER, a, [mutation], []) == ([], None)

    defense.remember_block(ATTACKER, "q=-1 UNION SELECT 1 INTO @,@,@")
    a = defense.assess(OTHER, "/", BROWSER)
    assert defense.check_content(OTHER, a, [mutation], []) == (["global_payload_family"], mutation)
    assert defense.check_content(OTHER, a, ["q=O'Neil", "q=laptop"], []) == ([], None)

    clock.now += 3601
    assert defense.check_content(OTHER, defense.assess(OTHER, "/", BROWSER), [mutation], []) == ([], None)


def test_benign_text_is_never_indexed_globally(make_defense):
    defense, _ = make_defense()
    defense.remember_block(ATTACKER, "q=laptop cheap deals")                 # no injection syntax
    a = defense.assess(OTHER, "/", BROWSER)
    assert defense.check_content(OTHER, a, ["q=laptop cheap deals!'"], []) == ([], None)


# ── backend error leaks ─────────────────────────────────────────────────────

SQL_ERROR = b"<b>Warning</b>: You have an error in your SQL syntax; check the manual that corresponds to your MySQL"


def test_error_leak_scrubbed_only_when_provoked_or_5xx(make_defense):
    defense, _ = make_defense()
    assert defense.observe_response(ATTACKER, "/item", 200, "text/html; charset=utf-8", SQL_ERROR, ["id=1'"])
    # a page that merely QUOTES a DB error (blog post) is left alone
    assert not defense.observe_response(USER, "/blog/mysql", 200, "text/html", SQL_ERROR, ["/blog/mysql"])
    assert defense.observe_response(USER, "/x", 500, "text/plain", b"Traceback (most recent call last):", [])
    assert not defense.observe_response(ATTACKER, "/f", 200, "application/octet-stream", SQL_ERROR, ["id=1'"])


def test_provoked_error_leaks_add_to_score(make_defense):
    defense, _ = make_defense()
    for i in range(3):
        defense.observe_response(ATTACKER, "/item", 200, "text/html", SQL_ERROR, [f"id={i}'"])
    assert defense.assess(ATTACKER, "/", BROWSER).flagged                # 3 x 35
    defense.observe_response(USER, "/x", 500, "text/html", SQL_ERROR, ["/x"])
    assert defense.assess(USER, "/", BROWSER).score == 0                  # not provoked


def test_scrub_can_be_disabled(make_defense):
    defense, _ = make_defense(scrub_backend_errors=False)
    assert not defense.observe_response(ATTACKER, "/item", 500, "text/html", SQL_ERROR, ["id=1'"])


@pytest.mark.parametrize("body,leaks", [
    (b"SQLSTATE[42000]: Syntax error or access violation", True),
    (b"ORA-01756: quoted string not properly terminated", True),
    (b"Unclosed quotation mark after the character string ''.", True),
    (b'sqlite3.OperationalError: near "\'": syntax error', True),
    (b"Welcome to our store. Order #1234 confirmed.", False),
])
def test_leak_signatures(body, leaks):
    assert leaks_backend_error("text/html", body) is leaks


# ── primitives, config ──────────────────────────────────────────────────────

@pytest.mark.parametrize("text,syntax", [
    ("q=1 or true", True), ("q=1)) or ((1", True), ("q=O'Neil", True), ("q=%3Cb%3E", True),
    ("q=laptop&page=2", False), ("q=salt and pepper", False), ("name=Anderson", False),
    ("q=5602-5601", False),
])
def test_injection_syntax(text, syntax):
    assert has_injection_syntax(text) is syntax


def test_compact_collapses_obfuscation():
    a = compact("q=' UNION SELECT password FROM users--")
    b = compact("q='/**/UnIoN/**/SeLeCt/**/password%20FROM%09users--")
    assert a == b


def test_lsh_puts_near_duplicates_in_a_shared_band():
    a = shingles(compact("q=-1 UNION SELECT 1 INTO @,@,@"))
    b = shingles(compact("q=-1 UNION SELxECT 1 INTO @,@,@"))
    assert similarity(b, a) >= 0.8
    assert set(lsh_keys(a)) & set(lsh_keys(b))
    assert lsh_keys(a) == lsh_keys(frozenset(a))                          # deterministic


def test_memory_store_is_bounded():
    store = MemoryAgentStore(max_clients=100, max_global=50)
    for i in range(1000):
        store.add_signal(f"2001:db8::{i:x}", "automation_client", 0.0, 600)
        store.remember_block(f"2001:db8::{i:x}", "x'", 0.0, 3600)
        store.global_put([f"k{i}"], "x'", 0.0, 3600)
    assert len(store._signals) == len(store._blocks) == 100
    assert len(store._global) == 50


def test_config_validation():
    assert agent_config_from_dict(None) == AgentDefenseConfig()
    with pytest.raises(ValueError):
        agent_config_from_dict({"declared_ai_agents": "maybe"})
    with pytest.raises(ValueError):
        agent_config_from_dict({"global_similarity": 0})
    with pytest.raises(ValueError):
        agent_config_from_dict({"no_such_key": 1})
    assert build_agent_defense({"enabled": False}) is None
    assert build_agent_defense({}).store.backend == "memory"
