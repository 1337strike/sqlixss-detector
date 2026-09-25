"""
tests/integration/test_waf_deployment.py
-----------------------------------------
Deployment behavior of the live WAF (not part of the paper's experiment):

  * waf_canonical.waf_views(): evasions found by driving the proxy with
    sqlmap tamper scripts (charunicodeencode, versioned/halfversioned
    keywords, space2comment).
  * WAF-only signature rules, with benign look-alikes that must pass.
  * block vs monitor mode, end-to-end over real HTTP (in-process servers).

Run:
    python -m pytest tests/integration/test_waf_deployment.py -v
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.baseline_normalized import canonicalize
from src.baseline_signature import (
    WAF_EXTRA_SQLI_PATTERNS, WAF_EXTRA_XSS_PATTERNS, SignatureBaseline,
)
from src.waf_canonical import waf_views


# ── evasion-aware views ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    # sqlmap charunicodeencode (IIS %u escapes): previously 0% detection
    ("%u0027%u0020OR%u0020%u0031%u003D%u0031--", "' or 1=1--"),
    # %u hidden under a percent-encoding layer
    ("%25u0027%2520OR%25201%3D1--", "' or 1=1--"),
    # MySQL executes versioned comments: keep the keyword
    ("/*!50000UNION*/ /*!SELECT*/ 1,2", "union select 1,2"),
    # sqlmap halfversionedmorekeywords nests them
    ("1)/*!/*!0AND*/5838=3487-- x", "1) and 5838=3487-- x"),
])
def test_views_expose_evasions(raw, expected):
    assert expected in waf_views(raw)


def test_space2comment_gets_spaced_view():
    views = waf_views("1/**/anD/**/9555=9555")
    assert "1and9555=9555" in views          # paper canonicalize() behavior
    assert "1 and 9555=9555" in views        # comments-as-spaces view


@pytest.mark.parametrize("text", ["hello world", "q=laptop+camera&page=2", "price=10%25", "O'Connor"])
def test_plain_input_single_view_matches_canonicalize(text):
    assert waf_views(text) == [canonicalize(text)]


def test_paper_canonicalize_unchanged_by_waf_layer():
    # the research pipeline must not decode %u or unwrap versioned comments
    assert "%u0027" in canonicalize("%u0027 OR 1=1")
    assert "union" not in canonicalize("/*!UNION*/")


# ── WAF-only signature rules ─────────────────────────────────────────────────

@pytest.fixture(scope="module")
def waf_sig():
    return SignatureBaseline(WAF_EXTRA_SQLI_PATTERNS, WAF_EXTRA_XSS_PATTERNS)


@pytest.mark.parametrize("payload,label", [
    ("exec master..xp_cmdshell 'ipconfig'", "sqli"),
    ("select @@version", "sqli"),
    ("admin'/*", "sqli"),
    ("1 and 2726=5917", "sqli"),
    ("iif(6584=3262,6584,1/0)", "sqli"),
    ("(case when 7733=9264 then 7733 else null end)", "sqli"),
    ("id=1' or '1'='1", "sqli"),
    ("<x onxxx=1", "xss"),
    ("alert`1`", "xss"),
    ("+adw-script+ad4-", "xss"),
])
def test_waf_rules_catch(waf_sig, payload, label):
    assert waf_sig.predict([payload]) == [label]


@pytest.mark.parametrize("text", [
    "email me @ home", "see /* notes */", "<b>bold</b>", "i'll alert you",
    "in case when needed", "size 2019-2020", "salt and pepper", "tom and 3 friends",
    "pref=color or size", "theme=dark; lang=en",
])
def test_waf_rules_benign(waf_sig, text):
    assert waf_sig.predict([text]) == ["benign"]


def test_research_baseline_has_no_waf_rules():
    base = SignatureBaseline()
    for p in ("select @@version", "<x onxxx=1", "1 and 2726=5917"):
        assert base.predict([p]) == ["benign"]


# ── block vs monitor mode over real HTTP ─────────────────────────────────────

def _run_mode(mode: str, tmp_path: Path) -> dict[str, int]:
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    from src.waf_proxy import create_app, load_config

    async def scenario():
        backend = web.Application()
        backend.router.add_route("*", "/{tail:.*}", lambda r: web.Response(text="backend-ok"))
        backend_server = TestServer(backend)
        await backend_server.start_server()

        config = load_config()
        config.update(mode=mode, backend_url=str(backend_server.make_url("")).rstrip("/"),
                      log_path=str(tmp_path / f"{mode}.log"))
        config["rate_limit"] = {**config["rate_limit"], "backend": "memory"}
        app, _ = create_app(config)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            codes = {}
            for name, path, headers in [
                ("benign", "/search?q=laptop", {}),
                ("sqli", "/search?q=%27%20OR%201%3D1%20--", {}),
                ("xss", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", {}),
                ("scanner", "/search?q=1", {"User-Agent": "sqlmap/1.8"}),
            ]:
                resp = await client.get(path, headers=headers)
                codes[name] = resp.status
            return codes
        finally:
            await client.close()
            await backend_server.close()

    return asyncio.run(scenario())


def test_block_mode_blocks(tmp_path):
    codes = _run_mode("block", tmp_path)
    assert codes == {"benign": 200, "sqli": 403, "xss": 403, "scanner": 403}


def test_monitor_mode_forwards_and_logs(tmp_path):
    codes = _run_mode("monitor", tmp_path)
    assert codes == {"benign": 200, "sqli": 200, "xss": 200, "scanner": 200}
    log = (tmp_path / "monitor.log").read_text()
    assert log.count('"decision": "would_block"') >= 2
    assert '"decision": "would_block_recon"' in log
    assert '"decision": "blocked' not in log


def test_invalid_mode_rejected(tmp_path):
    import yaml
    from src.waf_proxy import DEFAULT_CONFIG_PATH, load_config
    cfg = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text())
    cfg["mode"] = "detect"
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(SystemExit):
        load_config(p)
