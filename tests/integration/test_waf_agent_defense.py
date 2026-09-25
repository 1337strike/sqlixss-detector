"""
tests/integration/test_waf_agent_defense.py
-------------------------------------------
The AI-agent defense layer end-to-end: a real WafProxy over HTTP
(in-process servers) in front of a stub backend, with client IPs presented
via X-Forwarded-For from the trusted loopback proxy. Scenarios mirror an
LLM-driven agent (HexStrike AI-style): mutate-until-bypass, IP rotation,
error-based probing, decoy harvesting, forced browsing.

Run:
    python -m pytest tests/integration/test_waf_agent_defense.py -v
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from src.waf_proxy import create_app, load_config

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
BROWSER = {"User-Agent": CHROME, "Accept-Language": "en-US,en;q=0.9"}
SQL_ERROR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"


def q(value: str) -> str:
    return "/search?q=" + urllib.parse.quote(value, safe="")


async def _backend(request: web.Request) -> web.Response:
    if request.path.startswith("/missing/"):
        return web.Response(status=404, text="not found")
    if request.path == "/blog/mysql-errors":
        return web.Response(text=f"Common error: {SQL_ERROR}", content_type="text/html")
    if "'" in request.query.get("q", ""):          # a vulnerable app leaking its DB error
        return web.Response(text=f"<b>Warning</b>: {SQL_ERROR} near ''' at line 1", content_type="text/html")
    return web.Response(text="backend-ok")


def run(tmp_path: Path, scenario, mode: str = "block", **agent_overrides):
    """Runs `scenario(get, waf)`; get(path, ip, headers) -> (status, text)."""
    async def main():
        backend = web.Application()
        backend.router.add_route("*", "/{tail:.*}", _backend)
        bs = TestServer(backend)
        await bs.start_server()
        config = load_config()
        config.update(mode=mode, backend_url=str(bs.make_url("")).rstrip("/"), trusted_proxies=["127.0.0.1"],
                      log_path=str(tmp_path / "agent.log"))
        config["rate_limit"] = {**config["rate_limit"], "backend": "memory"}
        config["agent_defense"] = {**config["agent_defense"], **agent_overrides}
        app, waf = create_app(config)
        waf.logger.also_print = False
        client = TestClient(TestServer(app))
        await client.start_server()

        async def get(path, ip, headers=None):
            merged = {**BROWSER, **(headers or {}), "X-Forwarded-For": ip}
            resp = await client.get(path, headers={k: v for k, v in merged.items() if v is not None})
            return resp.status, await resp.text()

        try:
            return await scenario(get, waf)
        finally:
            await client.close()
            await bs.close()

    return asyncio.run(main())


def decisions(tmp_path: Path) -> list[dict]:
    return [json.loads(line) for line in (tmp_path / "agent.log").read_text().splitlines()]


def test_mutation_that_bypasses_the_model_is_refused_on_probation(tmp_path):
    """`1 AnD 2>1` (boolean inference probe) passes the ML ensemble. From a
    clean client it is forwarded; from a client that already had three
    distinct payloads refused, it is refused -- before any ban."""
    async def scenario(get, waf):
        clean = await get(q("1 AnD 2>1"), "198.51.100.1")
        attacks = [await get(q(p), "203.0.113.5")
                   for p in ("1' AND 1=1-- ", "<svg onload=alert(1)>", "' union select null,null-- ")]
        probe = await get(q("1 AnD 2>1"), "203.0.113.5")
        benign = await get(q("laptop"), "203.0.113.5")
        return clean[0], [a[0] for a in attacks], probe[0], benign[0], waf.rate_limiter.is_blocked("203.0.113.5")

    clean, attacks, probe, benign, banned = run(tmp_path, scenario)
    assert clean == 200
    assert attacks == [403, 403, 403]
    assert probe == 403 and not banned
    assert benign == 200                                  # probation is not a ban
    refusal = [d for d in decisions(tmp_path) if d["decision"] == "blocked_agent_content"]
    assert refusal and refusal[0]["triggered_by"] == ["probation_injection_syntax"]


def test_ip_rotation_does_not_reset_payload_memory(tmp_path):
    """A model bypass found by mutating (`SELxECT`) is refused from a fresh
    IP once the original payload was blocked from any IP."""
    original, mutation = "-1 UNION SELECT 1 INTO @,@,@", "-1 UNION SELxECT 1 INTO @,@,@"

    async def scenario(get, waf):
        before = await get(q(mutation), "198.51.100.2")
        blocked = await get(q(original), "203.0.113.6")
        rotated = await get(q(mutation), "203.0.113.200")
        return before[0], blocked[0], rotated[0]

    assert run(tmp_path, scenario) == (200, 403, 403)
    assert any(d["triggered_by"] == ["global_payload_family"] for d in decisions(tmp_path))


def test_honeypot_blocks_the_client_not_others(tmp_path):
    async def scenario(get, waf):
        trap = await get("/admin-backup/db.sql", "203.0.113.7")
        after = await get(q("laptop"), "203.0.113.7")
        other = await get(q("laptop"), "198.51.100.3")
        return trap[0], after[0], other[0]

    assert run(tmp_path, scenario) == (403, 403, 200)


def test_error_oracle_removed(tmp_path):
    """`O'Neil` passes the ensemble and makes the vulnerable backend emit its
    SQL error: the client gets a generic 500 without the error text. A page
    that merely quotes the error is served untouched."""
    async def scenario(get, waf):
        probe = await get(q("O'Neil"), "203.0.113.8")
        blog = await get("/blog/mysql-errors", "198.51.100.4")
        return probe, blog

    probe, blog = run(tmp_path, scenario)
    assert probe[0] == 500 and "SQL syntax" not in probe[1]
    assert blog[0] == 200 and SQL_ERROR in blog[1]


def test_error_based_probing_gets_the_client_blocked(tmp_path):
    async def scenario(get, waf):
        statuses = [(await get(q(f"x{i}'"), "203.0.113.9"))[0] for i in range(3)]
        return statuses, (await get(q("laptop"), "203.0.113.9"))[0]

    statuses, after = run(tmp_path, scenario)
    assert statuses == [500, 500, 500] and after == 403


def test_forced_browsing_gets_the_client_blocked(tmp_path):
    """Wordlist fuzzing with a clean browser UA (the agent already swapped
    out gobuster's default): 30 distinct 404s, then refused."""
    async def scenario(get, waf):
        fuzz = [(await get(f"/missing/{i}", "203.0.113.10"))[0] for i in range(30)]
        return fuzz, (await get(q("laptop"), "203.0.113.10"))[0]

    fuzz, after = run(tmp_path, scenario)
    assert fuzz == [404] * 30 and after == 403


def test_scripted_client_with_pasted_browser_ua_is_scored_not_blocked(tmp_path):
    async def scenario(get, waf):
        statuses = [(await get(q(f"item {i}"), "198.51.100.5", {"Accept-Language": None}))[0] for i in range(50)]
        return statuses, waf.agent.assess("198.51.100.5", "/", {"User-Agent": CHROME})

    statuses, assessment = run(tmp_path, scenario)
    assert statuses == [200] * 50
    assert "spoofed_browser_ua" in assessment.reasons and not assessment.flagged


def test_agent_refusals_look_like_every_other_refusal(tmp_path):
    notice = "Automated testing of this host is not authorized."

    async def scenario(get, waf):
        payload = await get(q("' OR 'x'='x"), "203.0.113.11")
        trap = await get("/admin-backup/", "203.0.113.12")
        return [(status, sorted(json.loads(text))) for status, text in (payload, trap)], json.loads(trap[1])

    refusals, body = run(tmp_path, scenario, deny_notice=notice)
    assert refusals[0] == refusals[1] == (403, ["error", "notice", "request_id"])
    assert body["notice"] == notice


def test_monitor_mode_only_logs(tmp_path):
    async def scenario(get, waf):
        trap = await get("/admin-backup/", "203.0.113.13")
        probe = await get(q("O'Neil"), "203.0.113.13")
        return trap[0], probe

    trap, probe = run(tmp_path, scenario, mode="monitor")
    assert trap == 200
    assert probe[0] == 200 and "SQL syntax" in probe[1]
    kinds = {d["decision"] for d in decisions(tmp_path)}
    assert {"would_block_agent", "would_scrub_error_leak"} <= kinds
    assert not any(k.startswith("blocked") for k in kinds)


def test_agent_defense_can_be_disabled(tmp_path):
    async def scenario(get, waf):
        return waf.agent, (await get("/admin-backup/", "203.0.113.14"))[0]

    assert run(tmp_path, scenario, enabled=False) == (None, 200)
