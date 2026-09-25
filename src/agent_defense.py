"""
agent_defense.py
----------------
Defense against AI-driven attack agents -- LLM orchestrators such as
HexStrike AI (MCP server driving sqlmap, nuclei, ffuf, dalfox, ... from an
LLM), PentestGPT, or a custom agent loop on top of any model.

What makes an AI agent different from a plain scanner
-----------------------------------------------------
recon_detection.py already catches the tools' DEFAULT fingerprints (sqlmap/
nuclei/HexStrike User-Agents, .git/.env probing, spoofed X-Forwarded-For).
An LLM agent defeats every one of those in its next step: it reads the 403,
reasons "WAF detected", and retries with a browser User-Agent, a new
encoding, a new tamper script. Its core loop is

    send payload -> observe response -> mutate -> resend

which turns every WAF decision and every backend error message into an
oracle. The defenses below target that loop, not any one tool's signature:

  1. PROBATION (per client). Once a client has sent
     `probation_min_distinct_blocks` DISTINCT blocked payloads within
     `probation_seconds`, it has demonstrated attack intent and the ML
     model stops being the only gate for it:
       - any query/body value or URL path containing injection SYNTAX
         (quotes, comment markers, statement separators, tags, SQL/JS
         keywords, boolean tautology shapes) is refused outright, and
       - any input similar (character 3-gram Jaccard/containment) to one of
         its earlier blocked payloads is refused.
     A mutation search that finally finds a model bypass still carries
     injection syntax -- the agent's search space collapses to inputs that
     cannot inject. A normal user never gets here (0 refusals on the 72,000
     CSIC 2010 normal requests, so 0 clients on probation).

  2. GLOBAL PAYLOAD FAMILIES (across clients). Agents rotate source IPs
     (proxies, cloud egress) precisely because per-IP state -- including
     the rate limiter -- resets on a new IP. Every blocked payload is
     indexed by MinHash-LSH; an input with injection syntax that is
     >= `global_similarity` similar to a payload blocked from ANY client in
     the last `global_memory_seconds` is refused. The model bypass one IP
     discovers by mutating is dead on arrival from the next IP.

  3. CLIENT SUSPICION SCORE (per client, sliding `window_seconds`).
     Weighted signals, blocked once the sum reaches `score_threshold`:
       honeypot          100  request to a decoy path (advertise them in
                              robots.txt `Disallow:` -- compliant crawlers
                              never fetch them, agents harvesting robots.txt
                              for targets always do)
       enumeration       100  >= `enumeration_distinct_error_paths`
                              distinct paths answered 401/403/404/405
                              (forced browsing / wordlist fuzzing, any UA)
       error_leak         35  the client's input with injection syntax made
                              the backend emit a DB error / stack trace
       probation_block    25  a probation refusal (above)
       declared_ai_agent  30  self-declared AI agent/crawler UA (GPTBot,
                              ClaudeBot, PerplexityBot, ...) -- or refused
                              outright with `declared_ai_agents: block`
       spoofed_browser_ua 30  claims Chrome/Firefox/Safari but sends no
                              Accept-Language (every real browser does;
                              requests/httpx/aiohttp with a pasted browser
                              UA -- the agent's first evasion -- do not)
       automation_client  20  HTTP-library UA (httpx, aiohttp, Go,
                              HeadlessChrome, ...)
       missing_sec_fetch  15  opt-in: browser UA without Sec-Fetch-* on an
                              HTTPS-only site
     Client-property signals (the last four) count once per window, and
     together sum to 95 < 100: a fingerprint alone never blocks anyone, it
     only shortens the path to a block for a client that also misbehaves.

  4. ERROR-ORACLE REMOVAL (responses). Error-based SQLi and most agent
     reasoning steps feed on backend error text ("You have an error in your
     SQL syntax", SQLSTATE[...], ORA-01756, Python tracebacks). A backend
     response containing one is replaced with a generic 500 when the status
     is >= 500, or when the request that produced it carried injection
     syntax (so a blog post quoting a MySQL error is never touched).

Every refusal from this module is the WAF's uniform 403, so none of the
above can itself be probed as an oracle.

State lives in a MemoryAgentStore (single process) or a RedisAgentStore
(shared across gunicorn workers/replicas, picked automatically when the
rate limiter is Redis-backed -- same rule as waf_stats.py).

This raises the cost of an automated, adaptive attack; it does not make a
WAF "immune". A patient human who never trips a detector, never errors the
backend and never probes a decoy is not affected by any of it.
"""

from __future__ import annotations

import random
import re
import time
import uuid
import zlib
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable

from src.baseline_normalized import canonicalize


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

SIGNAL_POINTS = {
    "honeypot": 100,
    "enumeration": 100,
    "error_leak": 35,
    "probation_block": 25,
    "declared_ai_agent": 30,
    "spoofed_browser_ua": 30,
    "automation_client": 20,
    "missing_sec_fetch": 15,
}
# Properties of the client rather than events: counted at most once per
# window, so they can never add up to a block on their own.
_ONCE_PER_WINDOW = {"enumeration", "declared_ai_agent", "spoofed_browser_ua",
                    "automation_client", "missing_sec_fetch"}


@dataclass
class AgentDefenseConfig:
    enabled: bool = True
    window_seconds: int = 600
    score_threshold: int = 100
    honeypot_paths: list[str] = field(default_factory=list)
    declared_ai_agents: str = "flag"            # "allow" | "flag" | "block"
    expect_sec_fetch: bool = False
    probation_min_distinct_blocks: int = 3
    probation_seconds: int = 3600
    probation_similarity: float = 0.5
    global_similarity: float = 0.8
    global_memory_seconds: int = 3600
    enumeration_distinct_error_paths: int = 30
    scrub_backend_errors: bool = True
    deny_notice: str | None = None

    def __post_init__(self):
        if self.declared_ai_agents not in ("allow", "flag", "block"):
            raise ValueError("declared_ai_agents must be 'allow', 'flag' or 'block'")
        if self.window_seconds <= 0 or self.probation_seconds <= 0 or self.global_memory_seconds <= 0:
            raise ValueError("window/probation/global memory durations must be > 0")
        if self.score_threshold < 1 or self.probation_min_distinct_blocks < 1:
            raise ValueError("score_threshold and probation_min_distinct_blocks must be >= 1")
        for name in ("probation_similarity", "global_similarity"):
            if not 0.0 < getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be in (0, 1]")
        if self.enumeration_distinct_error_paths < 1:
            raise ValueError("enumeration_distinct_error_paths must be >= 1")
        self.honeypot_paths = [p.lower() for p in self.honeypot_paths if p]


def agent_config_from_dict(section: dict | None) -> AgentDefenseConfig:
    known = AgentDefenseConfig.__dataclass_fields__
    section = section or {}
    unknown = set(section) - set(known)
    if unknown:
        raise ValueError(f"unknown agent_defense keys: {sorted(unknown)}")
    return AgentDefenseConfig(**section)


# --------------------------------------------------------------------------
# Client fingerprint
# --------------------------------------------------------------------------

# Self-declared AI crawlers / agents / assistants (documented UA tokens).
_DECLARED_AI_RE = re.compile(
    r"GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai"
    r"|PerplexityBot|Perplexity-User|CCBot|Bytespider|meta-externalagent|meta-externalfetcher"
    r"|cohere-ai|Amazonbot|MistralAI-User|DuckAssistBot|YouBot|AI2Bot|Diffbot|Google-CloudVertexBot",
    re.IGNORECASE,
)
# HTTP libraries and headless browsers agents drive (bare curl/python-requests
# are already scored by recon_detection).
_AUTOMATION_UA_RE = re.compile(
    r"python-httpx|aiohttp|python-urllib|Go-http-client|node-fetch|axios/|undici|okhttp"
    r"|libwww-perl|^Wget/|^Java/|Apache-HttpClient|Scrapy|HeadlessChrome|PhantomJS|Playwright|Puppeteer",
    re.IGNORECASE,
)
_BROWSER_CLAIM_RE = re.compile(r"^Mozilla/5\.0 .*(?:Chrome|Firefox|Safari|Edg|OPR)/\d")
_SEC_FETCH_BROWSER_RE = re.compile(r"(?:Chrome|Firefox|Edg)/\d")


def fingerprint_signals(headers, expect_sec_fetch: bool = False) -> list[str]:
    ua = headers.get("User-Agent", "")
    if _DECLARED_AI_RE.search(ua):
        return ["declared_ai_agent"]
    if _AUTOMATION_UA_RE.search(ua):
        return ["automation_client"]
    if _BROWSER_CLAIM_RE.search(ua):
        if not headers.get("Accept-Language"):
            return ["spoofed_browser_ua"]
        if expect_sec_fetch and _SEC_FETCH_BROWSER_RE.search(ua) and "Sec-Fetch-Mode" not in headers:
            return ["missing_sec_fetch"]
    return []


# --------------------------------------------------------------------------
# Payload normalization and similarity
# --------------------------------------------------------------------------

_MAX_TEXT = 512
_PARAM_PAIR_RE = re.compile(r"^[\w.\-\[\]]{1,64}=")
_WS_RE = re.compile(r"\s+")

# Injection syntax, matched on canonicalized values (decoded, comments
# removed, lower-cased). Deliberately broad: it is only ever enforced on
# clients on probation, and used to gate the (cross-client) global check.
INJECTION_SYNTAX_RE = re.compile(
    r"['\"`<>;\\]|--|/\*|\*/|#|\|\||%00|\x00"
    r"|\b(?:union|select|insert|update|delete|drop|truncate|exec|execute|declare|cast|convert|char|chr"
    r"|concat|sleep|benchmark|waitfor|pg_sleep|extractvalue|updatexml|load_file|outfile|dumpfile"
    r"|information_schema|sysobjects|xp_cmdshell|script|javascript|vbscript|onerror|onload|onmouseover"
    r"|onfocus|alert|prompt|confirm|eval|document|window|iframe|svg|srcdoc|fromcharcode)\b"
    r"|\b(?:and|or|xor|not|having)\b\s*\(?\s*[\w'\"(]+\s*(?:=|<|>|!=|\blike\b|\bbetween\b|\bin\b|\bis\b)"
    r"|\b(?:and|or|xor|having)\s+(?:true|false|null|not)\b|\)\s*(?:and|or|xor)\b|\b(?:rlike|regexp)\b"
)


def payload_values(text: str) -> str:
    """Query/form/JSON-pair text reduced to its values ("q=x&page=2" ->
    "x 2"): parameter names are shared by every request to an endpoint and
    would make unrelated inputs look similar."""
    text = text[: _MAX_TEXT * 2]
    if _PARAM_PAIR_RE.match(text):
        text = " ".join(part.split("=", 1)[1] if "=" in part else part for part in text.split("&"))
    return canonicalize(text)


def has_injection_syntax(text: str) -> bool:
    return bool(INJECTION_SYNTAX_RE.search(payload_values(text)))


def compact(text: str) -> str:
    """Similarity form: canonicalized values with ALL whitespace removed, so
    whitespace/comment/case/encoding shuffles of one payload collapse."""
    return _WS_RE.sub("", payload_values(text))[:_MAX_TEXT]


def shingles(norm: str, n: int = 3) -> frozenset[str]:
    if len(norm) <= n:
        return frozenset([norm]) if norm else frozenset()
    return frozenset(norm[i:i + n] for i in range(len(norm) - n + 1))


_MIN_CONTAIN_GRAMS = 5
_CONTAINMENT_THRESHOLD = 0.9


def similarity(new: frozenset[str], old: frozenset[str]) -> float:
    """max(Jaccard, containment of the OLD blocked payload in the new input).
    Containment catches padding: a blocked payload buried in filler."""
    if not new or not old:
        return 0.0
    inter = len(new & old)
    jaccard = inter / len(new | old)
    if len(old) >= _MIN_CONTAIN_GRAMS and inter / len(old) >= _CONTAINMENT_THRESHOLD:
        return max(jaccard, inter / len(old))
    return jaccard


# MinHash-LSH: 8 bands x 4 rows. A pair at Jaccard 0.8 shares a band with
# probability 1 - (1 - 0.8^4)^8 ~= 0.985; candidates are then confirmed with
# the exact similarity() above. Seeds are fixed so every worker process
# computes the same keys (Python's hash() is salted per process).
_BANDS, _ROWS = 8, 4
_PRIME = (1 << 61) - 1
_rng = random.Random(0x5EED_A6E7)
_PERMS = [(_rng.randrange(1, _PRIME), _rng.randrange(0, _PRIME)) for _ in range(_BANDS * _ROWS)]


def lsh_keys(grams: frozenset[str]) -> list[str]:
    if not grams:
        return []
    hashes = [zlib.crc32(g.encode("utf-8", "surrogatepass")) for g in grams]
    sig = [min((a * h + b) % _PRIME for h in hashes) for a, b in _PERMS]
    return [f"{band}:{zlib.crc32(repr(sig[band * _ROWS:(band + 1) * _ROWS]).encode()):08x}"
            for band in range(_BANDS)]


# --------------------------------------------------------------------------
# Backend error leakage
# --------------------------------------------------------------------------

ERROR_LEAK_RE = re.compile(
    r"You have an error in your SQL syntax|check the manual that (?:corresponds|fits) to your (?:MySQL|MariaDB)"
    r"|SQLSTATE\[|\bORA-\d{5}\b|\bPLS-\d{5}\b|pg_query\(\)|pg_exec\(\)|PG::[A-Za-z]+Error|psycopg2?\.errors"
    r"|unterminated quoted string at or near|syntax error at or near \""
    r"|Unclosed quotation mark after the character string|Incorrect syntax near '"
    r"|Microsoft OLE DB Provider for|\[ODBC SQL Server Driver\]|System\.Data\.SqlClient\.SqlException"
    r"|java\.sql\.SQLException|org\.hibernate\.[A-Za-z.]*Exception|com\.mysql\.jdbc"
    r"|sqlite3\.OperationalError|SQLite3::SQLException|SQLITE_ERROR|near \"[^\"]{1,40}\": syntax error"
    r"|Warning: (?:mysql|mysqli|pg|oci|sqlsrv|mssql|sqlite)_[a-z_]+\(|quoted string not properly terminated"
    r"|Syntax error in string in query expression|supplied argument is not a valid MySQL"
    r"|Npgsql\.|MySqlException|Traceback \(most recent call last\)",
    re.IGNORECASE,
)
_TEXTUAL_CT = ("text/", "json", "xml", "javascript")
_MAX_SCAN_BYTES = 256 * 1024


def leaks_backend_error(content_type: str, body: bytes) -> bool:
    if not body or not any(t in content_type.lower() for t in _TEXTUAL_CT):
        return False
    return bool(ERROR_LEAK_RE.search(body[:_MAX_SCAN_BYTES].decode("utf-8", errors="replace")))


# --------------------------------------------------------------------------
# State stores
# --------------------------------------------------------------------------

_MAX_BLOCKS_PER_IP = 32


def _touch(table: OrderedDict, key, factory, cap: int):
    value = table.get(key)
    if value is None:
        value = table[key] = factory()
        if len(table) > cap:
            table.popitem(last=False)
    else:
        table.move_to_end(key)
    return value


class MemoryAgentStore:
    """Per-process state, LRU-capped so rotating source addresses (IPv6
    gives an attacker millions) cannot grow it without bound."""

    backend = "memory"

    def __init__(self, max_clients: int = 100_000, max_global: int = 50_000):
        self.max_clients = max_clients
        self.max_global = max_global
        self._signals: OrderedDict[str, dict[str, float]] = OrderedDict()
        self._blocks: OrderedDict[str, deque] = OrderedDict()
        self._errors: OrderedDict[str, dict[str, float]] = OrderedDict()
        self._global: OrderedDict[str, tuple[float, str]] = OrderedDict()

    def add_signal(self, ip: str, member: str, now: float, window: int) -> None:
        _touch(self._signals, ip, dict, self.max_clients)[member] = now

    def snapshot(self, ip: str, now: float, window: int, probation_seconds: int) -> tuple[list[str], list[str]]:
        signals = self._signals.get(ip, {})
        for member in [m for m, ts in signals.items() if ts < now - window]:
            del signals[member]
        blocks = [text for ts, text in self._blocks.get(ip, ()) if ts >= now - probation_seconds]
        return list(signals), blocks

    def remember_block(self, ip: str, text: str, now: float, probation_seconds: int) -> None:
        _touch(self._blocks, ip, lambda: deque(maxlen=_MAX_BLOCKS_PER_IP), self.max_clients).append((now, text))

    def note_error_path(self, ip: str, path: str, now: float, window: int) -> int:
        paths = _touch(self._errors, ip, dict, self.max_clients)
        paths[path] = now
        for p in [p for p, ts in paths.items() if ts < now - window]:
            del paths[p]
        return len(paths)

    def global_put(self, keys: list[str], text: str, now: float, ttl: int) -> None:
        for key in keys:
            self._global[key] = (now + ttl, text)
            self._global.move_to_end(key)
        while len(self._global) > self.max_global:
            self._global.popitem(last=False)

    def global_get(self, keys: list[str], now: float) -> list[str]:
        found = []
        for key in keys:
            entry = self._global.get(key)
            if entry is not None and entry[0] >= now:
                found.append(entry[1])
        return found


class RedisAgentStore:
    """Same state in Redis, so every gunicorn worker and replica sees one
    client's history (an agent spraying requests across workers is still
    one client). Keys expire on their own; nothing needs sweeping."""

    backend = "redis"

    def __init__(self, redis_client, key_prefix: str = "waf:"):
        self.redis = redis_client
        self.prefix = f"{key_prefix}agent:"

    def add_signal(self, ip: str, member: str, now: float, window: int) -> None:
        key = f"{self.prefix}sig:{ip}"
        pipe = self.redis.pipeline()
        pipe.zadd(key, {member: now})
        pipe.expire(key, window)
        pipe.execute()

    def snapshot(self, ip: str, now: float, window: int, probation_seconds: int) -> tuple[list[str], list[str]]:
        sig_key, blk_key = f"{self.prefix}sig:{ip}", f"{self.prefix}blk:{ip}"
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(sig_key, "-inf", now - window)
        pipe.zrange(sig_key, 0, -1)
        pipe.lrange(blk_key, 0, -1)
        _, members, raw_blocks = pipe.execute()
        blocks = []
        for raw in raw_blocks:
            ts, _, text = raw.decode("utf-8", "replace").partition("|")
            if float(ts) >= now - probation_seconds:
                blocks.append(text)
        return [m.decode("utf-8", "replace") for m in members], blocks

    def remember_block(self, ip: str, text: str, now: float, probation_seconds: int) -> None:
        key = f"{self.prefix}blk:{ip}"
        pipe = self.redis.pipeline()
        pipe.lpush(key, f"{now}|{text}")
        pipe.ltrim(key, 0, _MAX_BLOCKS_PER_IP - 1)
        pipe.expire(key, probation_seconds)
        pipe.execute()

    def note_error_path(self, ip: str, path: str, now: float, window: int) -> int:
        key = f"{self.prefix}err:{ip}"
        pipe = self.redis.pipeline()
        pipe.zadd(key, {path: now})
        pipe.zremrangebyscore(key, "-inf", now - window)
        pipe.zcard(key)
        pipe.expire(key, window)
        return int(pipe.execute()[2])

    def global_put(self, keys: list[str], text: str, now: float, ttl: int) -> None:
        pipe = self.redis.pipeline()
        for key in keys:
            pipe.set(f"{self.prefix}lsh:{key}", f"{now + ttl}|{text}", ex=ttl)
        pipe.execute()

    def global_get(self, keys: list[str], now: float) -> list[str]:
        if not keys:
            return []
        found = []
        for raw in self.redis.mget([f"{self.prefix}lsh:{k}" for k in keys]):
            if raw is None:
                continue
            expires, _, text = raw.decode("utf-8", "replace").partition("|")
            if float(expires) >= now:
                found.append(text)
        return found


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------

@dataclass
class AgentAssessment:
    flagged: bool
    score: int
    reasons: list[str]
    blocked_texts: list[str]          # this client's remembered blocked payloads
    on_probation: bool


class AgentDefense:
    def __init__(self, config: AgentDefenseConfig, store, clock: Callable[[], float] = time.time):
        self.config = config
        self.store = store
        self.clock = clock

    def _add(self, ip: str, signal: str, now: float) -> None:
        member = signal if signal in _ONCE_PER_WINDOW else f"{signal}:{uuid.uuid4().hex[:12]}"
        self.store.add_signal(ip, member, now, self.config.window_seconds)

    def is_honeypot(self, path: str) -> bool:
        path = path.lower()
        return any(path.startswith(p) for p in self.config.honeypot_paths)

    def assess(self, ip: str, path: str, headers) -> AgentAssessment:
        """Per-request client assessment, before content inspection. Records
        this request's fingerprint/honeypot signals, then scores the client."""
        cfg = self.config
        now = self.clock()
        new = fingerprint_signals(headers, cfg.expect_sec_fetch)
        if "declared_ai_agent" in new and cfg.declared_ai_agents == "allow":
            new.remove("declared_ai_agent")
        if self.is_honeypot(path):
            new.append("honeypot")
        for signal in new:
            self._add(ip, signal, now)

        members, blocks = self.store.snapshot(ip, now, cfg.window_seconds, cfg.probation_seconds)
        names = [m.split(":", 1)[0] for m in members]
        score = sum(SIGNAL_POINTS.get(n, 0) for n in names)
        hard_block = "declared_ai_agent" in new and cfg.declared_ai_agents == "block"
        flagged = score >= cfg.score_threshold or hard_block
        reasons = [f"agent_score={score}"] + sorted(set(names))
        if hard_block:
            reasons.append("declared_ai_agent_blocked")
        on_probation = len(set(blocks)) >= cfg.probation_min_distinct_blocks
        return AgentAssessment(flagged, score, reasons, blocks, on_probation)

    def check_content(self, ip: str, assessment: AgentAssessment,
                      strict_texts: list[str], other_texts: list[str]) -> tuple[list[str], str | None]:
        """Called for input the ML ensemble and signatures let through.
        strict_texts: query/body/path (probation syntax policy applies);
        other_texts: header values (similarity only -- User-Agents contain
        ';' and parentheses by design). Returns (refusal reasons, offending
        text), or ([], None)."""
        cfg = self.config
        now = self.clock()
        if assessment.on_probation:
            old = [shingles(t) for t in set(assessment.blocked_texts)]
            for kind, texts in (("strict", strict_texts), ("other", other_texts)):
                for text in texts:
                    if not text:
                        continue
                    if kind == "strict" and has_injection_syntax(text):
                        self._add(ip, "probation_block", now)
                        return ["probation_injection_syntax"], text
                    grams = shingles(compact(text))
                    if any(similarity(grams, o) >= cfg.probation_similarity for o in old):
                        self._add(ip, "probation_block", now)
                        return ["probation_similar_to_blocked"], text

        for text in strict_texts + other_texts:
            if not text or not has_injection_syntax(text):
                continue
            grams = shingles(compact(text))
            for candidate in set(self.store.global_get(lsh_keys(grams), now)):
                if similarity(grams, shingles(candidate)) >= cfg.global_similarity:
                    return ["global_payload_family"], text
        return [], None

    def remember_block(self, ip: str, text: str | None) -> None:
        """Feeds a refused payload into the client's probation memory and,
        if it carries injection syntax, the cross-client LSH index."""
        if not text:
            return
        norm = compact(text)
        if not norm:
            return
        cfg = self.config
        now = self.clock()
        self.store.remember_block(ip, norm, now, cfg.probation_seconds)
        if has_injection_syntax(text):
            self.store.global_put(lsh_keys(shingles(norm)), norm, now, cfg.global_memory_seconds)

    def observe_response(self, ip: str, path: str, status: int, content_type: str, body: bytes,
                         request_texts: list[str]) -> bool:
        """Records enumeration/error-leak signals from a backend response.
        Returns True if the response must be replaced with a generic 500."""
        cfg = self.config
        now = self.clock()
        if status in (401, 403, 404, 405):
            if self.store.note_error_path(ip, path[:200], now, cfg.window_seconds) >= cfg.enumeration_distinct_error_paths:
                self._add(ip, "enumeration", now)
        if not cfg.scrub_backend_errors or not leaks_backend_error(content_type, body):
            return False
        provoked = any(t and has_injection_syntax(t) for t in request_texts)
        if provoked:
            self._add(ip, "error_leak", now)
        return provoked or status >= 500


def build_agent_defense(section: dict | None, rate_limiter=None) -> AgentDefense | None:
    """None when disabled. Shares the rate limiter's Redis connection and key
    prefix when it has one (multi-worker deployments), else in-memory."""
    config = agent_config_from_dict(section)
    if not config.enabled:
        return None
    redis_client = getattr(rate_limiter, "redis", None)
    if redis_client is not None:
        store = RedisAgentStore(redis_client, key_prefix=getattr(rate_limiter, "prefix", "waf:"))
    else:
        store = MemoryAgentStore()
    return AgentDefense(config, store)
