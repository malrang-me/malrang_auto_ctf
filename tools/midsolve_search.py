#!/usr/bin/env python3
"""midsolve_search.py — bounded, persisted search wrapper for mid-solve learning.

Designed to be the ONLY search entrypoint agents call when they hit an unknown
CVE / software / technique mid-solve. Replaces ad-hoc WebSearch by:

  1. kb.db (offline) FIRST — covers techniques + 65k external entries
  2. WebSearch / WebFetch ONLY as last resort (bounded, capped, deduped)
  3. Every result auto-saved to knowledge/writeup_staging/midsolve_*.json
     with a `used_in_challenge` tag so post_solve can absorb successful ones

Usage:
    python tools/midsolve_search.py cve CVE-2021-44228 --challenge logj
    python tools/midsolve_search.py software "imagemagick 7.0.10" --challenge img
    python tools/midsolve_search.py technique "ecdsa nonce reuse" --challenge sig

Discipline rules (CLAUDE.md / agent rules):
  - Per-challenge call cap: 4 (enforced via .midsolve_calls file)
  - Per-query dedup: same query → cached result, no re-fetch
  - Web fetch only if --web flag set AND offline returned 0 results
  - Output truncated to 8k characters total
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB_PATH = ROOT / "knowledge" / "kb.db"
SPEEDRUN_PATH = ROOT / "knowledge" / "speedrun.db"
STAGING_DIR = ROOT / "knowledge" / "writeup_staging"
CHALLENGES_DIR = ROOT / "challenges"

# Match the leading "[RepoName]" prefix used by knowledge.py when indexing
# external_techniques (e.g. "[PayloadsAllTheThings] Account Takeover\..." or
# "[HackTricks] generic-methodologies-and-resources\..."). Used to surface the
# real source repo in formatted output instead of a generic "[external]".
_EXT_REPO_RE = re.compile(r"^\[([^\]]+)\]\s*(.*)$")


def _split_external_repo(source_path: str) -> tuple[str, str]:
    """Return (repo_label, remainder) for an external_techniques source_path.

    Falls back to ("external", source_path) when no [RepoName] prefix is found.
    Common labels: PayloadsAllTheThings -> PATT, HackTricks -> HackTricks.
    """
    if not source_path:
        return ("external", "")
    m = _EXT_REPO_RE.match(source_path)
    if not m:
        return ("external", source_path)
    label = m.group(1).strip()
    rest = m.group(2).strip()
    aliases = {
        "PayloadsAllTheThings": "PATT",
        "PAT": "PATT",
    }
    return (aliases.get(label, label), rest)

CALL_CAP = 4               # per-challenge max midsolve_search invocations
OUTPUT_CAP = 8000          # max chars returned to caller
WEB_PAGE_CAP = 5000        # per-page char cap for web fetch
WEB_RESULTS_CAP = 3        # max web results per call

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Per-challenge call accounting + dedup cache
# ---------------------------------------------------------------------------

def _challenge_dir(name: str | None) -> Path | None:
    if not name:
        return None
    p = CHALLENGES_DIR / name
    return p if p.is_dir() else None


def _calls_file(cdir: Path) -> Path:
    return cdir / ".midsolve_calls.json"


def _load_calls(cdir: Path) -> dict:
    f = _calls_file(cdir)
    if not f.exists():
        return {"count": 0, "queries": {}}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"count": 0, "queries": {}}


def _save_calls(cdir: Path, data: dict) -> None:
    _calls_file(cdir).write_text(json.dumps(data, indent=2), encoding="utf-8")


def _query_key(mode: str, query: str) -> str:
    return hashlib.sha1(f"{mode}::{query}".encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Offline search (kb.db external tables + chunks)
# ---------------------------------------------------------------------------

def _fts_escape(q: str) -> str:
    """Quote a phrase for FTS5 to avoid syntax errors on dashes/colons."""
    safe = q.replace('"', '""')
    return f'"{safe}"'


def _fts_or_query(q: str) -> str:
    """Build an FTS5 OR query from a multi-word input.

    Single word → quoted phrase (safe for dashes/CVE IDs).
    Multi-word → `"a" OR "b" OR "c"` so matches don't require exact contiguity.
    Used by recon/technique modes where users pass loose keyword sets.
    """
    tokens = [t for t in re.split(r"\s+", q.strip()) if t]
    if len(tokens) <= 1:
        return _fts_escape(q)
    escaped = [f'"{t.replace(chr(34), chr(34)*2)}"' for t in tokens if len(t) >= 2]
    if not escaped:
        return _fts_escape(q)
    return " OR ".join(escaped)


def _search_table(conn: sqlite3.Connection, table: str, query: str, top: int) -> list[dict]:
    try:
        cols = [r[0] for r in conn.execute(f"SELECT * FROM {table} LIMIT 0").description]
    except sqlite3.Error:
        return []
    col_str = ", ".join(cols)
    try:
        rows = conn.execute(
            f"SELECT {col_str}, rank FROM {table} WHERE {table} MATCH ? ORDER BY rank LIMIT ?",
            (query, top),
        ).fetchall()
    except sqlite3.Error:
        # Try escaped phrase form
        try:
            rows = conn.execute(
                f"SELECT {col_str}, rank FROM {table} WHERE {table} MATCH ? ORDER BY rank LIMIT ?",
                (_fts_escape(query), top),
            ).fetchall()
        except sqlite3.Error:
            return []
    return [{c: r[c] for c in cols} | {"_table": table} for r in rows]


def _format_offline(results: list[dict]) -> str:
    parts: list[str] = []
    for r in results:
        tbl = r.get("_table", "?")
        if tbl == "exploitdb":
            parts.append(
                f"[exploitdb EDB-{r.get('edb_id', '?')} | {r.get('platform', '')}] "
                f"{r.get('description', '')}"
            )
        elif tbl == "cisa_kev":
            parts.append(
                f"[KEV {r.get('cve_id', '?')}] {r.get('vendor', '')} {r.get('product', '')} — "
                f"{(r.get('vulnerability_name') or '').strip()}\n  {(r.get('description') or '')[:300]}"
            )
        elif tbl == "external_techniques":
            label, rest = _split_external_repo(r.get("source_path", ""))
            parts.append(
                f"[{label}] {rest} § {r.get('heading', '')}\n"
                f"  {(r.get('body') or '')[:400]}"
            )
        elif tbl == "chunks":
            parts.append(
                f"[kb] {r.get('source_path', '')} § {r.get('heading', '')}\n"
                f"  {(r.get('body') or '')[:400]}"
            )
        elif tbl == "nuclei":
            parts.append(
                f"[nuclei {r.get('template_id', '?')} {r.get('severity', '')}] "
                f"{r.get('name', '')}\n  {(r.get('description') or '')[:300]}"
            )
        elif tbl == "speedrun":
            parts.append(
                f"[speedrun #{r.get('entry_id', '?')}] "
                f"{r.get('challenge', '?')} ({r.get('category', '?')})\n"
                f"  signals:  {(r.get('signals') or '').strip()[:200]}\n"
                f"  winning:  {(r.get('winning_chain') or '').strip()[:300]}"
            )
        else:
            parts.append(f"[{tbl}] {json.dumps({k: v for k, v in r.items() if k != '_table'})[:300]}")
    return "\n\n".join(parts)


# Category -> external_techniques source_path LIKE filters (recon/technique mode)
_CATEGORY_PATTERNS = {
    "pwn": ["%binary-exploitation%", "%libc-heap%", "%rop%", "%stack-overflow%", "%format-string%", "%protections%"],
    "rev": ["%reversing%", "%anti-debug%", "%obfuscat%", "%binary-exploitation%"],
    "web": ["%PayloadsAllTheThings%", "%pentesting-web%", "%web-vulns%"],
    "crypto": ["%crypto%", "%cipher%", "%hash%"],
    "forensics": ["%forensic%", "%pcap%", "%memory-dump%", "%steganograph%"],
    "web3": ["%blockchain%", "%smart-contract%", "%solidity%"],
    "ai": ["%AI%", "%llm%", "%prompt%"],
}


def _search_external_filtered(conn, query: str, patterns: list[str], top: int) -> list[dict]:
    """Like _search_table but with source_path LIKE filtering for external_techniques."""
    if not patterns:
        return _search_table(conn, "external_techniques", query, top)
    like_clause = " OR ".join("source_path LIKE ?" for _ in patterns)
    sql = (
        f"SELECT source_path, heading, body, rank FROM external_techniques "
        f"WHERE external_techniques MATCH ? AND ({like_clause}) ORDER BY rank LIMIT ?"
    )
    try:
        rows = conn.execute(sql, (query, *patterns, top)).fetchall()
    except sqlite3.Error:
        return _search_table(conn, "external_techniques", query, top)
    return [{"source_path": r[0], "heading": r[1], "body": r[2], "rank": r[3], "_table": "external_techniques"} for r in rows]


def _search_speedrun(query: str, top: int, category: str | None = None) -> list[dict]:
    """Search the SPEEDRUN_MEMORY FTS5 index for prior solved-challenge patterns.

    speedrun.db is a separate database from kb.db. Each row is a curated entry
    extracted from a past solve (signals -> winning_chain -> technique). Hitting
    here mid-solve is the closest thing to "have we solved a problem like this
    before?" and is the cheapest possible knowledge-reuse signal.
    """
    if not SPEEDRUN_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(SPEEDRUN_PATH))
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []

    cols = ("entry_id", "challenge", "category", "signals", "winning_chain",
            "technique", "snippet")
    col_str = ", ".join(cols)
    sql = (
        f"SELECT {col_str}, rank FROM speedrun WHERE speedrun MATCH ? "
        f"ORDER BY rank LIMIT ?"
    )
    try:
        rows = conn.execute(sql, (query, top)).fetchall()
    except sqlite3.Error:
        try:
            rows = conn.execute(sql, (_fts_escape(query), top)).fetchall()
        except sqlite3.Error:
            conn.close()
            return []

    out: list[dict] = []
    cat_lc = (category or "").lower()
    for r in rows:
        # Optional category filter: prefer same-category hits, but don't drop
        # cross-category ones (a crypto-side technique can still help rev).
        row_cat = (r["category"] or "").lower()
        rec = {c: r[c] for c in cols}
        rec["_table"] = "speedrun"
        rec["_same_category"] = bool(cat_lc) and (row_cat == cat_lc)
        out.append(rec)
    conn.close()

    # Stable sort: same-category first, then original FTS rank order.
    out.sort(key=lambda x: (0 if x.get("_same_category") else 1,))
    return out


def offline_search(mode: str, query: str, top: int = 5, category: str | None = None) -> tuple[list[dict], str]:
    """Search kb.db offline tables. Returns (raw_results, formatted_text).

    `category` enables source_path filtering on external_techniques (HackTricks/PAT).
    Used by recon and technique modes for precision.

    Also queries the separate speedrun.db (SPEEDRUN_MEMORY FTS5 index) for
    prior solved-challenge patterns. Speedrun hits are appended last so they
    don't crowd out fresh KB hits but still surface "we've seen this before".
    """
    if not KB_PATH.exists():
        return [], "[kb.db missing]"
    conn = sqlite3.connect(str(KB_PATH))
    conn.row_factory = sqlite3.Row

    results: list[dict] = []
    # Use OR query for recon/technique (loose keywords), phrase for cve/software (exact)
    if mode in ("recon", "technique"):
        fts_q = _fts_or_query(query)
    else:
        fts_q = _fts_escape(query)
    cat_patterns = _CATEGORY_PATTERNS.get((category or "").lower(), [])

    if mode == "cve":
        results += _search_table(conn, "cisa_kev", fts_q, top)
        results += _search_table(conn, "exploitdb", fts_q, top)
        results += _search_external_filtered(conn, fts_q, cat_patterns, top)
        results += _search_table(conn, "chunks", fts_q, top)
    elif mode == "software":
        results += _search_table(conn, "exploitdb", fts_q, top)
        results += _search_table(conn, "cisa_kev", fts_q, top)
        results += _search_external_filtered(conn, fts_q, cat_patterns, top)
        results += _search_table(conn, "nuclei", fts_q, top)
    elif mode == "technique":
        # Category-aware: pwn/web should hit external_techniques first (HackTricks/PAT),
        # crypto/rev should hit chunks first (local writeups). Others mix.
        if category in ("pwn", "web"):
            results += _search_external_filtered(conn, fts_q, cat_patterns, top)
            results += _search_table(conn, "chunks", fts_q, top)
            results += _search_table(conn, "exploitdb", fts_q, top // 2 or 1)
        else:
            results += _search_table(conn, "chunks", fts_q, top)
            results += _search_external_filtered(conn, fts_q, cat_patterns, top)
            results += _search_table(conn, "exploitdb", fts_q, top // 2 or 1)
    elif mode == "recon":
        # Cheap broad scan. Filter external_techniques aggressively if category given.
        results += _search_external_filtered(conn, fts_q, cat_patterns, top)
        results += _search_table(conn, "chunks", fts_q, top)
        if category in ("web", "pwn"):
            results += _search_table(conn, "cisa_kev", fts_q, max(1, top // 2))
    else:
        results += _search_table(conn, "chunks", fts_q, top)
        results += _search_external_filtered(conn, fts_q, cat_patterns, top)

    conn.close()

    # Speedrun memory: appended to every mode. Cap at 3 to keep output small.
    speedrun_top = 3 if mode == "recon" else max(2, top // 2)
    results += _search_speedrun(fts_q, speedrun_top, category=category)

    return results, _format_offline(results[:top * 2])


# ---------------------------------------------------------------------------
# Web fetch (last resort, bounded)
# ---------------------------------------------------------------------------

def web_search_bounded(query: str) -> tuple[list[dict], str]:
    """Last-resort web search via duckduckgo HTML scraping (no API key).
    Bounded to WEB_RESULTS_CAP results and WEB_PAGE_CAP chars per page."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        return [], "[web] requests/bs4 not installed; skip"

    try:
        # DDG HTML endpoint, no JS required
        r = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (midsolve_search)"},
            timeout=15,
        )
        r.raise_for_status()
    except Exception as e:
        return [], f"[web] search failed: {e}"

    soup = BeautifulSoup(r.text, "html.parser")
    links: list[dict] = []
    for a in soup.select("a.result__a")[:WEB_RESULTS_CAP]:
        href = a.get("href", "")
        if not href:
            continue
        title = a.get_text(strip=True)
        links.append({"url": href, "title": title})

    parts: list[str] = []
    for link in links:
        try:
            page = requests.get(
                link["url"],
                headers={"User-Agent": "Mozilla/5.0 (midsolve_search)"},
                timeout=15,
            )
            page.raise_for_status()
            try:
                import trafilatura
                text = trafilatura.extract(page.text) or ""
            except ImportError:
                text = BeautifulSoup(page.text, "html.parser").get_text(" ", strip=True)
            text = (text or "")[:WEB_PAGE_CAP]
            link["snippet"] = text
            parts.append(f"[web] {link['title']}\n  {link['url']}\n  {text[:1500]}")
        except Exception as e:
            link["snippet"] = f"fetch failed: {e}"
            parts.append(f"[web] {link['title']} ({link['url']}) — fetch failed: {e}")

    return links, "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def stage_result(mode: str, query: str, challenge: str | None,
                 offline: list[dict], web: list[dict]) -> Path:
    """Persist a midsolve_search result for later post_solve absorption."""
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    uid = hashlib.sha1(f"{mode}::{query}::{challenge}".encode("utf-8")).hexdigest()[:10]
    out = STAGING_DIR / f"midsolve_{uid}.json"
    payload = {
        "kind": "midsolve",
        "mode": mode,
        "query": query,
        "used_in_challenge": challenge or "",
        "fetched_at": datetime.now().isoformat(),
        "offline_hits": [
            {k: v for k, v in r.items() if k != "_table"} | {"table": r.get("_table")}
            for r in offline[:10]
        ],
        "web_hits": web[:WEB_RESULTS_CAP],
        "processed": False,  # absorbable by post_solve
        "succeeded": None,    # set later (post_solve will mark True if challenge solved)
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

def cmd_run(mode: str, query: str, challenge: str | None, allow_web: bool, top: int,
            category: str | None = None) -> int:
    cdir = _challenge_dir(challenge)

    # recon mode: cheap, offline-only, does NOT count toward call cap
    is_recon = (mode == "recon")

    # Per-challenge call cap + dedup (skipped for recon)
    cache_hit = None
    if cdir and not is_recon:
        calls = _load_calls(cdir)
        qk = _query_key(mode, query)
        if qk in calls.get("queries", {}):
            cache_hit = calls["queries"][qk]
            print(f"[midsolve] cache hit (skipping fetch): {query}")
        elif calls.get("count", 0) >= CALL_CAP:
            print(
                f"[midsolve] CALL CAP reached ({CALL_CAP}) for challenge {cdir.name}. "
                f"Stop searching, escalate to critic or different approach.",
                file=sys.stderr,
            )
            return 2

    # 1. Offline first (always)
    off_raw, off_text = offline_search(mode, query, top, category=category)
    has_offline = bool(off_raw)

    # 2. Web only if offline empty AND --web flag (never for recon)
    web_raw: list[dict] = []
    web_text = ""
    if not is_recon and not has_offline and allow_web:
        web_raw, web_text = web_search_bounded(query)

    # 3. Stage + accounting (recon does NOT stage, does NOT count)
    if not is_recon and cache_hit is None:
        staged = stage_result(mode, query, challenge, off_raw, web_raw)
        if cdir:
            calls = _load_calls(cdir)
            calls["count"] = calls.get("count", 0) + 1
            calls.setdefault("queries", {})[_query_key(mode, query)] = {
                "query": query,
                "mode": mode,
                "ts": datetime.now().isoformat(),
                "stage_file": str(staged.name),
                "offline_hits": len(off_raw),
                "web_hits": len(web_raw),
            }
            _save_calls(cdir, calls)

    # 4. Output (capped)
    sections: list[str] = []
    if off_text:
        sections.append("=== OFFLINE (kb.db) ===\n" + off_text)
    if web_text:
        sections.append("=== WEB (last resort, bounded) ===\n" + web_text)
    if not sections:
        if not allow_web:
            sections.append(
                "[midsolve] no offline hits. Re-run with --web to allow bounded web fetch."
            )
        else:
            sections.append("[midsolve] no results from any source.")

    output = "\n\n".join(sections)
    if len(output) > OUTPUT_CAP:
        output = output[:OUTPUT_CAP] + f"\n[... truncated at {OUTPUT_CAP} chars]"
    print(output)
    return 0


def main() -> int:
    # Force UTF-8 stdout so em dashes / non-ASCII KB entries don't blow up on
    # Windows consoles (cp949). Agents pipe this output back into prompts so
    # losing characters silently is worse than the cosmetic locale change.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)

    for mode_name, help_text in [
        ("cve",       "Search by CVE ID (e.g. CVE-2021-44228)"),
        ("software",  "Search by software + version (e.g. 'jq 1.6')"),
        ("technique", "Search by technique keyword (e.g. 'ecdsa nonce reuse')"),
        ("recon",     "Free broad scan at agent start. Offline-only, NO call cap, NO staging. "
                      "Triggered by scout/reverser/chain at recon time."),
    ]:
        s = sub.add_parser(mode_name, help=help_text)
        s.add_argument("query", help="search query")
        s.add_argument("--challenge", help="challenge folder name (for call cap + dedup + tagging)")
        s.add_argument("--category", help="pwn/web/crypto/rev/forensics/web3/ai -- prioritizes HackTricks/PAT paths")
        s.add_argument("--web", action="store_true",
                       help="allow web fetch as last resort if offline returns nothing (ignored for recon)")
        s.add_argument("--top", type=int, default=5)

    args = p.parse_args()
    return cmd_run(args.mode, args.query, args.challenge, args.web, args.top,
                   category=getattr(args, "category", None))


if __name__ == "__main__":
    sys.exit(main())
