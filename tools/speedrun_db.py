#!/usr/bin/env python3
"""
SPEEDRUN_MEMORY SQLite FTS5 index.
Replaces full-file scanning of 67KB markdown with indexed search.

Usage:
  speedrun_db.py rebuild              # rebuild index from CTF_SPEEDRUN_MEMORY.md
  speedrun_db.py search <query> [N]   # search top N entries (default 3)
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

MACHINE_ROOT = Path(__file__).resolve().parent.parent
MEMORY_FILE = MACHINE_ROOT / "knowledge" / "CTF_SPEEDRUN_MEMORY.md"
DB_FILE = MACHINE_ROOT / "knowledge" / "speedrun.db"


def init_db(conn: sqlite3.Connection):
    """Create FTS5 table if not exists."""
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS speedrun USING fts5(
            entry_id,
            challenge,
            category,
            signals,
            winning_chain,
            technique,
            snippet,
            full_text,
            tokenize='porter unicode61'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()


def parse_entries(content: str) -> list:
    """Parse SPEEDRUN_MEMORY.md into structured entries."""
    entries = []
    raw_entries = re.split(r'\n(?=## Entry \d+)', content)

    for raw in raw_entries:
        raw = raw.strip()
        if not raw or raw.startswith("# CTF"):
            continue

        entry = {}
        # Extract entry ID
        m = re.match(r'## Entry (\d+)', raw)
        entry["entry_id"] = m.group(1) if m else "0"

        # Extract fields
        for field, pattern in [
            ("challenge", r'(?:Challenge|Name|Problem):\s*(.+)'),
            ("category", r'Category:\s*(.+)'),
            ("signals", r'(?:Fast Detection Signals|Detection|Signals?):\s*(.+(?:\n\s*[-*].+)*)'),
            ("winning_chain", r'(?:Winning Chain|Approach|Chain):\s*(.+(?:\n\s*[-*].+)*)'),
            ("technique", r'(?:Key Technique|Technique|Key):\s*(.+)'),
            ("snippet", r'(?:Reusable Snippet|Snippet|Code):\s*(.+(?:\n.+)*?)(?=\n##|\n\*\*|\Z)'),
        ]:
            fm = re.search(pattern, raw, re.IGNORECASE)
            entry[field] = fm.group(1).strip()[:500] if fm else ""

        entry["full_text"] = raw[:800]
        entries.append(entry)

    return entries


def rebuild():
    """Rebuild FTS5 index from markdown file."""
    if not MEMORY_FILE.exists():
        print(f"[speedrun_db] {MEMORY_FILE} not found", file=sys.stderr)
        return 0

    content = MEMORY_FILE.read_text(encoding="utf-8", errors="replace")
    entries = parse_entries(content)

    conn = sqlite3.connect(str(DB_FILE))
    init_db(conn)

    # Clear and rebuild
    conn.execute("DELETE FROM speedrun")
    for e in entries:
        conn.execute(
            "INSERT INTO speedrun (entry_id, challenge, category, signals, winning_chain, technique, snippet, full_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (e["entry_id"], e["challenge"], e["category"], e["signals"],
             e["winning_chain"], e["technique"], e["snippet"], e["full_text"])
        )

    # Store metadata
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('entry_count', ?)",
                 (str(len(entries)),))
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('source_size', ?)",
                 (str(len(content)),))
    conn.commit()
    conn.close()

    print(f"[speedrun_db] Indexed {len(entries)} entries → {DB_FILE}")
    return len(entries)


def ensure_fresh() -> bool:
    """Rebuild the index if the markdown source is newer than the DB
    (or the DB is missing). Returns True if a rebuild was performed."""
    if not MEMORY_FILE.exists():
        return False
    if not DB_FILE.exists():
        rebuild()
        return True
    try:
        if MEMORY_FILE.stat().st_mtime > DB_FILE.stat().st_mtime:
            rebuild()
            return True
    except OSError:
        pass
    return False


def search(query: str, top_n: int = 3) -> list:
    """Search FTS5 index. Returns list of dicts."""
    ensure_fresh()
    if not DB_FILE.exists():
        return []

    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row

    # Build FTS5 query: combine terms with OR for broader matching
    terms = query.strip().split()
    fts_query = " OR ".join(f'"{t}"' for t in terms if len(t) > 1)

    if not fts_query:
        conn.close()
        return []

    try:
        rows = conn.execute(
            f"SELECT *, rank FROM speedrun WHERE speedrun MATCH ? ORDER BY rank LIMIT ?",
            (fts_query, top_n)
        ).fetchall()
    except sqlite3.OperationalError:
        # If FTS query fails, try simpler approach
        rows = conn.execute(
            "SELECT * FROM speedrun WHERE full_text LIKE ? OR category LIKE ? LIMIT ?",
            (f"%{terms[0]}%", f"%{terms[0]}%", top_n)
        ).fetchall()

    results = []
    for row in rows:
        results.append({
            "entry_id": row["entry_id"],
            "challenge": row["challenge"],
            "category": row["category"],
            "signals": row["signals"],
            "technique": row["technique"],
            "winning_chain": row["winning_chain"],
            "summary": row["full_text"][:400],
        })

    conn.close()
    return results


def format_results(results: list) -> str:
    """Format search results as compact text block."""
    if not results:
        return "[No matching SPEEDRUN entries]"

    lines = [f"[SPEEDRUN: {len(results)} relevant entries]"]
    for r in results:
        lines.append(f"\n### Entry {r['entry_id']} — {r['challenge']} ({r['category']})")
        if r["signals"]:
            lines.append(f"  Signals: {r['signals'][:200]}")
        if r["technique"]:
            lines.append(f"  Technique: {r['technique'][:150]}")
        if r["winning_chain"]:
            lines.append(f"  Chain: {r['winning_chain'][:200]}")

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="SPEEDRUN_MEMORY FTS5 index")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("rebuild", help="Rebuild index from markdown")

    sp = sub.add_parser("search", help="Search entries")
    sp.add_argument("query", help="Search query (category + keywords)")
    sp.add_argument("top_n", nargs="?", type=int, default=3)

    args = p.parse_args()

    if args.cmd == "rebuild":
        rebuild()
    elif args.cmd == "search":
        results = search(args.query, args.top_n)
        print(format_results(results))
    else:
        p.print_help()


if __name__ == "__main__":
    main()
