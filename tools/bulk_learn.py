#!/usr/bin/env python3
"""
bulk_learn.py — Generic CTF writeup crawler + stager

Claude Code session handles the actual learning (no API key needed).

Usage:
  python tools/bulk_learn.py crawl <URL> [--max N] [--category CATEGORY]
  python tools/bulk_learn.py crawl --url-file urls.txt
  python tools/bulk_learn.py status
  python tools/bulk_learn.py clear
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

PROJ_ROOT = Path(__file__).resolve().parent.parent
STAGING_DIR = PROJ_ROOT / "knowledge" / "writeup_staging"
SPEEDRUN_MEMORY = PROJ_ROOT / "knowledge" / "CTF_SPEEDRUN_MEMORY.md"

STAGING_DIR.mkdir(parents=True, exist_ok=True)

SKIP_EXTENSIONS = {".png", ".jpg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".exe", ".svg", ".ico"}
SKIP_KEYWORDS = ["twitter", "reddit", "youtube", "facebook", "instagram", "linkedin"]
WRITEUP_SIGNALS = re.compile(
    r"writeup|write-up|write_up|solution|solve|ctf|challenge|exploit|pwn|crypto|rev|web|forensic|misc|blockchain",
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def fetch_text(url: str, timeout: int = 15) -> str:
    """Extract main article text from any URL."""
    # Try trafilatura first (best generic extractor)
    try:
        import trafilatura
        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            text = trafilatura.extract(downloaded, include_comments=False, include_tables=True)
            if text and len(text) > 200:
                return text
    except ImportError:
        pass

    # Fallback: requests + bs4
    try:
        import requests
        from bs4 import BeautifulSoup
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["nav", "footer", "header", "script", "style", "aside"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        return re.sub(r'\n{3,}', '\n\n', text).strip()
    except Exception as e:
        print(f"  [warn] fetch failed: {e}", file=sys.stderr)
        return ""


def extract_links(base_url: str, max_links: int = 50) -> list[str]:
    """Find probable writeup links from an index page."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("[error] pip install requests beautifulsoup4", file=sys.stderr)
        return []

    try:
        resp = requests.get(base_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    base_domain = urlparse(base_url).netloc
    seen, scored = set(), []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if Path(parsed.path).suffix.lower() in SKIP_EXTENSIONS:
            continue
        if any(kw in parsed.netloc for kw in SKIP_KEYWORDS):
            continue
        if full in seen:
            continue
        seen.add(full)

        score = (
            bool(WRITEUP_SIGNALS.search(full)) +
            bool(WRITEUP_SIGNALS.search(a.get_text(strip=True))) +
            (parsed.netloc == base_domain)
        )
        scored.append((score, full))

    scored.sort(reverse=True)
    links = [u for _, u in scored[:max_links]]
    print(f"[crawl] {len(links)} candidate links from {base_url}")
    return links


def crawl_github(repo_url: str, max_files: int = 30) -> list[dict]:
    """Crawl GitHub repo for writeup markdown files."""
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)", repo_url)
    if not match:
        return []
    owner, repo = match.group(1), match.group(2).rstrip("/")
    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"

    try:
        import requests
        resp = requests.get(api_url, timeout=15)
        resp.raise_for_status()
        tree = resp.json().get("tree", [])
    except Exception as e:
        print(f"[warn] GitHub API: {e}", file=sys.stderr)
        return []

    files = [
        f for f in tree
        if f["type"] == "blob"
        and Path(f["path"]).suffix.lower() in (".md", ".txt")
        and any(s in f["path"].lower() for s in ["solve", "writeup", "solution", "readme"])
    ][:max_files]

    results = []
    for f in files:
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{f['path']}"
        try:
            import requests
            r = requests.get(raw, timeout=10)
            if r.status_code == 200 and len(r.text) > 150:
                results.append({"url": raw, "text": r.text, "path": f["path"]})
        except Exception:
            pass
        time.sleep(0.1)

    print(f"[github] {len(results)} writeup files from {owner}/{repo}")
    return results


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

def stage(url: str, text: str, category: str = "unknown") -> Path:
    uid = hashlib.sha1(url.encode()).hexdigest()[:10]
    out = STAGING_DIR / f"{category}_{uid}.json"
    out.write_text(json.dumps({
        "url": url,
        "category": category,
        "text": text[:20000],
        "fetched_at": datetime.now().isoformat(),
        "processed": False,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def ensure_deps():
    for pkg in ["requests", "beautifulsoup4", "trafilatura"]:
        mod = pkg.replace("-", "_").split(".")[0]
        try:
            __import__(mod)
        except ImportError:
            print(f"[setup] installing {pkg}...")
            os.system(f"{sys.executable} -m pip install -q {pkg}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_crawl(args):
    ensure_deps()
    urls = []

    if args.url_file:
        urls = [l.strip() for l in Path(args.url_file).read_text().splitlines() if l.strip()]
    elif args.url:
        urls = [args.url]

    total_staged = 0
    for base_url in urls:
        # GitHub repo → direct file extraction
        if re.match(r"https://github\.com/[^/]+/[^/]+/?$", base_url):
            items = crawl_github(base_url, max_files=args.max)
            for item in items:
                stage(item["url"], item["text"], args.category)
                total_staged += 1
            continue

        # Generic site → extract links → fetch each
        links = extract_links(base_url, max_links=args.max)
        # Also include base_url itself if it looks like a single writeup
        if not links or len(links) < 3:
            links = [base_url]

        for link in links[:args.max]:
            print(f"  [fetch] {link[:80]}")
            text = fetch_text(link)
            if len(text) > 300:
                stage(link, text, args.category)
                total_staged += 1
                print(f"  [staged] {total_staged}")
            else:
                print(f"  [skip] too short")
            time.sleep(0.4)

    # Print summary for Claude to read
    print(f"\n{'='*50}")
    print(f"CRAWL COMPLETE: {total_staged} writeups staged")
    print(f"Staging dir: {STAGING_DIR}")
    print(f"Next step: Claude reads staged files and writes SPEEDRUN entries")
    print(f"{'='*50}")

    # List staged files for Claude
    staged_files = list(STAGING_DIR.glob("*.json"))
    unprocessed = [f for f in staged_files
                   if not json.loads(f.read_text(encoding="utf-8")).get("processed")]
    print(f"\nUnprocessed staged files ({len(unprocessed)}):")
    for f in unprocessed:
        d = json.loads(f.read_text(encoding="utf-8"))
        print(f"  {f.name}: {d['url'][:70]}")


def cmd_status(args):
    files = list(STAGING_DIR.glob("*.json"))
    processed = sum(1 for f in files
                    if json.loads(f.read_text(encoding="utf-8")).get("processed"))
    pending = len(files) - processed
    nums = re.findall(r"## Entry (\d+)",
                      SPEEDRUN_MEMORY.read_text(encoding="utf-8") if SPEEDRUN_MEMORY.exists() else "")
    print(f"Staged: {len(files)} total | {pending} pending | {processed} done")
    print(f"SPEEDRUN entries: {len(nums)}")
    if pending:
        print("\nPending:")
        for f in files:
            d = json.loads(f.read_text(encoding="utf-8"))
            if not d.get("processed"):
                print(f"  [{d['category']}] {d['url'][:70]}")


def cmd_clear(args):
    for f in STAGING_DIR.glob("*.json"):
        f.unlink()
    print(f"[clear] Staging dir cleared")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("crawl")
    p.add_argument("url", nargs="?")
    p.add_argument("--url-file")
    p.add_argument("--category", default="unknown")
    p.add_argument("--max", type=int, default=20)

    sub.add_parser("status")
    sub.add_parser("clear")

    args = parser.parse_args()
    if args.cmd == "crawl":
        cmd_crawl(args)
    elif args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "clear":
        cmd_clear(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
