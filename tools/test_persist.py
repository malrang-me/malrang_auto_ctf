#!/usr/bin/env python3
"""Test persistent browser context for cookie persistence."""
from playwright.sync_api import sync_playwright
import os

UD = os.path.expanduser("~/.ctf-browser-data")
os.makedirs(UD, exist_ok=True)

with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(UD, headless=True)
    page = ctx.pages[0] if ctx.pages else ctx.new_page()
    page.goto("https://dreamhack.io", timeout=15000)
    title = page.title()
    cookies = ctx.cookies("https://dreamhack.io")
    print(f"Title: {title}")
    print(f"Total cookies: {len(cookies)}")
    for c in cookies:
        n = c.get("name", "?")
        v = str(c.get("value", ""))[:15]
        print(f"  {n} = {v}...")
    ctx.close()
    files = os.listdir(UD)
    print(f"Persisted files: {len(files)}")
    for f in files[:8]:
        print(f"  {f}")
