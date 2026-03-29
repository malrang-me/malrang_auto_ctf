---
name: ctf
description: Start CTF challenge solving pipeline. Auto-matches "ctf", "solve", "pwn", "reversing", "crypto challenge", "wargame", "dreamhack"
argument-hint: [challenge-path] [host:port]
---

# CTF Challenge Pipeline

## CRITICAL RULES
1. **Local flag file = FAKE** — only remote(host, port) has the real flag
2. **MUST use Agent Teams** — never solve directly (trivial exception only)
3. **Agent model MANDATORY** — reverser=sonnet, solver=opus, critic=opus, verifier=sonnet

## Pre-checks (auto-executed)

Challenge info:
!`if [ -d "$ARGUMENTS" ] 2>/dev/null; then ls -la "$ARGUMENTS" 2>/dev/null | head -10; fi`

## Pipeline (see .claude/rules/ctf_pipeline.md)

1. **Classify**: crypto/pwn/web/rev/trivial
2. **Select pipeline**: trivial→1-agent, crypto→5-agent, pwn→5-6 agent
3. **Execute**: sequential agent pipeline with handoffs
4. **Verify**: orchestrator runs solve.py directly
5. **Report**: update knowledge/challenges/
