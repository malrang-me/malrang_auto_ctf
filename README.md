# malrang_auto_ctf

Autonomous CTF solving framework for Claude Code.

## Features

- **8 categories**: crypto, pwn, web, rev, web3, forensics, ai, misc
- **11 MCP servers**: solver-z3, sage-helper, pwn-local, py-repl, and more
- **Auto loop detection**: 3x same failure = warning, 5x = hard stop
- **Flag verification**: candidates validated against actual execution output
- **Dreamhack auto-intake**: Chrome MCP navigates, downloads, scaffolds, solves
- **Parallel solving**: solver-a (orthodox) + solver-b (bypass) branches
- **Learning loop**: CTF_SPEEDRUN_MEMORY.md accumulates patterns across sessions

## Quick Start

```powershell
# Scaffold a new challenge
.\scripts\scaffold.ps1 -Name "RSA_Quartet" -Category crypto -Remote "host1.dreamhack.games 12345"

# Run solver
.\scripts\run.ps1 -Path challenges\RSA_Quartet -Mode remote

# Check completion gates
.\scripts\gate.ps1 -Path challenges\RSA_Quartet
```

Or in Claude Code, just say: `solve challenges/RSA_Quartet`

## Structure

```
categories/     8 attack-pattern guides per category
challenges/     flat namespace, one folder per challenge
knowledge/      CTF_SPEEDRUN_MEMORY.md (accumulated lessons)
mcp_servers/    custom MCP server code (pwn-local, sage, cryptominisat)
scripts/        5 essential PowerShell scripts
templates/      solve.py / exploit.py starter templates
```

## Environment

- Windows 11 + WSL (for pwntools, gdb, sage)
- Claude Code with 11 MCP servers
- Chrome MCP for web automation / Dreamhack intake
