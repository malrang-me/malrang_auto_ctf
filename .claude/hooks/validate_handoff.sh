#!/bin/bash
# validate_handoff.sh — Verify agent output contains required [HANDOFF] format
# Runs on SubagentStop event

set -uo pipefail
INPUT=$(cat)

# Extract the agent's output/transcript from stdin
TRANSCRIPT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('transcript', d.get('output', '')))
except:
    print('')
" 2>/dev/null)

# Check for handoff markers in the output
if echo "$TRANSCRIPT" | grep -q "\[HANDOFF"; then
    echo '{}'
    exit 0
fi

# Check if agent produced a completion artifact (FLAG_FOUND, solve.py, etc.)
if echo "$TRANSCRIPT" | grep -qE "FLAG_FOUND|flag\{|DH\{|CTF\{|picoCTF\{"; then
    echo '{}'
    exit 0
fi

# Check for explicit FAIL/COMPLETED status
if echo "$TRANSCRIPT" | grep -qE "\[STATUS: (COMPLETED|FAIL)\]"; then
    echo '{}'
    exit 0
fi

# No handoff found — warn but don't block (soft enforcement)
echo '{"decision":"report","reason":"⚠️ Agent output missing [HANDOFF] format. Consider adding structured handoff for next agent."}'
