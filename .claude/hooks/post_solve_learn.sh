#!/bin/bash
# post_solve_learn.sh — Auto-learn after flag found
# Runs on Stop hook: scans recent challenge dirs for real flags, writes SPEEDRUN entry if missing.

set -uo pipefail
INPUT=$(cat)
CWD=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cwd','.'))" 2>/dev/null || echo ".")

PROJECT_ROOT="/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf"
MEMORY_FILE="$PROJECT_ROOT/knowledge/CTF_SPEEDRUN_MEMORY.md"
LEARN_SCRIPT="$PROJECT_ROOT/tools/learn.py"

# Placeholder patterns to ignore
PLACEHOLDERS="DH{flag}|DH{testflag}|DH{test_test}|DH{UPATCHED}|DH{\.\.\.}|DH{\?*}"

# Find challenge dirs with real flags modified in last 2 hours
for challenge_dir in "$PROJECT_ROOT/challenges"/*/; do
    [[ -d "$challenge_dir" ]] || continue
    challenge_name=$(basename "$challenge_dir")

    # Find real flag in memory/discoveries.md or any .md/.txt/.py file
    flag=$(grep -rh "DH{" "$challenge_dir" 2>/dev/null \
        | grep -o "DH{[^}]*}" \
        | grep -vE "DH\{flag\}|DH\{testflag\}|DH\{test_test\}|DH\{UPATCHED\}|DH\{\.{3}\}|DH\{\?+\}" \
        | head -1)

    [[ -z "$flag" ]] && continue

    # Check if SPEEDRUN_MEMORY already has this challenge
    if grep -qF "Challenge: $challenge_name" "$MEMORY_FILE" 2>/dev/null; then
        continue
    fi

    # Get category from meta.yaml
    category=$(grep "^category:" "$challenge_dir/meta.yaml" 2>/dev/null | awk '{print $2}' || echo "unknown")

    # Get key facts from discoveries.md
    discoveries=$(cat "$challenge_dir/memory/discoveries.md" 2>/dev/null | head -30 || echo "No discoveries recorded.")

    # Get next entry number
    last_num=$(grep -oP "## Entry \K\d+" "$MEMORY_FILE" 2>/dev/null | sort -n | tail -1 || echo "0")
    next_num=$(printf "%03d" $((10#$last_num + 1)))

    # Generate entry
    entry="\n---\n\n## Entry $next_num - $challenge_name\n- Challenge: $challenge_name\n- Category: $category\n- Date: $(date +%Y-%m-%d)\n- Flag: $flag\n- Fast Detection Signals:\n  - See memory/discoveries.md\n- Winning Chain:\n  - $(echo "$discoveries" | grep -A2 "Technique\|technique\|Chain\|chain\|Attack" | head -3 | sed 's/^/  /')\n- Failure Signatures -> Immediate Fix:\n  - Check memory/failures.md\n- Reusable Assets:\n  - $challenge_dir/solve.py or exploit.py\n- Expected Speed-up Next Time:\n  - Pattern documented above\n"

    echo -e "$entry" >> "$MEMORY_FILE"
    echo "✅ [post_solve_learn] SPEEDRUN entry written for: $challenge_name ($flag)"

    # Signal file: tell Claude to run /compact at next session start
    touch "$PROJECT_ROOT/.compact_needed"
    echo "📦 [post_solve_learn] .compact_needed signal created"
done

echo '{}'
