#!/bin/bash
# pre_solve_validate.sh — Pre-solve auto-validation
# Ensures meta.yaml and memory/ files exist before solving starts
# Can be called manually: bash .claude/hooks/pre_solve_validate.sh < /dev/null

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

FIXED=0
for challenge_dir in "$PROJECT_ROOT/challenges"/*/; do
    [[ -d "$challenge_dir" ]] || continue
    name=$(basename "$challenge_dir")

    # Auto-generate meta.yaml if missing
    if [[ ! -f "$challenge_dir/meta.yaml" ]]; then
        python3 "$PROJECT_ROOT/tools/gen_meta.py" 2>/dev/null
        FIXED=$((FIXED + 1))
    fi

    # Ensure memory/ dir and files exist
    mkdir -p "$challenge_dir/memory" 2>/dev/null
    for mf in recon.md strategy.md discoveries.md failures.md; do
        if [[ ! -f "$challenge_dir/memory/$mf" ]]; then
            echo "# ${name} - ${mf%.md}" > "$challenge_dir/memory/$mf"
            FIXED=$((FIXED + 1))
        fi
    done
done

if [[ $FIXED -gt 0 ]]; then
    echo "[pre_solve_validate] Fixed $FIXED missing files"
fi
echo '{}'
