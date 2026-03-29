#!/bin/bash
# auto_decision_tree.sh — PostToolUse:Bash hook
# When a bash command fails, check if decision_tree.py can suggest next action
set -euo pipefail
INPUT=$(cat)
EXIT_CODE=$(echo "$INPUT" | jq -r '.tool_output.exit_code // 0' 2>/dev/null || echo "0")

if [[ "$EXIT_CODE" != "0" ]]; then
    CDIR="${CHALLENGE_DIR:-}"
    if [[ -n "$CDIR" ]] && [[ -f "$(dirname "$0")/../../tools/decision_tree.py" ]]; then
        PROJ="$(cd "$(dirname "$0")/../.." && pwd)"
        AGENT=$(echo "$INPUT" | jq -r '.agent // "solver"' 2>/dev/null || echo "solver")
        python3 "$PROJ/tools/decision_tree.py" next --agent "$AGENT" --trigger bash_failure 2>/dev/null || true
    fi
fi
echo '{}'
