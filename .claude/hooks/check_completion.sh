#!/bin/bash
# check_completion.sh — Verify agent actually completed (FAKE IDLE detection)
# Runs when an agent stops to check if checkpoint.json shows completion

set -euo pipefail
INPUT=$(cat)
CWD=$(echo "$INPUT" | jq -r '.cwd // "."')

WARNINGS=""
for cp in $(find "$CWD" -maxdepth 4 -name "checkpoint.json" -mmin -10 2>/dev/null | head -5); do
    STATUS=$(jq -r '.status // "unknown"' "$cp" 2>/dev/null || continue)
    AGENT=$(jq -r '.agent // "unknown"' "$cp" 2>/dev/null || echo "unknown")
    PHASE=$(jq -r '.phase_name // .phase // "?"' "$cp" 2>/dev/null || echo "?")
    
    if [[ "$STATUS" == "in_progress" ]]; then
        IN_PROG=$(jq -r '.in_progress // "none"' "$cp" 2>/dev/null || echo "none")
        WARNINGS="${WARNINGS}⚠️ FAKE IDLE: Agent '$AGENT' stopped but checkpoint shows in_progress (phase=$PHASE, task=$IN_PROG). Resume or respawn needed.\n"
    elif [[ "$STATUS" == "error" ]]; then
        ERROR=$(jq -r '.error // "unknown"' "$cp" 2>/dev/null || echo "unknown")
        WARNINGS="${WARNINGS}❌ Agent '$AGENT' errored: $ERROR. Needs fix before retry.\n"
    fi
done

if [[ -n "$WARNINGS" ]]; then
    echo "{\"decision\":\"block\",\"reason\":\"$(echo -e $WARNINGS | head -c 500)\"}"
else
    echo '{}'
fi
