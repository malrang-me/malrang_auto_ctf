#!/bin/bash
# parallel_solve.sh — Launch N claude sessions in tmux to solve CTF challenges
#
# Usage:
#   ./scripts/parallel_solve.sh 3 "picoCTF crypto medium"
#   ./scripts/parallel_solve.sh 2 "dreamhack crypto lv5" "dreamhack pwn lv4"
#   ./scripts/parallel_solve.sh 1 "solve challenges/Schnorsa"

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SESSION_NAME="ctf-parallel"
NUM_TASKS=${1:-1}
shift || true

# Kill existing session if any
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true

# Create first window
PROMPT="${1:-picoCTF crypto medium 문제 1개 풀어}"
tmux new-session -d -s "$SESSION_NAME" -c "$PROJECT_DIR"
tmux send-keys -t "$SESSION_NAME" "cd $PROJECT_DIR && claude '$PROMPT'" Enter

# Create additional windows for remaining tasks
for i in $(seq 2 "$NUM_TASKS"); do
    PROMPT="${!i:-picoCTF crypto medium 문제 1개 풀어 (instance $i)}"
    tmux new-window -t "$SESSION_NAME" -c "$PROJECT_DIR"
    tmux send-keys -t "$SESSION_NAME" "cd $PROJECT_DIR && claude '$PROMPT'" Enter
done

# Tile all windows if more than 1
if [ "$NUM_TASKS" -gt 1 ]; then
    # Switch to tiled layout for easy viewing
    tmux select-layout -t "$SESSION_NAME" tiled 2>/dev/null || true
fi

echo "Launched $NUM_TASKS claude sessions in tmux session '$SESSION_NAME'"
echo "Attach with: tmux attach -t $SESSION_NAME"
echo "Switch windows: Ctrl+B then number (0,1,2...)"

# Auto-attach
tmux attach -t "$SESSION_NAME"
