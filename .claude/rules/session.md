# Session Management & Context Economy

## Architecture
One main session (orchestrator) + spawned subagents per problem.
Main session does NOT solve directly — spawn agents.

## Subagent Spawning
Use `Agent` tool with `subagent_type`, include ALL context in prompt.
Use `triage.py --build-prompt <agent>` for compact context injection.

## /compact Triggers
| Trigger | Action |
|---------|--------|
| Problem solved | `/compact` |
| 3+ problems in session | `/compact` |
| Context > ~80k tokens | `/compact` immediately |
| Before 3+ parallel agents | `/compact` |

## Token Budget
```
Main session:    < 30k tokens
Per-subagent:    unlimited (isolated)
After /compact:  ~5k baseline
```

## .compact_needed Check
At session start: `[ -f .compact_needed ] && rm .compact_needed && echo "Previous solve needs compact"`
