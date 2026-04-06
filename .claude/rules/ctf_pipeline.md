# CTF Pipeline — Selection & Execution

## Pipeline Selection
```
trivial (1-3 line bug):     ctf-solver → [orch: report]                         (1-agent)
crypto (easy RSA):          crypto_prescreen → [성공] verifier → [orch: report]  (1-2 agent)
crypto (easy, 기타):         reverser → crypto-solver → verifier → [orch: report] (3-agent)
crypto (medium/hard):        reverser → crypto-solver → critic → verifier → reporter (5-agent)
rev (easy/medium):           reverser → solver → verifier → [orch: report]       (3-agent)
rev (hard):                  reverser → solver → critic → verifier → reporter    (5-agent)
pwn (vuln clear):            reverser → chain → critic → verifier → [orch: report] (4-agent)
pwn (vuln unclear):          reverser → trigger → chain → critic → verifier      (6-agent)
web (trivial vuln):          scout → ctf-solver → [orch: report]                 (2-agent)
web (complex):               scout → analyst → exploiter → [orch: report]        (3-agent)
web3:                        reverser → solver → critic → verifier → reporter    (5-agent)
forensics (complex):         ctf-solver (recon → analyze → extract) → [orch: report] (1-agent)
```
**[orch: report]** = 오케스트레이터가 직접 처리 (FLAGS.txt + learn.py + 간소화 보고서). reporter 에이전트 스폰 안 함.
**reporter 에이전트** = hard 난이도 + 상세 모델/Effort 분석 필요 시에만 스폰. 그 외에는 ~20k 토큰 절감.
**crypto prescreen**: RSA easy 문제는 `python tools/crypto_prescreen.py` 먼저 실행.
**crypto-solver**: crypto 전용 에이전트 (`subagent_type="crypto-solver"`). SageMath + lattice + oracle.
**web fast-path**: scout가 `TRIVIAL: true` 판정 시 analyst/exploiter 생략.
Never use full 6-agent unconditionally. Unnecessary agents = token waste.

## Agent Models (MANDATORY — no spawn without model)
| Agent | Model | Agent | Model |
|-------|-------|-------|-------|
| reverser | sonnet / **opus**(hard) | scout | sonnet |
| solver | opus | analyst | sonnet |
| **crypto-solver** | **opus** | exploiter | opus |
| chain | opus | reporter | sonnet |
| trigger | sonnet | ctf-solver | sonnet |
| critic | opus | verifier | sonnet |

## 동적 모델 선택
triage.py `difficulty` 결과 기준:
- `easy/medium` → reverser=sonnet
- `hard` → reverser=opus (Agent 스폰 시 `model: "opus"` 오버라이드)
오케스트레이터가 판단. 에이전트 .md의 기본 model은 sonnet이지만 스폰 시 오버라이드 가능.

## Contest Mode Pipeline (속도 최우선)
```
trivial:        ctf-solver → flag 기록                              (1-agent)
crypto (easy):  crypto_prescreen → [실패시] crypto-solver → verifier (1-2 agent)
crypto (hard):  reverser → crypto-solver (즉시 병렬) → verifier      (2-3 agent)
rev:            reverser → solver (즉시 병렬) → verifier             (2-3 agent)
pwn:            reverser → chain (즉시 병렬) → verifier              (2-3 agent)
web:            scout → exploiter (analyst 스킵)                     (2 agent)
```
- critic: easy/medium 스킵. hard만 실행.
- reporter: 대회 후 일괄. 풀이 중에는 FLAGS.txt + learn.py만.
- effort: 난이도별 (easy=medium, medium=high, hard=max). practice와 동일.
- dual approach: **1회 실패 시 즉시** 병렬.

## Failure Protocol
- **2 consecutive failures → Dual-Approach**: 2 solver agents with different strategies, first success wins
- **3 failures (same L3) → midsolve_search.py**: offline kb.db first (cisa_kev/exploitdb/HackTricks/PayloadsAllTheThings), `--web` only if 0 hits. 4 calls/challenge cap. 직접 WebSearch 금지 — `rules/common.md` 참조.
- **3× same signature → Stall Mode**: stop, re-examine assumptions, switch chain

## Checkpoint Protocol
All agents maintain `<challenge_dir>/checkpoint.json`. See `rules/common.md`.

## Fake Flag Protection
Local flag files are ALWAYS fake. Only `remote(host, port)` yields real flags.
Orchestrator MUST run solve.py directly to verify FLAG_FOUND claims.
