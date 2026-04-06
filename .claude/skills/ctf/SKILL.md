---
name: ctf
description: Start CTF challenge solving pipeline. Auto-matches "ctf", "solve", "pwn", "reversing", "crypto challenge", "wargame", "dreamhack"
argument-hint: "[challenge-path] [--mode contest]"
---

# CTF Challenge Pipeline

## Mode Detection
인자 또는 대화에서 `--mode contest`, `실전`, `대회`, `contest` 감지 시 → **Contest Mode** 활성화.
없으면 → **Practice Mode** (기본).

## CRITICAL RULES (양쪽 모드 공통)
1. **Local flag file = FAKE** — only remote(host, port) has the real flag
2. **MUST use Agent Teams** — never solve directly
3. **IDA MCP 강제 우선** — `python tools/ida_auto.py check` 먼저. 응답하면 IDA만 사용.

## Pre-checks (auto-executed)
Challenge info:
!`if [ -d "$ARGUMENTS" ] 2>/dev/null; then ls -la "$ARGUMENTS" 2>/dev/null | head -10; fi`

## Intake
- **WebFetch + curl 우선.** DOM 스냅샷 금지.
- Dreamhack: `WebFetch` → `curl`. Chrome 안 씀.

---

## Practice Mode (기본 — 연습/워게임)
```
목표: 정확도 + 토큰 절감 + 학습 기록
```
- Pipeline: 전체 에이전트 (critic, verifier, reporter 포함)
- Effort: 난이도별 조절 (easy=medium, medium=high, hard=max)
- Dual approach: 2회 실패 후 병렬
- Verifier: 로컬 3회 + 리모트 1회
- Reporter: **반드시 스폰**, 성과 보고서 + learn.py + FLAGS.txt

### Completion Checklist (Practice)
- [ ] Flag verified (2+ runs)
- [ ] reporter 스폰 + 성과 보고서
- [ ] FLAGS.txt + learn.py record
ALL checked = 완료.

---

## Contest Mode (실전 — 대회)
```
목표: 속도 최우선. 빨리 flag 뽑기.
```
- **critic 스킵** (easy/medium — hard에서만 실행)
- **reporter 최소화**: FLAGS.txt 추가 + learn.py record만. 보고서는 대회 후.
- **effort 난이도별** (easy=medium, medium=high, hard=max) — practice와 동일
- **dual approach 즉시**: 1회 실패 시 바로 병렬 2개
- **verifier 축소**: 로컬 1회 + 리모트 1회
- **인테이크 최소화**: scaffold + triage만, 메모/전략 문서 생략

### Pipeline (Contest)
```
trivial:        ctf-solver → flag 기록                          (1-agent)
crypto/rev:     reverser → solver (즉시 병렬 가능) → verifier   (2-3 agent)
pwn:            reverser → chain (즉시 병렬 가능) → verifier    (2-3 agent)
web:            scout → exploiter (analyst 스킵)                (2 agent)
```

### Completion Checklist (Contest)
- [ ] Flag verified (1+ run)
- [ ] FLAGS.txt에 추가됨
- [ ] learn.py record 실행됨
대회 후: reporter 일괄 스폰하여 보고서 생성.
