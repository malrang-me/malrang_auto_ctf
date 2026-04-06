# Learning Trigger Rules

## Writeup 학습 트리거

사용자가 **"[URL] 학습해"** 또는 **"[URL]에 있는거 학습해"** 형태로 입력하면:

1. `python tools/bulk_learn.py crawl <URL> --max 20`
2. 루프: `python tools/bulk_learn.py next` → 한 건씩 JSON 받기
3. 각 파일에서 추출: challenge_name, category, fast_detection_signals, winning_chain, why_it_won, failure_signatures, key_technique, reusable_snippet
4. `knowledge/CTF_SPEEDRUN_MEMORY.md`에 엔트리 추가 (반드시 본문에 `Source-URL: <원본 URL>` 한 줄 포함 — verify가 이걸로 매칭함)
5. 처리 완료: `python tools/bulk_learn.py mark <id>` (processed=true + processed_at 기록)
6. 모든 pending 처리 후 `python tools/bulk_learn.py verify` 로 audit (URL이 SPEEDRUN_MEMORY에 실제 들어갔는지 확인)
7. `python tools/speedrun_db.py rebuild` 또는 그냥 다음 `learn.py record`가 자동 cascade
8. 요약 보고: "N개 라이트업에서 M개 엔트리 학습 완료"

주의: CTF 무관 내용 건너뛰기. <300자 건너뛰기. mark는 SPEEDRUN entry 작성 *후*에만 호출.

## Post-Flag Learning (MANDATORY)
flag → `learn.py record` (kb.db + speedrun.db cascade 자동) → 성과 보고서 → /compact

## Post-Failure Learning
```bash
python tools/learn.py record --challenge-dir challenges/<name> --status failed --category <cat> --notes "blocker: ..."
```
