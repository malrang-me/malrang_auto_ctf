---
name: progress
description: "CTF 문제 풀이 진행상황 보고. 단계별 진행도, 소요시간, 예상시간, 토큰 사용량 표시."
argument-hint: "[challenge-name]"
user-invocable: true
allowed-tools:
  - Read
  - Bash
  - Glob
---

# 진행상황 보고

현재 풀고 있는 CTF 문제의 진행상황을 간결하게 보고한다.

## 데이터 수집

1. 현재 작업 중인 challenge 디렉토리 파악 (인자 또는 최근 checkpoint)
2. 아래 파일들을 읽어서 상태 파악:

```bash
# checkpoint 상태
cat challenges/<name>/checkpoint.json 2>/dev/null

# 실패 기록
cat challenges/<name>/memory/failures.md 2>/dev/null

# 전략
cat challenges/<name>/memory/strategy.md 2>/dev/null

# 산출물 존재 여부
ls challenges/<name>/reversal_map.md challenges/<name>/solve.py challenges/<name>/exploit.py challenges/<name>/critic_review.md 2>/dev/null
```

## 출력 형식 (반드시 이 형식으로, 한글로)

```
┌─ 진행상황: <challenge_name> ─────────────────────────┐
│                                                       │
│  카테고리: <cat>  난이도: <diff>  파이프라인: <type>    │
│                                                       │
│  단계          상태       소요    예상    토큰(추정)   │
│  ─────────────────────────────────────────────────── │
│  인테이크      ✅ 완료    1분     -       ~1k         │
│  reverser     ✅ 완료    3분     -       ~3k         │
│  solver       🔄 진행중  5분~    8분     ~8k~        │
│    ├ 모델링    ✅ 완료            -       ~2k         │
│    ├ 시도 #1   ❌ 실패            -       ~3k         │
│    └ 시도 #2   🔄 진행중          -       ~3k~        │
│  critic       ⬚ 대기     -      3분     ~4k         │
│  verifier     ⬚ 대기     -      2분     ~1k         │
│  reporter     ⬚ 대기     -      1분     ~1k         │
│  ─────────────────────────────────────────────────── │
│  경과: X분  |  예상 잔여: Y분  |  토큰: ~Xk / ~Yk    │
│                                                       │
│  현재 상태: <지금 뭘 하고 있는지 1줄>                  │
│  실패 횟수: N회 (L1: n, L2: n, L3: n)                 │
│  다음 단계: <다음에 할 일 1줄>                         │
└───────────────────────────────────────────────────────┘
```

## 규칙

- **간결하게**: 위 테이블 형식만 출력. 설명/분석 추가 금지.
- **추정 기반**: 정확한 토큰 수치가 없으면 합리적 추정 사용.
- **checkpoint.json 없으면**: 디렉토리 내 파일 존재 여부로 단계 추정.
- **토큰 추정 기준**:
  - 인테이크: ~1k
  - reverser(sonnet): 디컴파일 크기에 따라 2-5k
  - solver(opus): 시도당 3-5k
  - critic(opus): 3-5k
  - verifier(sonnet): 1-2k
  - reporter(sonnet): 1-2k
