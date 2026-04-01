# Timing Side-Channel Attack

## 개요
서버의 응답 시간 차이를 이용해 비밀 값을 추론하는 공격.
비교 연산이 일찍 종료되는지(early return) 또는 추가 연산이 실행되는지로 판별.

## 탐지 시그널
- 바이트/블록 단위 비교 (해시, 토큰, 패스워드)
- Python `==` 비교 (바이트 단위 short-circuit)
- 블록별 SHA/HMAC 비교
- 응답이 "맞음/틀림" 이분법

## 공격 기법

### 바이트 단위 타이밍
```python
import time, socket

def measure(payload):
    t0 = time.time()
    send_payload(payload)
    recv_response()
    return time.time() - t0

# 각 위치별로 256개 후보 테스트
for pos in range(secret_len):
    best_char, best_time = 0, 0
    for c in range(256):
        candidate = known + bytes([c]) + b'\x00' * (secret_len - pos - 1)
        elapsed = measure(candidate)
        if elapsed > best_time:
            best_char, best_time = c, elapsed
    known += bytes([best_char])
```

### 블록 단위 타이밍 (GoN 2022 Leetcode 패턴)
- 16바이트를 4바이트 블록으로 나눠 SHA512 비교
- 맞는 블록이 있으면 추가 해시 연산 → 응답 지연
- 블록별 hex 브루트포스 (4바이트 hex = 0000~ffff)

### 통계적 접근
- 단일 측정은 노이즈가 큼 → 여러 번 반복 측정
- 중앙값 또는 최소값 사용 (네트워크 지터 제거)
- 자동 임계값: `mean + 2*stdev` 이상이면 hit

## 주의사항
- 네트워크 지터가 크면 로컬/같은 네트워크에서 시도
- 서버가 constant-time 비교 사용하면 불가 (`hmac.compare_digest`)
- 랜덤 비교 순서는 공격을 어렵게 하지만 불가능하게 하진 않음

## 관련 문제
- GoN 2022 N. Leetcode: SHA512 블록 비교 타이밍 어택
