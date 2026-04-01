# RBG+++ (KalmarCTF 2026)

- Platform: Dreamhack (wargame #2824), 원본 KalmarCTF 2026
- Category: Crypto (Level 10)
- Author: soon_haari
- Solvers: 0 (Dreamhack 기준)
- Writeup: https://blog.sceleri.cc/posts/kalmar-ctf-2026/
- Source: https://github.com/soon-haari/my-ctf-challenges/tree/main/2026-kalmar/rbg%2B%2B%2B

## 챌린지 코드

```python
from Crypto.Util.number import *

PBITS, NDAT = 137, 137

with open("flag.txt", "rb") as f:
    m = int.from_bytes(f.read())

N = getPrime(PBITS) * getPrime(PBITS)
e = getRandomRange(731, N)
print(f"{N = }")

lcg = lambda s: (s * 3 + 1337) % N

for i in range(NDAT):
    print(pow(m, e:=lcg(e), N) + pow(m, e:=lcg(e), N))

    # Internal audit
    e = getRandomRange(731, N)
    print(f"[DEBUG] {e = }")
```

## 구조 분석

### 파라미터
- N = p·q (137-bit primes 2개)
- m = flag (비밀)
- LCG: `e' = 3e + 1337 mod N`
- 137쌍의 `(r_i, debug_e_i)` 제공

### 각 반복
1. e₁ = lcg(e_prev) → e₂ = lcg(e₁)
2. 출력: `r = m^{e₁} + m^{e₂} mod N` (N을 넘는 정수 합, mod N 아님 주의!)
3. 출력: `[DEBUG] e = <new_random_e>`
4. e를 새 랜덤 값으로 리셋

### 중요 관찰
- 각 쌍은 **독립** (e가 매번 랜덤 리셋)
- e₂ = 3·e₁ + 1337 mod N (LCG 관계)
- r = m^{e₁} + m^{e₂} (정수 합, N을 넘을 수 있음)
- N이 274-bit → 쉽게 인수분해 가능

## 풀이 전략

### Phase 1: 수식 변환
`r = m^e + m^{3e+1337 mod N}` 에서, `N < 3e+1337 < 2N`이면:
```
r ≡ m^e + m^{3e+1337-N} (mod N)
```
변수 치환: `x = m^{e+(1337-N)/2}`, `z = m^{(1337-N)/2}`
→ `x³ + x ≡ r·z (mod N)`

p, q 별로 독립 풀이.

### Phase 2: LLL (Small Relations)
`Σ c_i · e_i ≡ 0 (mod p-1)` with small c_i
→ `Π (m^{e_i})^{c_i} · z^c ≡ 1 (mod p)`

최적 파라미터: k=8, 양수 4개 + 음수 4개

### Phase 3: Algebraic Number Theory
- x_i는 F_p[z] 위의 차수 3 대수적 수
- Companion matrix의 거듭제곱으로 x_i^{c_i}의 최소다항식 계산
- Newton's identities로 곱의 계수를 O(mn)에 계산

### Phase 4: Polynomial Solving
- 양수/음수 파트 분리 → 이변수 → resultant로 t 소거
- Fast Lagrange interpolation (연속 평가점, O(n))
- 두 다항식의 GCD로 z 복원
- z = m^{(1337-N)/2} → m 복원

## 계산 시간 (저자 기준)
| 단계 | 시간 |
|------|------|
| LLL | ~1시간 |
| z 평가 | ~2시간/다항식 × 4개 |
| Lagrange 보간 | ~50분/다항식 |
| GCD | ~20분 |
| **총** | **~10시간** |

## 선행 문제
- **lance-hard?** (KalmarCTF 2025): 타원곡선 버전, Wagner's Birthday + Semaev polynomials
- **RBG** (Daily Alpacahack): 원본 문제

## 핵심 기법
- LLL lattice reduction for exponent relations
- Algebraic number theory over F_p[z]
- Newton's identities / power sums
- Fast Lagrange interpolation
- Half-GCD for large polynomials
- Companion matrix for algebraic number operations
