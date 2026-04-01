# LLL + Algebraic Number Theory for Polynomial Root Finding

## 개요
모듈러 지수 방정식에서 비밀 값을 복원하는 고급 기법.
LLL로 지수 간 작은 관계식을 찾고, 대수적 수 이론으로 다변수 다항식을 효율적으로 단변수로 축소.

## 적용 조건
- `r_i = m^{e_i} + m^{e_i'} mod N` 형태 (지수가 선형 관계)
- N이 작은 소수 곱 (인수분해 가능)
- 여러 쌍의 (e, r) 데이터 제공

## 1단계: 수식 정리 (Monic 변환)

`e' = 3e + 1337 mod N`일 때, `N < 3e + 1337 < 2N`이면:
```
m^e + m^{3e+1337-N} ≡ r (mod N)
```
변수 치환: `x = m^{e + (1337-N)/2}`, `z = m^{(1337-N)/2}` → monic 형태:
```
x³ + x ≡ r·z (mod N)
```
- z는 모든 쌍에서 상수 (미지수이지만 공통)
- p, q 별로 독립 풀이 가능

## 2단계: LLL로 작은 관계식 찾기

### 목표
`Σ c_i · e_i ≡ 0 (mod p-1)` (작은 c_i)

→ `Π (m^{e_i})^{c_i} ≡ 1 (mod p)` (곱 관계)

### 격자 구성
z도 m의 거듭제곱이므로 LLL에 포함 가능:
```
Π (m^{e_i})^{c_i} · z^c ≡ 1 (mod p)
```

### 파라미터 선택
- k=8이 최적 (양수 4개 + 음수 4개로 균형)
- 최종 다항식 차수 ≈ `3^k · c + 3^{k-1} · max{Σ양수ci, Σ음수(-ci)}`
- 실전: ~2^25 차수

## 3단계: 대수적 수 기법으로 단변수 축소

### 핵심 아이디어
`x_i³ + x_i ≡ r_i·z (mod p)`에서 x_i는 "F_p[z] 위의 대수적 수"

### Prop 1: 거듭제곱
f(α)=0인 차수 d 대수적 수에서, t=α^k도 차수 d.
- f의 companion matrix M의 M^k의 특성다항식이 t의 최소다항식

### Prop 2: 곱
f(α)=0 (차수 m), g(β)=0 (차수 n)일 때, t=α·β는 차수 m·n.
- `Π_{i,j}(x - α_i·β_j)`의 계수는 대칭 다항식 → f,g의 계수로 계산 가능

### Newton's Identities로 효율적 계산
- Power sums: `p_k = Σα_i^k`, `q_k = Σβ_j^k`
- 곱의 power sum: `Σ(α_iβ_j)^k = p_k · q_k`
- Power sums ↔ 기본 대칭 다항식 변환: Newton's identities
- **시간복잡도: O(mn)** (resultant보다 훨씬 빠름)

## 4단계: 다항식 풀기

### 양수/음수 분리
```
t ≡ Π_{i=1}^4 (m^{e_i})^{c_i} · z^c (mod p)    [양수 파트]
t ≡ Π_{i=5}^8 (m^{e_i})^{-c_i} (mod p)          [음수 파트]
```
각 파트를 (t, z)의 이변수 다항식으로 축소 → resultant로 t 소거

### Fast Lagrange Interpolation
- 연속 평가점 사용 → O(n) 보간
- z에 랜덤 값 대입하여 F_p[z] → F_p 매핑, 나중에 보간

### GCD로 근 찾기
- 직접 `gcd(f, z^p - z)`: 차수 ~2^25에서 NTL FFT 실패 가능
- 대안: 두 개의 최종 다항식 생성 → 서로 GCD → ~20분

## lance-hard? (선행 문제) 핵심 차이점

| | lance-hard? | RBG+++ |
|---|---|---|
| 구조 | 타원곡선 x좌표 합 | 모듈러 지수 합 |
| 관계식 찾기 | Wagner's Birthday (±1 계수) | LLL (작은 정수 계수) |
| 다항식 구성 | Semaev summation polynomial | 대수적 수 이론 |
| 풀이 시간 | ~40분 (최적화) | ~10시간 |

### lance-hard? Wagner's Birthday 기법
- 1000개 샘플을 4그룹으로 분할
- 각 그룹 내 (250 choose 3)×2³ 조합 생성
- Birthday attack으로 12개 ±1 관계 탐색
- Semaev S₃ 재귀적으로 S₁₂ 구성

### lance-hard? Fast Root Finding
```python
# gcd(f, x^p - x)로 선형 인수만 추출 → <0.5초
g = pow(r, p, f) - r
roots = f.gcd(g).roots()
```

## 탐지 시그널
- `m^e + m^{f(e)} mod N` 형태 (지수에 선형/다항식 관계)
- N이 작은 소수 곱 (인수분해 가능)
- 다수의 (e, r) 쌍 제공
- LCG/LFSR로 지수 생성

## 계산 요구사항
- SageMath + NTL (다항식 GCD, FFT)
- Cython/pyx 가속 권장
- 멀티스레드 평가 가능
- 메모리: 16GB+ (대규모 다항식)

## 참고
- KalmarCTF 2026 RBG+++ (Sceleri writeup)
- KalmarCTF 2025 lance-hard? (Neobeo writeup)
- Daily Alpacahack RBG (선행 문제)
