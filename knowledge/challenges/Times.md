# Times — Reversing | Dreamhack Level 4

## 개요

드림 콘서트 티켓 등록 프로그램. argv[1]로 티켓 등록 키를 입력받아 검증한다.
두 가지 보호 메커니즘이 있으나 둘 다 정상 실행 환경에서는 무력화되며,
실질적인 변환은 32비트 비트 반전(bit_reverse_32)만 남는다.
해당 변환이 자기 역함수이므로 목표 데이터에 그대로 적용하면 키가 나온다.

- **바이너리**: ELF 64-bit PIE, x86-64, dynamically linked, stripped
- **입력**: argv[1] (40바이트 ASCII)
- **플래그**: `DH{a20f984e48f83e69566e2aee17b491b7fc722ab2}`

---

## 보호 메커니즘

### 1. 시간 게이트 (.init_array, 0x17d0)

```c
if (time(0) <= 0x71ca77ff)   // 2030-06-30 23:59:59 UTC
    puts("Not yet !!! Please wait more time.");
    exit(0);
```

현재 시간이 2030년 이전이면 프로그램이 즉시 종료된다.
**우회**: `LD_PRELOAD`로 `time()`이 `0x71ca7800`을 반환하는 가짜 공유 라이브러리를 주입한다.

### 2. ptrace 안티디버그 (.init_array, 0x1800)

```c
long ret = ptrace(PTRACE_TRACEME, 0, 0x7470, 0x6172);
long val = (ret + 1) * 0x4d2;
*(uint16_t*)0x4048 ^= (uint16_t)val;
```

| 상황 | ptrace 반환값 | val | 0x4048 결과 |
|------|-------------|-----|------------|
| 일반 실행 | 0 | 0x04d2 | 0x04d2 XOR 0x04d2 = **0x0000** |
| 디버거 붙음 | -1 | 0 | 0x04d2 XOR 0x0000 = **0x04d2** |

일반 실행 시 0x4048이 0x0000이 된다. 이후 단계에서 이 값으로 XOR하면 항등 연산이다.

---

## 메인 검증 로직 (0x183e)

| 단계 | 동작 | 정상 실행 시 효과 |
|------|------|-----------------|
| 1 | `strdup(argv[1])`, `strlen` 확인 | 입력 복사 |
| 2 | `time(0)` → `srand` → `rand()+rand()` → MD5 → K1[16] | 키스트림 생성 |
| 3 | `input[i] ^= K1[...]` (각 바이트 XOR) | **변환 A** |
| 4 | `*(u16*)(input+j*2) ^= *(u16*)0x4048` | 0x0000이므로 **항등** |
| 5 | 동일 `time(0)` → 동일 seed → 동일 K2 == K1 | 키스트림 재생성 |
| 6 | `input[i] ^= K2[...]` | **변환 A 역원** (XOR 취소) |
| 7 | `*(u32*)(input+j*4) = bit_reverse_32(...)` | **변환 B** (유일 잔존) |
| 8 | `memcmp(input, target, 41)` | 목표와 비교 |

핵심 통찰:
- 단계 3과 6은 동일한 키스트림을 사용하므로 서로 상쇄된다 (`x XOR k XOR k = x`).
- 단계 4는 0x0000 XOR이므로 항등이다.
- **결과적으로 단계 7, bit_reverse_32만 실질적인 변환이다.**

---

## 공격 전략

`bit_reverse_32`는 자기 역함수(`f(f(x)) == x`)이므로, 목표 데이터에 `bit_reverse_32`를 적용하면 곧바로 등록 키를 얻는다.

```
registration_key = bit_reverse_32_on_each_word(target_data)
```

---

## 솔버 코드

`/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/Times/solve.py`

```python
import struct

target = bytes.fromhex(
    '660c4c86a62c1c9c1c661c2c9c6ca6cc'
    'a66c6caca6a6864c2c46ec8cec468c9c'
    '4cecc6664c46864cd2'
)

def bit_reverse_32(n):
    n &= 0xFFFFFFFF
    n = ((n & 0xAAAAAAAA) >> 1) | ((n & 0x55555555) << 1)
    n = ((n & 0xCCCCCCCC) >> 2) | ((n & 0x33333333) << 2)
    n = ((n & 0xF0F0F0F0) >> 4) | ((n & 0x0F0F0F0F) << 4)
    n = ((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)
    n = ((n >> 16) | (n << 16)) & 0xFFFFFFFF
    return n

result = bytearray(target)
for j in range(10):
    word = struct.unpack_from('<I', result, j*4)[0]
    struct.pack_into('<I', result, j*4, bit_reverse_32(word))

registration_key = result[:40].decode('ascii')
print(f"Registration key: {registration_key}")
print(f"Flag: DH{{{registration_key}}}")
```

---

## 검증

```bash
# faketime.c: time() 반환값을 0x71ca7800으로 고정
gcc -shared -fPIC -o /tmp/faketime.so faketime.c

# 바이너리 실행
LD_PRELOAD=/tmp/faketime.so ./times a20f984e48f83e69566e2aee17b491b7fc722ab2
# 출력: Welcome to registration center
#       Registration done !
```

---

## 실패 사례

없음. 분석 후 단번에 성공.

---

## 재사용 가능한 패턴

### 패턴 1: 키스트림 XOR 취소 인식

동일한 `time()` 호출을 seed로 사용하는 `srand`/`rand` 쌍이 두 번 XOR에 등장하면, 두 변환은 항등이다. 이 패턴을 발견하면 해당 XOR 단계를 제거하고 나머지 변환에 집중한다.

### 패턴 2: ptrace 안티디버그 + 전역 상수

ptrace 결과를 연산하여 전역 메모리의 XOR 키를 결정하는 패턴. 디버거 없이 실행하면 전역 상수가 0이 되어 무력화되는 경우가 많다. 정적 분석으로 초기값을 추적할 것.

### 패턴 3: 시간 게이트 LD_PRELOAD 우회

```c
// faketime.c
#include <time.h>
time_t time(time_t *tloc) {
    time_t t = 0x71ca7800;
    if (tloc) *tloc = t;
    return t;
}
```

```bash
gcc -shared -fPIC -o /tmp/faketime.so faketime.c
LD_PRELOAD=/tmp/faketime.so ./binary
```

### 패턴 4: 자기 역함수 변환 즉시 반전

`bit_reverse`, `byte_swap`, `nibble_swap` 등 자기 역함수인 변환은 목표 데이터에 동일 함수를 적용하면 역산이 끝난다. 암호화 역산 불필요.

---

## 플래그

```
DH{a20f984e48f83e69566e2aee17b491b7fc722ab2}
```
