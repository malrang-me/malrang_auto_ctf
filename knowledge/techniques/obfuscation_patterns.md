# Obfuscation Pattern Database

리버싱 에이전트가 난독화 탐지 시 참조하는 패턴 DB.
각 패턴: 탐지 시그니처 + 디옵퓨스케이션 전략 + 자동화 도구.

---

## 1. Opaque Predicates

### 1a. getauxval(AT_HWCAP)
- **시그니처**: `getauxval(6)` → `(val-1) & val == 0` 분기
- **동작**: x86-64 WSL2에서 AT_HWCAP=0x1000 (power of 2) → 조건 항상 참
- **코드 팽창**: ~5x (각 연산이 opaque guard 포함)
- **탐지**: IDA `imports` → getauxval 존재 + `decompile` → 반복 분기 패턴
- **제거**: IDA `py_eval`로 dead branch NOP, 또는 `gdb_auto.py patch`
- **실전 예시**: Mirage (DH Level 7)

### 1b. MBA (Mixed Boolean-Arithmetic)
- **시그니처**: `x*(x-1)%2 == 0`, `(x|y) - (x&y) == x^y` 등 항등식
- **동작**: 수학적으로 항상 참/거짓인 복잡한 표현식
- **탐지**: decompile에서 비정상적으로 긴 조건문 + 비트 연산 조합
- **제거**: Z3로 조건 simplify → 상수로 치환, 또는 SSPAM/MBA-Blast 도구

### 1c. 상수 비교 (Trivial Opaque)
- **시그니처**: `if (0x12345 == 0x12345)`, `if (1)`
- **동작**: 컴파일러가 최적화하지 못하도록 volatile/indirect로 숨김
- **탐지**: IDA decompile에서 상수 조건 검색
- **제거**: dead branch 제거 (NOP)

### 1d. Hash-Based Opaque
- **시그니처**: `CRC32(constant_string) == known_hash`
- **동작**: 런타임에 해시 계산 → 항상 동일 결과
- **탐지**: CRC32/MD5/SHA 함수 호출 + 상수 인자
- **제거**: GDB에서 실행하여 결과 확인 → 분기 고정

---

### 1e. rand()%N Switch-Case (Runtime Opaque)
- **시그니처**: `srand(seed); ... switch(rand()%N) { case 0: ... case 1: ... }` — 모든 case가 동일 결과
- **동작**: 런타임에 랜덤 분기하지만 모든 경로가 같은 연산을 수행 → 코드 N배 팽창
- **코드 팽창**: Nx (N=4이면 4배, .text 120KB+ 가능)
- **탐지**:
  - `ida_meta.json`의 imports에 `rand`/`srand` 존재 + `xrefs_to_interesting`에 다수 호출처
  - `Grep "rand" decompiled/` → switch/case 다수 발견
- **핵심 규칙**: **case 1개만 분석하면 됨. 나머지 N-1개는 무시.**
- **headless 패치 (선택)**: rand() 호출을 `xor eax, eax`로 치환해 항상 case 0 실행:
  ```bash
  cat > /tmp/nop_rand.py <<'PY'
  import idautils, idc
  for ea in idautils.Names():
      if "rand" not in ea[1]:
          continue
      # call rand -> xor eax, eax; nop; nop; nop
      for xref in idautils.CodeRefsTo(ea[0], 0):
          idc.patch_byte(xref,   0x31)
          idc.patch_byte(xref+1, 0xC0)
          for i in range(2, 5):
              idc.patch_byte(xref+i, 0x90)
  PY
  python tools/ida_headless.py patch <binary> --script /tmp/nop_rand.py -o <binary>.patched
  python tools/ida_headless.py full <binary>.patched --challenge-dir challenges/<name>
  ```
- **실전 예시**: cipher (DH Level 3) — rand()%4로 4경로, 모두 AES-like 연산

## 2. Control Flow Flattening (OLLVM)

- **시그니처**: `while(1) { switch(state_var) { case 0: ... state_var=3; break; ... } }`
- **구조**: 단일 dispatcher 블록 + state 변수가 모든 전환 제어
- **탐지**: IDA `basic_blocks` → switch 블록에 10+ case + 단일 state 변수
- **특징**: 실제 실행 순서와 코드 순서 불일치, 모든 블록이 switch로 복귀
- **제거 전략**:
  1. GDB trace로 실제 state 전이 순서 기록
  2. state 변수 값 → 블록 매핑 테이블 구축
  3. 실행 순서대로 블록 재배치 → 선형 코드 복원
- **도구**: deflat.py (OLLVM deflattening), D-810 (IDA plugin)

---

## 3. Dead Code Insertion

- **시그니처**: unconditional jump 뒤 unreachable 코드, `break` 즉시 실행하는 루프
- **탐지**: IDA `basic_blocks` → 진입 불가 블록 (xref 없음)
- **제거**: NOP 또는 블록 삭제
- **영향**: 코드 크기 1.5~3x 증가, 분석 복잡도 증가

---

## 4. Instruction Substitution

- **시그니처**: 단순 연산을 복잡한 등가 연산으로 치환
  - `ADD a,b` → `SUB a, NEG(b)` 또는 `(a^b) + 2*(a&b)`
  - `XOR a,b` → `(a|b) & ~(a&b)` 또는 `NOT(AND(a,b)) AND OR(a,b)`
  - `MOV rax,0x41` → `MOV rax,0x20; ADD rax,0x21`
- **탐지**: 연속 NOT/AND/OR 패턴 = 단일 XOR, 불필요한 분리 연산
- **제거**: peephole optimization (패턴 매칭 → 단순화)

---

## 5. String Encryption

### 5a. XOR Loop Decrypt
- **시그니처**: 루프에서 XOR + 고정 키로 문자열 디코딩
- **탐지**: `strings` 결과 비정상적으로 적음 + memcpy/strcpy xref 다수
- **추출**: GDB bp on decrypt 함수 완료 시점 → 메모리 덤프

### 5b. Stack String Construction
- **시그니처**: `mov byte [rsp+0], 'H'; mov byte [rsp+1], 'e'; ...`
- **탐지**: 연속 mov byte 명령어 + 즉치값이 printable ASCII
- **추출**: IDA에서 직접 읽기 가능 (디컴파일러가 보통 복원)

### 5c. RC4/AES Runtime Decrypt
- **시그니처**: 키 스케줄링 루프 (256-byte S-box 초기화) + 암호화 함수 호출
- **탐지**: imports에 crypto 라이브러리 또는 특징적 상수 (AES: 0x63636363)
- **추출**: GDB bp after decrypt → dump

---

## 6. Import Obfuscation

### 6a. Dynamic Resolution (Linux)
- **시그니처**: `dlopen`/`dlsym` 호출, 또는 직접 syscall (`syscall` insn / `int 0x80`)
- **탐지**: import 테이블 비정상적으로 적음 + dlsym xref
- **추출**: GDB bp on dlsym → 첫 번째 인자 로그

### 6b. Dynamic Resolution (Windows)
- **시그니처**: `GetProcAddress`/`LoadLibrary` 반복 호출
- **탐지**: imports에 kernel32 + GetProcAddress만 존재
- **추출**: 디버거에서 GetProcAddress 인자 로그

---

## 7. Anti-Debug (Comprehensive)

### Linux
| 기법 | 시그니처 | 바이패스 |
|------|---------|---------|
| ptrace(TRACEME) | `call ptrace` / syscall 101 | LD_PRELOAD return 0 / GDB `set $rax=0` |
| TracerPid | `fopen("/proc/self/status")` | LD_PRELOAD fopen hook / `set $rax=0` |
| timing check | `clock_gettime`/`gettimeofday` | LD_PRELOAD 고정 시간 반환 |
| alarm() | `call alarm` | LD_PRELOAD return 0 / `set $rdi=0` |
| SIGTRAP handler | `signal(5, handler)` + `int3` | GDB `handle SIGTRAP nostop` |
| /proc/self/maps | `fopen("/proc/self/maps")` | LD_PRELOAD hook |
| getauxval | `getauxval(AT_*)` | LD_PRELOAD 고정값 반환 |
| prctl(PR_SET_DUMPABLE) | `prctl(4, 0)` | LD_PRELOAD return 0 |

### Windows
| 기법 | 시그니처 | 바이패스 |
|------|---------|---------|
| IsDebuggerPresent | import 또는 PEB.BeingDebugged | `mov byte [PEB+2], 0` |
| CheckRemoteDebugger | API 호출 | return FALSE hook |
| NtQueryInformationProcess | ProcessDebugPort (0x7) | return 0 hook |
| DR0-DR7 검사 | `mov rax, dr0` / GetThreadContext | context 조작 |
| OutputDebugString timing | 호출 전후 시간 비교 | timing 고정 |
| int 2d / int 3 | 예외 핸들러 기반 | SEH chain 조작 |

### 탐지 자동화
```bash
python tools/gdb_auto.py detect ./binary
# 출력: {"ptrace": true, "timing": false, "alarm": true, "tracerpid": false, ...}
```

---

## 8. Self-Modifying Code (SMC)

- **시그니처**: mprotect(PROT_WRITE|PROT_EXEC) + .text 섹션 쓰기
- **탐지**: mprotect import + 실행 코드 영역 쓰기 패턴
- **분석**: GDB bp on mprotect → 수정 후 코드 덤프
- **주의**: 정적 분석 결과가 실행 시 코드와 다름

---

## 9. Packing/Encryption

| 패커 | 탐지 | 언패킹 |
|------|------|--------|
| UPX | `strings \| grep UPX` | `upx -d` |
| ASPack | 섹션 이름 `.aspack` | OEP 추적 후 덤프 |
| Themida | 섹션 `.themida` | 동적 덤프 (Scylla) |
| VMProtect | VM dispatcher 패턴 | 동적 트레이싱 + 부분 복원 |
| Custom | entry point가 비표준 섹션 | GDB hardware bp on OEP |

---

## 10. 빠른 판별 플로우차트

```
1. strings 결과 < 10개? → 패킹 또는 string encryption (§5, §9)
2. import 테이블 < 5개? → import 난독화 (§6)
3. .text 100KB+ 또는 함수 50개+? → 난독화 의심 → 4-6 확인
4. rand/srand import + switch(rand()%N)? → runtime opaque (§1e) → case 1개만 분석!
5. decompile 500줄+? → opaque predicate 또는 CFF (§1, §2)
6. switch문에 10+ case + state 변수? → OLLVM CFF (§2)
7. getauxval/ptrace/alarm import? → anti-debug (§7)
8. mprotect(PROT_WRITE) import? → SMC (§8)
9. 위 해당 없음 → 난독화 아닐 가능성 높음
```
