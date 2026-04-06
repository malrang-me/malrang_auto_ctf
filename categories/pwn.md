# PWN — Binary Exploitation

## MCP Tools
- **pwn-local**: checksec, readelf, objdump, ROPgadget, run_solve (timeout up to 600s)
- **py-repl**: offset calculations | **solver-z3**: complex input validation
- WSL: `gdb`, `one_gadget`, `ropper`, pwntools, `seccomp-tools`, `patchelf`

## Pwn-Specific Tools (added in v3)
| Tool | Purpose | Replaces |
|---|---|---|
| `tools/pwn_setup.py` | libc 버전 고정 + patchelf + one_gadget/symbol 추출 → `libc_offsets.json` | 시스템 libc 사용으로 인한 오프셋 어긋남 |
| `tools/gdb_pwn.py cyclic` | BOF offset 단일 호출 측정 | break/run/x 반복 (~15회) |
| `tools/gdb_pwn.py heap` | tcache/fastbin/unsorted JSON 덤프 | pwndbg 수동 명령 (~10회) |
| `tools/gdb_pwn.py trace-leak` | leak 후보 reg+mem 동시 출력 | break + info reg + x/8gx |
| `tools/gdb_pwn.py canary` | 카나리 위치 + 버퍼 크기 자동 추출 | objdump grep |
| `tools/gdb_pwn.py inspect` | 다중 BP 단일 GDB 실행 dump | 반복 break/continue |
| `tools/one_gadget_check.py` | one_gadget 제약 조건 자동 검증 + 랭킹 | 텍스트 읽고 GDB 수동 |

## Pwn 템플릿 (chain agent는 새로 짜기 전에 먼저 Read)
| Template | When |
|---|---|
| `templates/heap_attacks.py` | UAF / double-free / unsorted leak / FSOP (5개 패턴) |
| `templates/srop_frame.py` | 짧은 BOF + syscall 가젯 / 정적 바이너리 |
| `templates/seccomp_orw.py` | execve 차단 → ORW 셸코드 또는 ROP |
| `templates/exploit.py` | 일반 ret2libc / ret2csu (스텁) |

## Mandatory First Steps
1. `pwn_checksec` → protections
2. `python tools/ida_auto.py open <binary>` → IDA 자동 실행 (실패 시 Ghidra fallback)
3. IDA/Ghidra로 main, vuln 함수 디컴파일 (objdump -d 전체는 **절대 금지**)
4. **`python tools/pwn_setup.py challenges/<name>`** — libc 버전 고정 + 오프셋 추출
   (제공된 libc.so.6 vs WSL 시스템 libc 비교, patchelf, one_gadget, symbols → `libc_offsets.json`)
5. **`wsl seccomp-tools dump <binary> > seccomp_dump.txt`** — seccomp 정책 덤프
   (없으면 무시, 있으면 reversal_map.md `Binary Info`에 `execve_blocked`/`allowed_syscalls` 기재)
6. libc 미제공 시: `wsl ~/libc-database/identify` 로 후보 식별 → 다운로드 후 4번 재실행
7. Check Dockerfile for exact env

## Libc 버전 불일치 (false-positive #1 원인)
- 바이너리는 glibc A로 빌드, 로컬 WSL은 glibc B → one_gadget/system/__free_hook 오프셋 전부 다름
- 로컬 테스트는 통과 (양쪽 모두 잘못된 libc로 일관) → 리모트 크래시
- **방지**: chain agent solve.py 는 반드시 `libc = ELF('./libc.so.6')` 명시 로딩 +
  `libc_offsets.json`에서 오프셋 읽기 + 로컬 실행은 `<binary>.patched` 또는
  `process([ld.path, elf.path], env={'LD_PRELOAD': libc.path})`
- critic Stage 4가 위반 시 자동 REJECT

## Attack Patterns

### Stack
- BOF → overwrite return, ROP chain
- Canary leak → format string `%p` or brute byte-by-byte (fork server)
- Partial overwrite → low bytes only (no full leak)
- Stack pivot → `leave; ret` to controlled buffer
- SROP → sigreturn frame

### Format String
- Read: `%N$p` leak stack (canary, PIE, libc)
- Write: `%N$hhn`/`%N$hn` arbitrary address
- GOT overwrite → redirect to system/one_gadget

### Heap
- UAF → tcache poisoning (fd overwrite)
- Double free → tcache dup → arbitrary alloc
- Tcache struct abuse → corrupt perthread_struct
- Large bin attack → arbitrary qword overwrite

### GOT / ROP
- Partial RELRO → direct GOT overwrite
- Full RELRO → __malloc_hook, vtable pointers
- ret2libc / ret2csu / one_gadget / ret2dlresolve

## Token-Efficient Tool Chain (IDA급 절감 도구)
```bash
# one_gadget: ROPgadget 5000줄 → 3-5줄 (99% 절감)
wsl one_gadget ./libc.so.6

# libc-database: strings 수백줄 → 1줄 식별 (99% 절감)
wsl ~/libc-database/identify <libc>
wsl ~/libc-database/find puts 0x875a0

# seccomp-tools: strace 수백줄 → 10줄 정책 테이블 (95% 절감)
wsl seccomp-tools dump ./binary

# pwndbg/GEF: raw GDB 출력 → 구조화된 정보 (50% 절감)
# heap, got, canary 등 한 줄 명령으로 확인
```

## Chain Priority
- **A**: leak-based deterministic (leak canary/PIE/libc → ROP → shell)
- **B**: partial overwrite + limited brute (1/16 or 1/256)
- **C**: environment-dependent (one_gadget, specific libc)

## Pitfalls
- one_gadget: ALWAYS verify constraints. Never blindly use.
- RIP control alone is NOT done. Must get shell/flag.
- pwntools: `wsl python3 exploit.py` for reliability.
- x86_64: 16-byte RSP alignment before call. Add `ret` gadget.
- PIE + canary: need 2 separate leaks.
- ASLR brute: 1/4096 feasible, 1/65536 not.

## Primitive Sequencing
1. Primitive acquisition → 2. Info leak → 3. Control transfer → 4. Payload delivery
Each stage MUST be verified before advancing.

## Advanced (L4+ only)
- CFI/CET bypass, ARM PAC, non-x86 exploitation
- Windows: SEH overwrite, LFH exploitation
- Kernel: modprobe_path, cross-cache, io_uring
