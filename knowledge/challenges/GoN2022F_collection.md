# 2022 Fall GoN Open Qual - Authors' Writeup Collection

> Source: https://hackmd.io/@Xion/goq_22f_authors_writeup
> Author: Xion (전 문제)
> 난이도: 고급 (최대 솔버 7팀, 0-solve 2개)

---

## F. Heliodor — Web (TOCTOU Race Condition)

**솔버**: 2팀

### 취약점
Express.js에서 `fs.stat()`과 `fs.createReadStream()` 사이의 **TOCTOU(Time-of-Check-Time-of-Use)** 레이스 컨디션.

### 추가 취약점: Path Traversal
- 정규식 `/[0-9A-Za-z_-]*/`가 빈 키 허용
- `path.resolve()`가 오른쪽→왼쪽 처리 → 절대경로 삽입 가능

### 공격 원리
`/proc` 파일시스템은 `stat()`에서 size=0 반환 → 정상적으로는 읽기 불가.
하지만 fd 재사용을 통한 레이스:

1. 요청 #1, #2: 서로 다른 파일 open (`/etc/passwd`, `/proc/self/environ`)
2. 요청 #3: `/proc/self/fd/N` symlink를 stat (큰 파일 가리킬 때)
3. stat과 stream 생성 사이에 fd N이 `/proc/self/environ`으로 재할당
4. 큰 파일의 size로 읽기 → 환경변수(플래그 포함) leak

### 패턴 인식
- Express.js + 파일 서빙 + stat/stream 분리 → TOCTOU
- `/proc` 파일은 stat size=0 → race 없이는 읽기 불가
- **3개 동시 요청**으로 fd 재사용 트리거

---

## G. Emerald Tablet — Web (Django dictsort 사이드채널)

**솔버**: 7팀
**관련 CVE**: CVE-2021-45116

### 취약점
Django `dictsort` 템플릿 필터의 **stable sort 속성**을 이용한 정보 유출.

### 공격 원리
1. 미지의 UUID를 포함한 레코드들과 함께 공격자 제어 레코드를 다수 삽입
2. 특정 문자 위치로 정렬 요청
3. Stable sort 특성: 같은 키의 원소는 원래 순서 유지
4. 정렬 전후 순서 변화 → 문자 크기 비교 관계 추론
5. Z3 solver로 부등식 제약 → UUID 문자 복원

### 솔버 방법론
```
1. 레코드 100+ 개 spray (통계적 유의성 확보)
2. 각 UUID 위치(0~31)에 대해 정렬 요청
3. 정렬 후 위치 변화로 부등식 제약 수집
4. Z3로 각 hex 문자 결정 (0-9, a-f)
```

### 패턴 인식
- Django + `dictsort` 필터 → CVE-2021-45116 사이드채널
- 정렬 결과만 관찰 가능 + 비밀 데이터 존재 → stable sort oracle

---

## H. Reconquista — Pwn (TLS Overflow → DTV → Heap)

**솔버**: 0팀

### 환경
C++ 바이너리, 스레드 기반, glibc

### 취약점
Thread Local Storage(TLS)의 `std::string` 배열 200개 중 경계 초과 쓰기 → TCB(Thread Control Block)의 `dtv` 포인터 덮어쓰기

### TCB 구조 (glibc)
```
[TLS 데이터] [tcbhead_t]
              ├── self pointer
              ├── dtv pointer ← 덮어쓰기 대상
              ├── ...
              └── stack_guard (카나리)
```
TLS가 TCB 바로 앞에 위치 → 선형 오버플로우로 dtv 도달 가능 (카나리 전에 55개 추가 포인터)

### 익스플로잇 체인
1. 200개 더미 노트 할당 (TLS 배열 채우기)
2. 노트 #200에 size=0x565 (0x140 + 0x420 + flags) 설정
3. 가드 청크로 consolidation 방지
4. dtv 포인터를 fake chunk 주소로 덮어쓰기
5. 스레드 exit/re-entry 시 `_dl_resize_dtv()` → `realloc(fake_chunk)` 트리거
6. fake chunk가 `tcache_perthread_struct`와 겹침 → tcache poisoning
7. heap 포인터 leak
8. `free@got` (libstdc++) → `system` 덮어쓰기
9. 문자열 재할당 시 `free(buffer)` → shell

### 패턴 인식
- 스레드 기반 + TLS 배열 오버플로우 → TCB dtv 포인터 조작
- `_dl_resize_dtv()`의 realloc이 fake chunk primitive 제공
- **glibc 내부 구조 지식 필수** (tcbhead_t, DTV 레이아웃)

---

## I. Redis-made — Pwn (CVE-2022-35951)

**솔버**: 0팀

### 환경
Redis 7.0.4

### 취약점
**CVE-2022-35951**: `XAUTOCLAIM` 명령의 `deleted_ids` 배열 할당 시 정수 오버플로우

```c
// count * sizeof(streamID)에서 오버플로우
zmalloc(count * sizeof(streamID))  // count가 매우 크면 작은 크기 할당
```

### 발견 방법론 (중요!)
1. CVE-2022-31144 패치 (PR #11002, Issue #10968) 분석
2. 같은 코드 영역에서 패치되지 않은 유사 취약점 발견
3. **패치 리뷰 → 파생 취약점 발견** 방법론

### 공격
- `count`에 `0x1000000000000000 + normal_count` 전달 → 작은 버퍼에 큰 데이터 쓰기
- streamID overflow로 Redis 객체 위조
- 임의 주소 읽기/쓰기 → RCE

### 패턴 인식
- Redis stream 명령 + 큰 count 파라미터 → 정수 오버플로우 확인
- **CVE 패치 분석 → 동일 코드 영역의 미패치 취약점** 은 CTF 출제의 단골 패턴

---

## J. NPU — Pwn (QEMU DMA MMIO Reentrancy → VM Escape)

**솔버**: 1팀

### 환경
커스텀 QEMU 디바이스 드라이버

### 취약점
**DMA MMIO Reentrancy** (논문: "Matryoshka Trap: Recursive MMIO Flaws Lead to VM Escape")

게스트의 DMA 버퍼 주소를 디바이스 MMIO 영역으로 설정하면:
- DMA 처리 중 MMIO 핸들러가 재귀적으로 호출됨
- 현재 노트가 freed 상태에서 접근 → **Use-After-Free**

### 익스플로잇 체인
1. MMIO 매핑 + DMA 버퍼 할당 (물리 메모리 연속성 확보)
2. 노트 할당 (0x405 크기, tcache 0x410 bin)
3. **DMA 버퍼를 MMIO 주소로 설정** → reentrancy 트리거
4. UAF로 tcache 메타데이터 leak → safe-linking 디코딩
5. heap base 계산 → **TCG RWX 영역** 주소 추론 (`heap & ~0xffffff + 0xc000000`)
6. tcache poisoning → RWX 영역에 노트 할당
7. shellcode 쓰기 + 실행 → **호스트 QEMU 프로세스 RCE**

### Safe-linking 디코딩
```c
// prot_ptr = ((heap_ptr + 0x820) >> 12) ^ heap_ptr
// 역산:
heap_ptr |= prot_ptr & (0xfffULL << 36);
heap_ptr |= (prot_ptr ^ (heap_ptr >> 12)) & (0xfffULL << 24);
heap_ptr |= (prot_ptr ^ (heap_ptr >> 12)) & (0xfffULL << 12);
heap_ptr |= (prot_ptr ^ (heap_ptr >> 12)) & 0xfffULL;
```

### Chained Recursive MMIO 패턴
```c
// RWvec의 DMA 주소를 MMIO 주소로 설정 → 재귀적 MMIO 실행
rwv_virt[0] = RWV(mmio_phys + WRITE_IDX, ...);          // MMIO write
rwv_virt[1] = RWV(mmio_phys + WRITE_NOTE_RESIZE, ...);  // 다른 MMIO 트리거
// → WRITE_NOTE_PROCESS_RWVEC가 이 RWvec을 처리하면서 재귀
```

### 패턴 인식
- QEMU 커스텀 디바이스 + DMA → MMIO reentrancy 확인
- DMA 버퍼 주소가 MMIO 영역을 가리키면 재귀 가능
- TCG RWX: QEMU의 JIT 코드 영역, heap 근처 고정 오프셋
- glibc 2.32+ safe-linking: `(ptr >> 12) ^ next` 디코딩 필요

### 참고
- "Matryoshka Trap" 논문
- https://ctftime.org/writeup/31188
- http://pzhxbz.cn/?p=164
