# GDB Python Scripting for CTF

## 개요
복잡한 연산을 리버싱하기 어려울 때, GDB Python API로 함수를 반복 실행하며
I/O 매핑을 브루트포스하는 기법.

## 사용 시나리오
- 연산이 복잡하지만 입력 공간이 작을 때 (1~3 바이트 단위)
- 함수가 순수 함수 (side-effect 없음)
- 비교 테이블이 주어져 있을 때

## 핵심 패턴

### 레지스터 설정 + 실행 + 결과 읽기
```python
#!gdb ./binary -x
import gdb

target_table = [0xAB1FF171, 0x116437CE, ...]  # 기대값
results = [None] * len(target_table)

class InputBreakpoint(gdb.Breakpoint):
    """함수 진입점에서 입력 레지스터 설정"""
    def stop(self):
        global current_a, current_b
        gdb.execute(f"set $rdi={(current_a << 8) | current_b}")
        return False  # 멈추지 않고 계속 실행

class OutputBreakpoint(gdb.Breakpoint):
    """결과 비교점에서 출력 읽기"""
    def stop(self):
        global current_a, current_b
        rax = int(gdb.execute("p $rax", to_string=True).split("=")[1].strip())
        rax &= 0xFFFFFFFFFFFFFFFF

        if rax in target_table:
            idx = target_table.index(rax)
            results[idx] = chr(current_b) + chr(current_a)

        # 다음 입력으로 진행
        advance_input()
        gdb.execute("set $rip=FUNC_START_ADDR")  # 함수 처음으로 점프
        return False

gdb.execute("file ./binary")
gdb.execute("aslr off")
InputBreakpoint("* FUNC_ENTRY_ADDR")
OutputBreakpoint("* CMP_ADDR")
gdb.execute("r dummy_input")
```

### 핵심 트릭
1. **`set $rip`로 함수 반복**: 프로세스를 재시작하지 않고 PC를 함수 시작으로 리셋
2. **`return False`**: 브레이크포인트에서 멈추지 않고 자동 진행
3. **ASLR off**: 주소 고정으로 브레이크포인트 안정화

## 성능
- 2바이트 브루트포스 (printable): ~95 * 95 = 9,025 시도
- GDB 오버헤드: 시도당 ~1ms → 총 ~10초
- 3바이트: ~857,375 시도 → ~14분 (아직 실용적)

## 대안
- `angr`로 심볼릭 실행 (더 우아하지만 설정 복잡)
- `unicorn` 에뮬레이션 (GDB보다 빠름)
- `frida` instrumentation (동적 바이너리)

## 관련 문제
- GoN 2022 D. Nonsense: 48바이트를 2바이트 단위로 GDB 브루트포스
