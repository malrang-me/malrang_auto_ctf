# TOCTOU Race Condition

## 개요
Time-of-Check-Time-of-Use: 검증 시점과 사용 시점 사이의 간격을 악용.
파일 시스템, 웹 서버, 인증 체크 등에서 발생.

## Web/파일 서버 TOCTOU (GoN 2022F Heliodor 패턴)

### 취약 코드 패턴
```javascript
// Express.js
const stat = await fs.stat(filepath);    // 1) 파일 크기 확인
// ... 시간 간격 ...
const stream = fs.createReadStream(filepath, { end: stat.size }); // 2) 파일 읽기
```
1과 2 사이에 filepath가 가리키는 대상이 변경되면 다른 파일을 읽을 수 있음.

### /proc 파일 leak 기법
- `/proc` 파일은 `stat()`에서 size=0 반환 → 직접 읽기 불가
- fd 재사용 트릭:
  1. 요청 A: 큰 파일 open → fd N 할당
  2. 요청 B: fd N close
  3. 요청 C: `/proc/self/environ` open → fd N 재할당
  4. `/proc/self/fd/N` symlink는 이제 environ을 가리킴
  5. stat은 이전 큰 파일의 size를 캐시 → 그 크기만큼 읽기

### 공격 조건
- 3개+ 동시 요청 (레이스 윈도우 확보)
- path traversal 가능 (또는 `/proc/self/fd/` 접근 가능)
- stat과 read 사이에 간격 존재

## 일반적 TOCTOU 패턴

### 파일 시스템
```c
if (access(path, W_OK) == 0) {  // check
    // ... 다른 프로세스가 path를 symlink로 변경 ...
    open(path, O_WRONLY);        // use → 다른 파일 열림
}
```

### 인증
```python
if user.is_admin:               # check
    # ... 다른 요청이 user.is_admin을 변경 ...
    perform_admin_action()       # use
```

### 파일 업로드
```python
if is_safe_extension(filename):  # check
    # ... 파일명 변경 ...
    save_file(filename)          # use
```

## 탐지 시그널
- stat/access 후 open/read/write 분리
- 멀티스레드/비동기 파일 처리
- symlink 가능한 경로 + 권한 검사 분리
- `/proc/self/fd/` 접근 가능

## 공격 도구
```python
# Python 동시 요청
import threading, requests
threads = [threading.Thread(target=race_request, args=(i,)) for i in range(100)]
for t in threads: t.start()
for t in threads: t.join()
```

## 참고
- GoN 2022F F. Heliodor (2 solves)
- CWE-367: TOCTOU Race Condition
