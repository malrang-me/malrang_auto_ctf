# SSRF via TLS Session ID Poisoning

## 개요
Curl의 TLS 세션 재사용을 악용하여, 공격자 제어 Session ID를 내부 서비스(Memcached 등)에 주입하는 기법.
DNS rebinding과 결합하면 내부 네트워크 서비스에 임의 데이터를 전송할 수 있음.

## 탐지 시그널
- 서버가 pycurl/libcurl로 외부 URL을 fetch
- `SSL_VERIFYPEER=0`, `SSL_VERIFYHOST=0` (TLS 검증 비활성화)
- 내부에 Memcached/Redis 등 텍스트 프로토콜 서비스 존재
- Flask 세션이 Memcached 기반 (pickle deserialization)

## 공격 체인

### 1. DNS Rebinding 설정
```
attacker.com → 첫 번째 조회: 공격자 IP
                두 번째 조회: 내부 IP (127.0.0.1 등)
TTL = 0 (즉시 만료)
```

### 2. 악성 TLS 서버 준비
```python
# 공격자 TLS 서버
# ServerHello에 커스텀 Session ID (0x20 바이트) 포함
# Session ID = Memcached 명령어 인코딩
# 정상 HTTP 응답 후 redirect → 같은 도메인
```

### 3. Session ID가 Memcached로 전달되는 과정
```
1. Curl → attacker.com (공격자 IP로 해석)
2. TLS handshake: 공격자가 Session ID 설정
3. HTTP redirect → attacker.com (이번엔 내부 IP로 해석)
4. Curl이 같은 도메인이므로 TLS 세션 재사용 시도
5. ClientHello에 저장된 Session ID 포함
6. 내부 Memcached가 Session ID 바이트를 명령으로 해석
```

### 4. Pickle 주입
```python
# Session ID 안에 Memcached set 명령 인코딩
# Memcached에 Flask 세션 키로 pickle 데이터 저장
# Flask가 세션 로드 시 pickle.loads() 실행 → RCE 가능
```

## 핵심 트릭
- TLS Session ID는 최대 32바이트 → 페이로드 크기 제한
- Memcached 텍스트 프로토콜은 줄 단위 → Session ID에 `\r\n` 포함
- DNS rebinding TTL을 0으로 설정해 IP 전환 보장
- libcurl은 같은 호스트네임이면 TLS 세션 캐시 재사용

## 방어
- TLS 인증서 검증 활성화 (`VERIFYPEER=1`)
- 내부 서비스에 인증 필수 (Memcached SASL)
- DNS rebinding 방지 (private IP 차단)

## 관련 문제
- GoN 2022 G. Trino: Albireo (SSRF + TLS Session ID + Memcached + Pickle)
- 출처: https://hackmd.io/@Xion/goq_22s_authors_writeup
