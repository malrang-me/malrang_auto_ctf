# FORENSICS — Digital Forensics

## Tools (priority order — 토큰 절감 핵심)
- **tshark** (PCAP — 전체 덤프 대비 100x 절감):
  ```bash
  wsl tshark -r <file> -qz io,phs                        # 프로토콜 요약 (1줄)
  wsl tshark -r <file> -qz conv,tcp                       # TCP 연결 요약
  wsl tshark -r <file> -Y "http" -T fields -e http.request.uri -e http.response.code
  wsl tshark -r <file> -Y "dns" -T fields -e dns.qry.name
  wsl tshark -r <file> -qz follow,tcp,ascii,0             # 첫 스트림만
  ```
  **Rule**: pcap → tshark 필터만. `tcpdump | strings` = **절대 금지** (5만+ 토큰).
- **exiftool** (JSON + jq):
  ```bash
  wsl exiftool -j <file> | jq '.[0] | {Comment, Author, GPS*, Software}'
  ```
  verbose 텍스트 출력 금지. `-j` + `jq` 필수.
- **py-repl**: PIL, struct, binascii
- WSL: binwalk, foremost, steghide, volatility3, strings, xxd, file

## First Steps
1. `file` all files
2. `exiftool -j | jq keys` (키만 확인)
3. `strings | grep -iE 'flag|DH\{|CTF\{'` (**필터 필수**, 전체 금지)
4. `binwalk`
5. Visual inspect if image

## Stego Decision Tree
```
PNG/BMP → zsteg (LSB)
JPEG → stegsolve + steghide (password: empty, common)
WAV/audio → spectogram (Audacity/sox)
Text → whitespace/zero-width decode
```

## PCAP Decision Tree
```
1. tshark -qz io,phs → 프로토콜 분포 확인
2. HTTP 있으면 → tshark -Y http → URI + status 확인
3. DNS 있으면 → tshark -Y dns → exfil 패턴 확인
4. TCP stream → follow,tcp,ascii,0 (첫 스트림만)
5. 파일 추출 → tshark --export-objects
```

## Memory Decision Tree
```
1. volatility3 -f dump.raw windows.info → OS 확인
2. windows.pslist → 프로세스 목록
3. 의심 프로세스 → windows.dumpfiles --pid X
4. strings on dump → grep flag format
```

## Attack Patterns
- **File Carving**: binwalk -e, foremost, polyglot, corrupted headers
- **Stego**: 위 decision tree 참조
- **Memory**: 위 decision tree 참조
- **Network**: 위 PCAP decision tree 참조
- **Disk**: autopsy/sleuthkit, hidden partitions, ADS (NTFS)
- **Encoding**: multi-layer (base64→hex→rot13→XOR), QR codes
