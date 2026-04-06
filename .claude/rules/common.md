# Shared Rules (all agents inherit)

## Iron Rules (Universal)
1. **NEVER submit flags** — report to user only. User submits manually.
2. Evidence-based only — every claim needs tool output proof.
3. Anti-soliloquying — never claim results without actual execution logs.

## Failure Classification
- **L1 Transient**: Network timeout, tool crash → retry same approach
- **L2 Tool-specific**: Wrong params, syntax error → adjust params or switch tool
- **L3 Methodology**: Wrong attack vector → pivot strategy entirely
- **L4 Reasoning**: Fundamental misunderstanding → re-read challenge from scratch
Same-level failures compound: 3× L2 → escalate to L3. 3× L3 → escalate to L4.

## Loop Detection
- **3 same-signature failures**: MUST change assumption/approach. Write to `memory/failures.md`.
- **5 same-signature failures**: HARD STOP. Switch to fundamentally different approach.

## Library Preference
1. Crypto: SageMath > gmpy2 > pycryptodome > sympy > custom
2. Pwn: pwntools > ropper > manual ROP
3. Web: requests/curl > custom HTTP
4. Rev: Z3 > angr > manual constraint solving

## KB Shortcut Discipline (모든 에이전트 적용)

### 1. Recon 단계 — 항상 활성화 (무료, cap 없음)
**`triage.py`가 challenge별로 `[KB SHORTCUTS]` 섹션을 자동 주입한다.** 이 섹션은 kb.db에서 카테고리 라우팅으로 뽑은 HackTricks / PayloadsAllTheThings / ExploitDB / CISA KEV 상위 5건이다.

**모든 pipeline agent는 분석 시작 전에 이 섹션을 반드시 읽는다.** 매칭된 기법이 있으면 그대로 적용 — CWE 체크리스트나 처음부터 코드 작성 전에.

**추가 recon이 필요하면** (특정 기법/CVE/프레임워크가 명시적으로 보일 때):
```bash
python tools/midsolve_search.py recon "<keywords>" --category pwn|web|crypto|rev|forensics|web3|ai
```
- `recon` 모드는 **offline-only, cap 없음, staging 안 함, dedup 안 함**
- 카테고리별 `external_techniques.source_path` LIKE 필터로 노이즈 제거
- 자유롭게 호출 가능. 막히지 않았어도 OK.

### 2. Mid-solve 단계 — trigger 필수 (cap 4회)

**모르는 CVE / 소프트웨어 / 기법을 만났을 때**는 아래 mode를 사용 (cap 있음):

```bash
python tools/midsolve_search.py cve <CVE-ID>              --challenge <name>
python tools/midsolve_search.py software "<name version>" --challenge <name>
python tools/midsolve_search.py technique "<keywords>"    --challenge <name> --category <cat>
# offline 결과가 0개일 때만:
python tools/midsolve_search.py technique "..." --challenge <name> --web
```

**Mid-solve Trigger (이 4가지 시그널 중 하나여야 발동):**
1. 챌린지 설명/바이너리 strings에 `CVE-\d{4}-\d+` 정규식 매치
2. Named software + version 명시 (예: `nginx 1.20.1`, `imagemagick 7.0.10`)
3. Reverser가 모르는 crypto primitive 명시 → solver 첫 실패 후
4. 같은 method-level 실패 3회 (3× L3) → 마지막 시도 전

**금지:**
- `WebSearch`/`WebFetch` 직접 호출 (midsolve_search 경유)
- mid-solve 모드(`cve`/`software`/`technique`)에서 trigger 없이 호출
- 같은 challenge에서 같은 query 재호출 (자동 dedup되긴 하지만 의도적 반복 금지)
- 호출 횟수 cap (challenge당 4회) 초과 시 critic/다른 접근으로 escalate
- **recon 모드는 위 금지사항에서 면제** (무료 + offline + cap 없음)

### 3. Offline 우선순위 (카테고리 라우팅 적용)
- `recon` 모드: external_techniques(카테고리 필터) → chunks → cisa_kev(web/pwn만)
- `cve` 모드: cisa_kev → exploitdb → external_techniques(필터) → chunks
- `software` 모드: exploitdb → cisa_kev → external_techniques(필터) → nuclei
- `technique` 모드: **pwn/web** 은 external_techniques 먼저, **crypto/rev** 는 chunks 먼저

### 4. 자동 persistence
- `recon` 모드는 staging 안 함 (cheap, 무한 호출 가능)
- mid-solve 모드 호출은 `knowledge/writeup_staging/midsolve_*.json`에 저장
- `post_solve.py`가 flag 발견 시 `succeeded=true` 자동 태그
- 다음 challenge에서 같은 pattern 만나면 kb.db에서 발견됨

## Tool Routing Fallback Chains
```
Binary analysis: checksec → readelf → objdump → strings
Decompile:       IDA MCP (if available) → Ghidra headless → objdump -d → gdb disas
Port scan:       nc -zv → python socket → nmap (WSL)
Web recon:       curl + jq → WebFetch → requests → Chrome MCP (최후 수단)
Crypto math:     sage-helper → solver-z3 → py-repl gmpy2
Forensics:       tshark (필터) → binwalk → strings (grep) → exiftool -j + jq
Web3:            forge test (no -vvvv) → cast (single call) → web3.py
API testing:     curl + jq 필터 → requests (절대 raw dump 금지)
```
**IDA MCP 강제 우선**: 바이너리 분석 시 반드시 `python tools/ida_auto.py check` 먼저 실행.
- 응답하면: **IDA MCP만 사용**. Ghidra/objdump 호출 금지.
- 응답 안 하면: Ghidra headless → objdump 순서로 fallback.
- IDA MCP 도구: `decompile`, `list_funcs`, `imports`, `xrefs_to`, `stack_frame`, `analyze_funcs` 등.

## Causal Reasoning Chain
```
Evidence (tool output)        → confidence: 0.9
  ↓ SUPPORTS
Hypothesis (inference)        → confidence: 0.5-0.8
  ↓ REVEALS (after verification)
Vulnerability (confirmed)     → confidence: 0.8+
  ↓ EXPLOITS
Exploit (executable payload)  → confidence: 0.9+
```
No hypothesis without evidence. No vulnerability without verified hypothesis. No exploit without confirmed vulnerability.

## Handoff Protocol
```
[HANDOFF from @<agent> to @<next_agent>]
- Finding/Artifact: <filename>
- Confidence: PASS / PARTIAL / FAIL
- Key Result: <1-2 sentence>
- Next Action: <specific task>
- Blockers: <if any, else "None">
```
**CRITICAL: Handoff prompt MUST be < 4k tokens.**
- 분석 결과는 파일(reversal_map.md 등)에 저장하고, 프롬프트에는 파일 경로만 전달.
- 디컴파일 출력, 어셈블리, 소스코드를 프롬프트에 직접 포함 **절대 금지**.
- 프롬프트에는: 핵심 요약 (vuln type, key values) + 파일 경로 + 다음 액션만.
- 다음 에이전트가 파일을 직접 Read해서 필요한 부분만 확인.

## Checkpoint (all agents)
```bash
python tools/checkpoint.py update <challenge_dir> --agent <name> --phase <N> --phase-name <name> --status in_progress
python tools/checkpoint.py complete <challenge_dir> --agent <name>
python tools/checkpoint.py fail <challenge_dir> --agent <name> --error "<reason>"
```

## Computation Offload (Token Savings)
NEVER reason through math in text. Offload ALL computation to MCP tools:
- **sage-helper**: `pow(c, d, n)`, `factor(n)`, `discrete_log()`, `LLL()`, `GF()` → result only
- **py-repl**: `gmpy2.iroot()`, `gmpy2.invert()`, hex conversions → 1-line result
- **solver-z3**: constraint models → SAT/UNSAT + model values
Example: RSA decrypt is `sage-helper: pow(c, d, n)` = 20 tokens, NOT 500 tokens of manual reasoning.

## Output Token Hygiene
- `objdump -d`: NEVER full output. Use `pwn_objdump` with `pattern` filter.
- `strings`: ALWAYS `grep -iE 'flag|key|password'`. Never unfiltered.
- JSON APIs: ALWAYS `jq` filter. Never raw JSON dumps.
- PCAP: ALWAYS `tshark` with display filter. Never full packet dumps.
- Ghidra decompile: one function at a time via `--func X --stdout`.

## Verification Checklist
1. Flag matches expected format (DH{...}, flag{...}, CTF{...})
2. Flag from actual execution output, NOT strings/placeholder/comments
3. For remote: flag from actual server, not local test
4. Reproducible on 2+ consecutive runs
