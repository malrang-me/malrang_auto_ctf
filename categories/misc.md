# MISC — Miscellaneous

## Tools
- py-repl, solver-z3, sage-helper, Chrome MCP, WSL

## Patterns
- **Programming/Math**: algo implementation, number theory, Z3/SAT logic puzzles, game theory
- **Encoding**: esoteric languages (BF, Whitespace, Piet), multi-layer decode, visual codes (QR, Braille, Morse)
- **Interactive/PPC**: netcat parse+compute+send, proof of work, maze BFS/DFS, game solving (minimax, DP)
- **OSINT**: image geolocation, username tracking, metadata GPS, historical data
- **Jail/Sandbox**: Python jail (`__subclasses__()`), bash restricted bypass, calculator injection

## Sub-type Decision Tree
```
file/strings에서 flag 바로 발견?  → 즉시 제출
수학/로직 퍼즐?                   → solver-z3 / sage-helper
multi-layer 인코딩?               → peel loop: detect → decode → repeat
interactive netcat?               → pwntools recv/send + auto-solve
esoteric language?                → WebSearch로 인터프리터 찾기 (구현 금지)
OSINT?                            → 15분 제한. 리드 없으면 중단.
Python jail?                      → __subclasses__() 체인
```

## Pitfalls
- Try the obvious first: strings, file, exiftool
- Interactive: handle I/O carefully, account for latency
- Esoteric: use online interpreters, don't implement
- OSINT: max 15 min without concrete lead
