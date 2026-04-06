# WEB3 — Blockchain / Smart Contracts

## Tools
- **py-repl**: web3.py, eth_abi | **solver-z3**: math-heavy contracts
- WSL: forge, cast, anvil (Foundry suite)

## First Steps
1. Chain params: chainId, RPC, block number
2. Read ALL contract source → map inheritance, modifiers, state
3. Identify access control
4. Map state transitions
5. Deploy test: `anvil --fork-url <rpc>`

## Attack Patterns
- **Access Control**: missing modifier, tx.origin, delegatecall storage collision, unprotected initializer
- **Reentrancy**: classic (external call before state update), cross-function, read-only
- **Math**: overflow/underflow (<0.8.0), precision loss, flash loan, oracle manipulation
- **Storage**: collision (proxy), uninitialized pointer, private != secret (eth_getStorageAt)
- **Misc**: blockhash randomness, selfdestruct force ETH, signature replay, frontrunning

## Pitfalls
- Fork mainnet for testing — don't guess state
- Solidity <0.8.0: no overflow protection
- Storage layout: count slots carefully (dynamic arrays, mappings)
- Gas: `forge test -v` (single v). **`-vvvv` 금지** (5만 토큰 낭비)

## Token-Saving Rules
- **contract source**: solver 프롬프트에 전체 넣지 말 것. 취약 함수만 reversal_map.md에.
- **forge test**: `-v` 최대. `-vvvv` = 20-50k 토큰 낭비 → 금지.
- **cast call**: 결과를 `| jq '.result'`로 필터. raw 금지.
- **ABI**: 필요한 함수 시그니처만. 전체 ABI dump 금지.

## Advanced (L4+ only)
- L2/rollup: challenge period, message replay, sequencer MEV
- Proxy: UUPS upgradeTo, diamond facet routing, EIP-1167 confusion
- DeFi: flash loan + oracle, governance attack, ERC-4626 vault inflation
