# Web3 Fundamental Techniques

## Reentrancy
- Vulnerability: external call before state update
- Detection: `call.value()` or `.transfer()` before storage write
- Exploit: fallback/receive function re-enters vulnerable function
- Defense: checks-effects-interactions pattern, ReentrancyGuard

## Flash Loan Attacks
- Borrow large amount, manipulate price/state, profit, repay in same tx
- Key: find price oracle dependency (AMM spot price, single-source oracle)
- Tools: Foundry `forge test --fork-url`, Hardhat fork mode

## Integer Overflow/Underflow
- Solidity <0.8: unchecked arithmetic
- Solidity >=0.8: auto-revert, but `unchecked {}` blocks are vulnerable
- Classic: `balances[msg.sender] -= amount` with amount > balance

## Access Control
- Missing `onlyOwner` / `require(msg.sender == owner)`
- Uninitialized proxy: `initialize()` not called or callable by anyone
- Delegatecall to attacker-controlled address

## Storage Collision (Proxy Patterns)
- Proxy storage slot 0 vs implementation storage slot 0
- EIP-1967 standard slots prevent collision
- Check: `cast storage <addr> <slot>` to inspect layout

## Common CTF Patterns
| Pattern | Detection Signal | Exploit |
|---------|-----------------|---------|
| Reentrancy | external call before state update | Reentrant contract |
| Flash loan | price calculated from pool reserves | Manipulate reserves in same tx |
| Selfdestruct | `isSolved()` checks balance == 0 | Force send ETH via selfdestruct |
| tx.origin | `require(tx.origin == owner)` | Phishing contract as intermediary |
| Weak randomness | `block.timestamp` or `blockhash` | Predict or manipulate |

## Tools
- Foundry (forge/cast/anvil): compilation, testing, local fork
- Hardhat: JS-based testing framework
- Slither: static analyzer
- Mythril: symbolic execution
- cast: CLI blockchain interaction
