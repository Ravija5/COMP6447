# COMP6447

## Templates

Generic:
```python

from pwn import *

PROGNAME = "./<name>"
REMOTEIP = "<ip>"
REMOTEPORT = <port>

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf


p.sendline(payload)
p.interactive()
```

## Pwntools 

Fit example
```python
payload = fit({
    offset : p32(elf.symbols["win"])
})
```
