# Return Object Programming

## When & why to use ROP
* If stack is non-executable (NX) i.e. can't return to shellcode placed on stack
* There's a lot of executable code in virtual memory space (code section, library section). You can still return to these instead of shellcode.

### Return2code  
There is a useful `system()` function inside the binary.
If not, try to use gadgets from the binary to form shellcode.

### Return2libc
No useful `system()` function in binary. Leak libc.

**How to:**
1. Leak a libc address (GOT address)
    1.1. Is there a `puts`/`printf`/`putc` in binary?  
        We can use this by calling `puts@plt(puts@got)` to print the address of puts@got on stdin
        Note: this is only possible when PIE is disabled
2. Use this to find the version of libc being used in remote - use Russian website  
3. Then set the base address of current libc to the new libc address.
Note: libc base address always ends in 000 
```
libc.address = puts - libc.symbols["puts"]
```
4. Now, you can use `libc.symbols["system"]` to get system function 

Note: If you can't get `system` use ropper to generate a pure ROPChain using gadgets.

### Pure ROP Chain
Chain gadgets to get arbritrary code excution
```
ropper -f fname --chain execve
```

### Chaining functions
Using `pop pop ret` gadgets --badbytes=000A 



## Automation s
Searching for strings in binary 
```
target = next(elf.search(b"/bin/sh\x00"))
```

Using ropper 
```python
ropper -f fname --search 'pop eax; ret'
ropper -f fname --search 'pop e?x; ret'   #With wildcards

ropper -f fnmae --chain execve #Generating an execve chain

ropper -f fname --badbytes=000A #Removing badchars from search

ropper -f fname --stack-pivot
```

## Some reasons why ROP chains fail
1. Avoid bad bytes  
    * 0x20 - space
    * 0x09 = \t
    * 0x00 = null  
    * 0x0A  
    * 0x0d

## Sys execve call 
```
sys_execve (ebx = 0x0b, ebx = "/bin/sh\x00", ecx = NULL, edx = NULL)
```