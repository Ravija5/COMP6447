# Memory Protections

The following are memoyr protections applied to executables:
* NX  - Stack and heap are not executable i.e. can't drop in shellcode and execute it. 
* ASLR - randomises the base of libraries (libc) so we don't know the address of function in libc. 
* PIE - randomises the base address of the binary which makes it difficult to use gadegts and function addreses in the binary
* Canary - a random value generated at program initialisation adn inserted into the stack at the end of a high risk area (such as an array) where the stack overflows. At the end of the function, it is checked to see if the value has been modified.
 * Full RELRO - prevents you from overwriting GOT. 


## References:
https://ironhackers.es/en/tutoriales/pwn-rop-bypass-nx-aslr-pie-y-canary/