# HTB Pwn - Hellhound

#### Tags
[ret2win]
[heap-exploitation]
[house-of-spirit]

Check out the protections
```
RELRO Full RELRO
STACK CANARY Canary found
NX NX enabled
PIE No PIE
RPATH No RPATH
RUNPATH RW-RUNPATH
```

## Initial Observations
- They give us a memory leak on the stack, and since the binary is PIE, we also know the location of where the binary is loaded
- We also discover a function beserker_mode_off, which prints out our flag, so if we gain control over RIP, we can go there and print the flag
- One of the main observations after looking through the code was this line
`local_50 = *(void **)((long)local_50 + 8);`

- Which modifies the pointer that we can write using this code
```
printf("\n[*] Write some code: ");
read(0,local_50,0x20);
```

This allows us to write what where, allowing us to write 8 bytes, then the next 8 bytes being the next address we will write to.
## Free Protection Bypass
After writing out PoC, we then try to free, however we get hit with an error that we can't free, which is a memory protection in free.
## Bugs