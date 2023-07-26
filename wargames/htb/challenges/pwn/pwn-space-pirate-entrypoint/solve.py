from pwn import *

context.binary = ''
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = ''
PORT = 123

def get_process():
  proc = process()
  #proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""

  """)

def main():
  proc = get_process()
  #attach_gdb(proc)

  payload = b''.join([

  ])

  proc.sendlineafter(b'', payload)
  proc.interactive()

if __name__ == '__main__':
  main()
