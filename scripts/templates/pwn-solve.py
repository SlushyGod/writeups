from pwn import *

context.arch = ''
context.binary = ''
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def get_process():
  proc = process()
  #proc = remote()

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
