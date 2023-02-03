""" Solution

    Easy challenge, use the bit stream to get the cartesian cords, scripting made it much faster

    """

""" Post Mortem

    Fairly straight forward challenge, just gotta code faster
    
    """

from pwn import *
import re

HOST = '127.0.0.1'
PORT = 5000

def main():
  proc = remote(HOST, PORT)

  proc.recvuntil(b'Bits to transmit: ')
  transmit_bits = proc.recvline().strip().decode()
  transmit_bits = transmit_bits.replace(' ','')

  samples = []
  for i in range(0, len(transmit_bits), 2):
    bits = transmit_bits[i:i+2]
    sample = None

    if bits == '00':
      sample = '-1.0 -1.0'
    elif bits == '01':
      sample = '-1.0 1.0'
    elif bits == '10':
      sample = '1.0 -1.0'
    else:
      sample = '1.0 1.0'

    samples.append(sample)

  samples = ' '.join(samples)
  proc.sendlineafter(b'Input samples: ', samples.encode())

  while True:
    line = proc.recvline().decode()
    if re.match(r'flag{.*}', line):
      print(line)
      break

if __name__ == '__main__':
  main()
