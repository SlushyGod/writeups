""" Solution

    You are given an encrypted message, that uses a wierd xor encryption scheme
    It maps bytes of the key to locations of the message, then xors the values
    The solution requires you to first find the length of the key, then find where each byte of the key maps to
    Submit the key for the solution

    """

""" Post Mortem

    - Could've been cleaner with scripting, I kept getting confused on variable names and what they accomplished
    - 100000% shouldve worked out the pseudo code and solution on paper first
    - should spend time doing a glance over the code to make sure I know whats happening/should be happening

    """

from pwn import *
import binascii
import re

HOST = '127.0.0.1'
PORT = 5000

def bytes_to_string(msg):
    return binascii.hexlify(msg).decode()

def print_bytes(msg):
    print(bytes_to_string(msg))

class MsgHarness():
  def __init__(self, host, port):
    self.proc = remote(host, port)
    self._startup()

  def _startup(self):
    self.proc.recvuntil(b'Encoded msg is: ')
    msg = self.proc.recvline().strip()
    self.clean_msg = self._process_msg(msg)

  def _process_msg(self, msg):
    try:
      return bytes.fromhex(msg.strip().decode())
    except:
      print(f'Err on msg: {msg}')

  def send_msg(self, msg):
    self.proc.sendlineafter(b'Msg: ', msg.encode())
    return self._process_msg(self.proc.recvline())

  def get_flag(self, msg):
    self.send_msg(msg)
    while True:
      line = self.proc.recvline().decode()
      if re.match(r'flag{.*}', line):
        print(line)

  def get_init_msg(self):
    return self.clean_msg

def xor_msg(new_msg, old_msg):
  msg = bytes()
  for i in range(len(new_msg)):
    msg += (new_msg[i] ^ old_msg[i]).to_bytes(1, 'big')
  
  return msg

def get_key_length(harness):
  init_msg = harness.get_init_msg()
  for i in range(1, 256):
    msg = '01' * i
    new_msg = harness.send_msg(msg)

    mapping = xor_msg(init_msg, new_msg)
    zeros = mapping.count(b'\x00')
    if zeros > 10:
      return i

def main():
  harness = MsgHarness(HOST, PORT)
  key_length = get_key_length(harness)
  cipher_msg = harness.get_init_msg()

  ones_msg = harness.send_msg('01'*key_length)
  one_xor_msg = xor_msg(harness.send_msg('01'*key_length), cipher_msg)
  two_xor_msg = xor_msg(harness.send_msg('02'*key_length), cipher_msg)

  # Get the plaintext message
  real_msg = []
  msg_map = []
  for i in range(len(one_xor_msg)):
    if one_xor_msg[i] == 0 and two_xor_msg[i] == 0:
      real_msg.append(ones_msg[i])
      msg_map.append(0)
    else:
      real_msg.append(ones_msg[i] ^ 1)
      msg_map.append(1)
  
  # Craft incrementing message
  msg = []
  for i in range(1,key_length+1):
    msg.append(f'{i:02x}')
  incr_msg = harness.send_msg(''.join(msg))

  # Create key mapping
  key_mapping = [None]*key_length
  for i in range(len(msg_map)):
    if msg_map[i] == 1:
      key = incr_msg[i] ^ real_msg[i]
      try:
        key_mapping[key-1] = i
      except:
        print(f'Index error: {i}, {key}')

  # Get the key value using the map, plaintext, and ciphertext
  key = []
  for i in key_mapping:
    key_int = real_msg[i] ^ cipher_msg[i]
    key.append(f'{key_int:02x}')

  harness.get_flag(''.join(key))

if __name__ == '__main__':
  main()

