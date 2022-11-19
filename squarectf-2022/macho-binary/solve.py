""" Solution
    
    RE the decryption method, which just points to the encryption method, then you see the xor on each byte, so its safe to assume its xor encryption
    With this, use the known first 5 bytes flag{ to get the 5 byte key (using the RE information)
    Use this key to get the rest of the flag

    """

""" Post Mortem

    Maybe get a better way to extract the bytes data into a python variable, everything else was pretty straight forward

    """


encrypted_flag = b'\x0a\x03\x0d\x1f\x1f\x18\x07\x09\x27\x02\x19\x01\x0f\x0c\x0d\x03\x01\x33\x16\x05\x01\x0a\x1f\x27\x05\x1e\x0a\x33\x19\x3b\x0f\x00\x01\x15\x11\x18\x0e\x18\x11\x12\x09\x30\x1c\x0a\x0b\x1c\x0a\x1e\x0c\x1d\x33\x05\x03\x13\x01\x33\x08\x09\x0c\x3b\x05\x1b\x11\x00'

def main():
  plain = 'flag{'
  key = b''
  
  for i, char in enumerate(plain):
    key_int = ord(char) ^ encrypted_flag[i]
    key += key_int.to_bytes(1, 'big')
  
  print('Found key: %s' % key.encode())
  
  flag = b''
  key_index = 0
  for char in encrypted_flag:
    flag_int = key[key_index] ^ char
    flag += flag_int.to_bytes(1, 'big')
    key_index = (key_index + 1) % len(key)
  
  print('Flag: %s' % flag.encode())

if __name__ == '__main__':
  main()
