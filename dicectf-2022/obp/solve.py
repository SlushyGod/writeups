'''
The unbreakable One Byte Pad
'''

# Solution
# Get the ciphertext from output.txt, brute force the xor key, look for the hope{.*} to see if something is caught

import re

def decrypt(key, ciphertext):
  plaintext = ''.join([chr(key ^ int(byte)) for byte in ciphertext])
  return plaintext

def main():
  b_ciphertext = None
  with open('output.txt', 'r') as f:
    ciphertext = f.read().strip()
    b_ciphertext = bytes.fromhex(ciphertext) # Convert to binary, its ascii encoded binary

  flag_regex = r'hope{.*}'
  for key in range(256):
    plaintext = decrypt(key, b_ciphertext)

    flag_match = re.search(flag_regex, plaintext)
    if flag_match:
      print(flag_match[0])


if __name__ == '__main__':
  main()
