# picoCTF Gym
# Reverse Engineering | Transformation
#
# Desc:
# I wonder what this really is... enc ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
#
# Deliverables:
# enc

def main():
  # Given the description, we probably just need to reverse how the flag was encoded
  with open('enc') as f:
    encoded_flag = f.read()

  flag = []
  for c in encoded_flag:
    flag.append(chr(ord(c) >> 8)) # Get the MSB
    flag.append(chr(ord(c) & 0x00FF)) # Get the LSB
  
  print('Flag is {}'.format(''.join(flag)))

if __name__ == '__main__':
  main()
