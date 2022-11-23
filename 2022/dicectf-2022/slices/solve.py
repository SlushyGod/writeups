'''
Have a slice
'''

# Solution
# Reverse challenge, need to follow how the flag is being checked to get it
#
# if flag[:5] != 'hope{': fail()
# if flag[-1] != '}': fail()
# if flag[5::3] != 'i0_tnl3a0': fail()
# if flag[4::4] != '{0p0lsl': fail()
# if flag[3::5] != 'e0y_3l': fail()
# if flag[6::3] != '_vph_is_t': fail()
# if flag[7::3] != 'ley0sc_l}': fail()

# Very hacky method done for negative indexes, might want to fix later if I got time

import re

def main():
  flag_exploded = [
    {'start': 0, 'step': 1, 'val': 'hope{'},
    {'start': -1, 'step': 0, 'val': '}'},
    {'start': 5, 'step': 3, 'val': 'i0_tnl3a0'},
    {'start': 4, 'step': 4, 'val': '{0p0lsl'},
    {'start': 3, 'step': 5, 'val': 'e0y_3l'},
    {'start': 6, 'step': 3, 'val': '_vph_is_t'},
    {'start': 7, 'step': 3, 'val': 'ley0sc_l}'}
  ]
 
  arr_size = sum(len(flag_part['val']) for flag_part in flag_exploded)
  flag_arr = [''] * arr_size
  neg_arr = [] # Hacky method for negative indexes

  # Loop through the flag parts
  for flag_part in flag_exploded:
    flag_index = flag_part['start']
    flag_count = flag_part['step']

    # Loop through each flag part and add it to the flag array
    for c in flag_part['val']:
      if flag_index < 0:
        neg_arr.insert(0, c)
        continue

      flag_arr[flag_index] = c
      flag_index += flag_count

  flag = ''.join(flag_arr)

  for i in range(-1, -len(neg_arr), -1):
    flag[i] = neg_arr[i]

  print(flag)

if __name__ == '__main__':
  main()
