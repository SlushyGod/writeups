# PicoCTF Gym
# Reverse Engineering - keygenme-py
#
# Deliverable
# keygenme-trial.py

# Solution
# Looks like we are supposed to reverse the check_key function that will allow us to call the decrypt function

import hashlib

# Global variables defined in the challenge
bUsername_trial = b"PRITCHARD"
key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial

def check_key(key, username_trial):
    global key_full_template_trial

    if len(key) != len(key_full_template_trial):
        return False
    else:
        # Check static base key part --v
        i = 0
        for c in key_part_static1_trial:
            if key[i] != c:
                return False

            i += 1

        # TODO : test performance on toolbox container
        # Check dynamic part --v
        if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[5]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[3]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[6]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[2]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[7]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[1]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[8]:
            return False

        return True

def main(): 
  digest = hashlib.sha256(bUsername_trial).hexdigest()
  digest_map = [4, 5, 3, 6, 2, 7, 1, 8] # This was gotten based on the check key function, grabbed the index it was checking in the order it searched

  key = []
  for i in digest_map:
    key.append(digest[i])

  flag = key_part_static1_trial + ''.join(key) + "}"
  print('This is the flag: {}'.format(flag))

if __name__ == '__main__':
  main()
