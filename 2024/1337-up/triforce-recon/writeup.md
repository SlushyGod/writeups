# 1337 Up | TriForce Recon - REV (100)

This challenge was pretty straight forward as it had 3 secrets that were xor encoded with a hardcoded key. Extracting all 3 secrets and their respective keys combined to create the flag.

## Initial Analysis
How to get the building blocks of ideas for exploitation

## Solution
How to exploit after initial analysis

## Solve Script
``` python
import re

htob = lambda hex_d: bytes.fromhex(hex_d)

def xor_decrypt(cipher, key):
    plain = []
    for i, char in enumerate(cipher):
        plain_char = char ^ key[i % len(key)]
        plain.append(chr(plain_char))

    return ''.join(plain)

def main():
    secrets = [{
        'cipher': htob('7e54595f09434b0f4a5d59757b514a5b6d550d0f0c765b7d45'),
        'key': htob('38')
    },
    {
        'cipher': htob('775a5051034d5644706002635f467d0570030558454b'),
        'key' : htob('3136')
    },
    {
        'cipher': htob('755e525500496177065b057c076602025d6152467a0755735046025d5d4f'),
        'key': htob('3332')
    }]

    plaintext = ''
    flag_pattern = r'\{(.*?)\}'
    for secret in secrets:
        flag = xor_decrypt(secret['cipher'], secret['key'])
        plaintext += re.findall(flag_pattern, flag)[0]

    flag = f'INTGRITI{{{plaintext}}}'
    print(f'Flag: {flag}')

if __name__ == '__main__':
    main()
```