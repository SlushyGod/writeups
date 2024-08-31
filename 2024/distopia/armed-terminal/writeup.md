# HTB Distopia | Armed Terminal - REV (Easy)

This was an interesting binary which was ARM based and used a thumb instructions. It also used a signal and a loop. The main objective was to determine the path of execution that was used to determine whether the password (the flag), was correct.

## Initial Analysis
Looking through the binary, Ghidra is having some issues disassembling the ARM instructions. There are thumb instructions which are not being interpreted properly, however when we look at the instruction set we can determine what they are. The entry point loads a key function that is used to map which function to execute next `FUN_00010240`. From here the analysis of what was happening was a bit dicey, so I decided the best course of action was just to execute it.

``` bash
$ qemu-arm ./armedterminal
hello
Wrong!
$ ello
ello: command not found
```

Running the binary gave me a bit of information:
- It was receiving user input
- It was verifying that user input against some value
- It was reading one byte at a time, this is because it read `h`, and then the rest of the data `ello` was passed to the terminal.

Now let's run the binary in a debugger and see if there is anything we can discover. I just stepped through the entire binary, and focused on the functions that were being called.

Run `armedterminal` using the GDB server baked in QEMU.

``` bash
$ qemu-arm -g 6000 ./armedterminal
```

Run your GDB client and connect to the server.

``` bash
$ gdb-multiarch ./armedterminal
...
pwndbg> target remote 127.0.0.1:6000
Remote debugging using 127.0.0.1:6000
0x00010054 in ?? ()
```

After setting up GDB, start stepping through the function to see the function calls and the control flow of the execution. After stepping through the flow, the flow seems to be focused around jumping through functions listed in the function table `PTR_LAB_00010290`.

## Solution

There is a function table located at `PTR_LAB_00010290` which contains all of the functions required for "verifying" the flag. `LAB_000100a0` is the first function in this table.

```
                        LAB_000100a0                              
000100a0 5f 00 00 eb     bl         FUN_00010224                                   
000100a4 48 00 50 e3     cmp        r0,#0x48
000100a8 3f 00 00 1a     bne        fail_condition
000100ac f6 00 f0 e7     udf        #0x6
```

The above function is checking if `r0 == 0x48` which is `H`. If this check passes it will continue on, with `udf #0x6`. Looking at the table, the function at index `0x6` is `LAB_00010084`.

```
                        LAB_00010084                              
00010084 66 00 00 eb     bl         FUN_00010224                                  
00010088 54 00 50 e3     cmp        r0,#0x54
0001008c 46 00 00 1a     bne        fail_condition
00010090 f7 00 f0 e7     udf        #0x7
```

This function is checking if `r0 == 0x54` which is `T`. This starts to spell out the start of the flag `HT` from the typical `HTB{`. Analyzing the entire binary gets us the flag `HTB{4rmz_4ND_ThUMbZ}`.
