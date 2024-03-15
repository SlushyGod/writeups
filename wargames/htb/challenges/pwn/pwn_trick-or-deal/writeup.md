Tags
#memory-leak
#ret2win
#use-after-free

Notes:
- find a binary leak
- found a leak just by running the binary and pausing before we read, from here we can print out the current stack and see what pointers we can leak
- We found one for a pointer to a string in data section, which we can use to calculate our offset
- call steal
- call make_offer, make it 0x50
- then set the value 0x48 -> unlock_storage
- set the menu to 1, to print the weapon, however we overwrote it to the unlock_storage

Maybe a link to the challenge, and if there is no link, just a link to the zip file