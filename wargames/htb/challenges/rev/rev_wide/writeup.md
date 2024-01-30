HTB{som3_str1ng5_4r3_w1d3}

Literally run it, you just go through the different dimensions, once you come on 6 you see its encrypted (you also see it from the table). From there it asks you for the key to decrypt.
From there we open it up in ghidra and look for where it is asking for the key to see how its verifying our key. Which we see the password "sup3rs3cr3tw1d3". From there we just run the binary
and see if we get anything

Might want to do a breakdown of the wide string that ghidra just automatically produced for us
