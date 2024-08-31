So you run it and it asks you for a key.

Opening up the binary we see it asking for the key, then some char assignment (which we can clean up in ghidra, usually an assignment of values like this is a char array)
A tricky thing here is that when you look at this in ghidra since we are using x64 (little endian), it is moving an int value, which will then be swapped cause of little endian.
So the start of the char array is not 0x6f0547480c35643f, but actually the other way around (will get more clearer later)

After that we encounter a for loop for 26 chars (as many as the assignment above)
from there the i % 3, which so we know its got an array s_ = fgets which is our input for the "key", the key should be 3 chars, or at least it will only use 3 chars from it

it then xors that key across the char array.

So from here we know that our typical flags start with HTB, also xor is a transitive property, meaning  plain x key = cipher x plain = key, so if we take the first 3 chars of our cipher text
and xor it with HTB, we get the key w0w, entering that as our key we get our flag!

HTB{x0r_1s_us3d_by_h4x0r!}
