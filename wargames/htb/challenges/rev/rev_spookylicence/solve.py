'''
Just from opening it looks nasty, good thing there is angr to save the day!
From doing some RE it looks like our key size needs to be 32 chars, so we just make a symbolic byte array of 32 chars
HTB{The_sp0000000key_liC3nC3K3Y}
'''

import angr
import claripy

# Straight forwardish angr challenge, just need to avoid cases that don't give use the flag

FLAG_LEN = 32 
STDIN_FD = 0

base_addr = 0x100000 # To match addresses to Ghidra
binary = "./spookylicence"

proj = angr.Project(binary, main_opts={'base_addr': base_addr})

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat( *flag_chars ) # Add \n for scanf() to accept the input

state = proj.factory.full_init_state(
        args=[binary, flag],
        add_options=angr.options.unicorn,
)

# Add constraints that all characters are printable
for k in flag_chars:
    state.solver.add(k >= ord('!'))
    state.solver.add(k <= ord('~'))

simgr = proj.factory.simulation_manager(state)
find_addr  = [0x101876] # SUCCESS
avoid_addr = [0x101889, 0x1011b1]

simgr.explore(find=find_addr, avoid=avoid_addr) # print if 5 are found as this isn't perfect

if (len(simgr.found) > 0):
    for found in simgr.found:
        solved_flag = simgr.found[0].solver.eval(flag, cast_to=bytes)
        print(solved_flag)
else:
  print('Was not able to find the key...')

