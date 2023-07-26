import angr
import claripy

# Straight forwardish angr challenge, just need to avoid cases that don't give use the flag

"""
Call Tree:
0x401b92 - main
0x401a70 - check_flag
0x4012f8 - called_by_check_flag
0x4011b6 - check_flag_4 (hardcoded calculation)
0x40140d - RIP gets overriden in check_flag_4 to point here
0x401aed - unsure what happened here
0x4015fd - call_check_flag_3 this gets called from a hardcoded register value
0x4014a0 - call_flag_3
0x4018cb - call_check_flag_2 gets called by 0x401aed
0x40176b - check_flag_2 called by call_check_flag_2
0x401a61 - called from check_flag_2 by manipulating the rip on stack
0x401b7c - same as above
0x401c1d - and back in main
"""

FLAG_LEN = 41
STDIN_FD = 0

base_addr = 0x400000 # To match addresses to Ghidra
binary = "./service"

proj = angr.Project(binary, main_opts={'base_addr': base_addr}) 

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')]) # Add \n for scanf() to accept the input

state = proj.factory.full_init_state(
        args=[binary],
        add_options=angr.options.unicorn,
        stdin=flag,
)

# Add constraints that all characters are printable
for k in flag_chars:
    state.solver.add(k >= ord('!'))
    state.solver.add(k <= ord('~'))

simgr = proj.factory.simulation_manager(state)
find_addr  = [0x00401a61] # SUCCESS

avoid_check_flag_4 = [0x004012ea, 0x004012ef]
avoid_check_flag_3 = [0x004015ef, 0x004015f4]
avoid_check_flag_2 = [0x004018bd, 0x004018c2]
avoid_broken_assembly = [0x00401497] # 0x0040140d
avoid_additional = [0x00401a43,0x0040173c] # these are hidden in the call_check_flag function

avoid_addr = []
avoid_addr += avoid_check_flag_4
avoid_addr += avoid_check_flag_3
avoid_addr += avoid_check_flag_2
avoid_addr += avoid_broken_assembly
avoid_addr += avoid_additional

simgr.explore(find=find_addr, avoid=avoid_addr, num_find=5) # print if 5 are found as this isn't perfect
if (len(simgr.found) > 0):
    for found in simgr.found:
        print(found.posix.dumps(STDIN_FD))
