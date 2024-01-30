import angr
import claripy

base_addr = 0x100000
proj = angr.Project('./vault', main_opts={'base_addr': base_addr})
state = proj.factory.entry_state()


flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(25)]
flag = claripy.Concat( *flag_chars )

sym_file_name = 'flag.txt'
sym_file = angr.storage.file.SimFile(sym_file_name, content=flag)
state.fs.insert(sym_file_name, sym_file)

simgr = proj.factory.simgr(state)

print("Binary loaded, start exploring...")
simgr.explore(avoid=0x10c3a9)
for state in simgr.avoid:
  solved_sym_file = state.fs.get('flag.txt')
  print(solved_sym_file.concretize())
