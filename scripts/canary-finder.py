from pwn import *


class CanaryFinder():
  def __init__(self, buffer_size):
    self.buffer_size = buffer_size

  def sendlineafter(self, line):
    proc.sendlineafter(line)



