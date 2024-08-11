#!/usr/bin/python3

"""
The idea here is that you are given a pcap file full of modbus responses

You parse through those modbus responses to see which registers and which unit they were writing to
After discovering the registers and units, you request the data from the holding registers
"""

import socket
from time import sleep
from umodbus import conf
from umodbus.client import tcp

# Adjust modbus configuration
conf.SIGNED_VALUES = True

# Create a socket connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
sock.connect(('94.237.63.201', 47753)) # CHANGE THE IP & PORT to the dockers instance

# Need to specify the unit ID, which you can find in the pcap file right after the length data
def read_register(register_address):
    request = tcp.read_holding_registers(slave_id=52, starting_address=register_address, quantity=1)
    response = tcp.send_message(request, sock)
    sleep(1)
    return response[0]

# write your umodbus command here
# registers that were written to:
registers = [6, 10, 12, 21, 22, 26, 47, 53, 63, 77, 83, 86, 89, 95, 96, 104, 123, 128, 131, 134, 139, 143, 144, 145, 153, 163, 168, 173, 179, 193, 206, 210, 214, 215, 219, 221, 224, 225, 226, 231, 239, 253]
data = []
for register in registers:
    data.append(chr(read_register(register)))

print(''.join(data))

# Send your message to the network

# Use sleep between messages 

# Close the connection
sock.close()
