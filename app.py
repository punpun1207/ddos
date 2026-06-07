#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import json
import socket

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

def udp_receiver():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('127.0.0.1', 5555))
    while True:
        data, addr = udp_socket.recvfrom(1024)
        try:
            msg = json.loads(data.decode('utf-8'))
            socketio.emit('metrics', msg)
        except Exception as e:
            pass

if __name__ == '__main__':
    t = threading.Thread(target=udp_receiver, daemon=True)
    t.start()
    socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
