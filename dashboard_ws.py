#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()

import requests
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sdn-ddos-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Địa chỉ controller - sửa lại cho đúng
CONTROLLER_API = "http://localhost:5001"   # <- ĐÃ SỬA

def fetch_controller(endpoint, default=None):
    try:
        r = requests.get(f"{CONTROLLER_API}/{endpoint}", timeout=2)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Error fetching {endpoint}: {e}")
    return default if default is not None else {}

def post_controller(endpoint, json_data=None):
    try:
        if json_data:
            r = requests.post(f"{CONTROLLER_API}/{endpoint}", json=json_data, timeout=2)
        else:
            r = requests.post(f"{CONTROLLER_API}/{endpoint}", timeout=2)
        return r.status_code == 200
    except:
        return False

# Background task
def background_push():
    while True:
        stats = fetch_controller('attack_stats', default={'tcp_syn':0,'udp':0,'icmp':0,'tcp_ack':0,'total':0})
        status = fetch_controller('status', default={'mode':'manual','pending_alerts':0,'active_blocks':0})
        pending = fetch_controller('pending_alerts', default=[])
        blocked = fetch_controller('blocked_ips', default={})
        socketio.emit('stats_update', stats)
        socketio.emit('status_update', status)
        socketio.emit('pending_update', pending)
        socketio.emit('blocked_update', blocked)
        eventlet.sleep(3)

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    stats = fetch_controller('attack_stats', default={'tcp_syn':0,'udp':0,'icmp':0,'tcp_ack':0,'total':0})
    status = fetch_controller('status', default={'mode':'manual','pending_alerts':0,'active_blocks':0})
    pending = fetch_controller('pending_alerts', default=[])
    blocked = fetch_controller('blocked_ips', default={})
    emit('stats_update', stats)
    emit('status_update', status)
    emit('pending_update', pending)
    emit('blocked_update', blocked)

@app.route('/')
def index():
    return render_template('dashboard1.html')

# Các route REST API cho actions
@app.route('/approve/<int:aid>', methods=['POST'])
def approve(aid):
    ok = post_controller(f'approve/{aid}')
    return jsonify({'status':'ok' if ok else 'error'})

@app.route('/reject/<int:aid>', methods=['POST'])
def reject(aid):
    ok = post_controller(f'reject/{aid}')
    return jsonify({'status':'ok' if ok else 'error'})

@app.route('/set_mode/<mode>', methods=['POST'])
def set_mode(mode):
    ok = post_controller('mode', json_data={'mode': mode})
    return jsonify({'status':'ok' if ok else 'error'})

@app.route('/whitelist/add', methods=['POST'])
def add_whitelist():
    ip = request.json.get('ip')
    if ip:
        ok = post_controller('whitelist/add', json_data={'ip': ip})
        return jsonify({'status':'ok' if ok else 'error'})
    return jsonify({'error':'missing ip'}), 400

@app.route('/unblock/<ip>', methods=['POST'])
def unblock(ip):
    ok = post_controller(f'unblock/{ip}')
    return jsonify({'status':'ok' if ok else 'error'})

if __name__ == '__main__':
    socketio.start_background_task(background_push)
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)