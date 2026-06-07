#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()

import requests
from flask import Flask, render_template, jsonify, request
import time

app = Flask(__name__)
CONTROLLER_API = "http://localhost:5001"   # Cổng API của controller

@app.route('/')
def index():
    return render_template('dashboard_final.html')

@app.route('/api/attack_stats')
def api_attack_stats():
    try:
        r = requests.get(f"{CONTROLLER_API}/attack_stats", timeout=2)
        return jsonify(r.json())
    except:
        return jsonify({'tcp_syn': 0, 'udp': 0, 'icmp': 0, 'tcp_ack': 0, 'total': 0})

@app.route('/api/status')
def api_status():
    try:
        r = requests.get(f"{CONTROLLER_API}/status", timeout=2)
        return jsonify(r.json())
    except:
        return jsonify({'mode': 'manual', 'pending_alerts': 0, 'active_blocks': 0})

@app.route('/api/pending')
def api_pending():
    try:
        r = requests.get(f"{CONTROLLER_API}/pending_alerts", timeout=2)
        return jsonify(r.json())
    except:
        return jsonify([])

@app.route('/api/blocked')
def api_blocked():
    try:
        r = requests.get(f"{CONTROLLER_API}/blocked_ips", timeout=2)
        return jsonify(r.json())
    except:
        return jsonify({})

@app.route('/api/topology')
def api_topology():
    try:
        r = requests.get(f"{CONTROLLER_API}/topology", timeout=2)
        return jsonify(r.json())
    except:
        # fallback
        switches = [f's{i}' for i in range(1,7)]
        hosts = [f'h{i}' for i in range(1,19)]
        links = [{'source': f's{i}', 'target': f's{i+1}'} for i in range(1,6)]
        for i in range(1,19):
            sw = (i-1)//3 + 1
            links.append({'source': f'h{i}', 'target': f's{sw}'})
        return jsonify({'switches': switches, 'hosts': hosts, 'links': links})

@app.route('/api/timeseries')
def api_timeseries():
    try:
        r = requests.get(f"{CONTROLLER_API}/timeseries", timeout=2)
        return jsonify(r.json())
    except:
        return jsonify({'ddos_ratio': [0.1,0.2,0.3], 'entropy_dst': [2.5,2.0,1.5]})

@app.route('/approve/<int:aid>', methods=['POST'])
def approve(aid):
    try:
        requests.post(f"{CONTROLLER_API}/approve/{aid}", timeout=2)
        return jsonify({'status': 'ok'})
    except:
        return jsonify({'error': 'failed'}), 500

@app.route('/reject/<int:aid>', methods=['POST'])
def reject(aid):
    try:
        requests.post(f"{CONTROLLER_API}/reject/{aid}", timeout=2)
        return jsonify({'status': 'ok'})
    except:
        return jsonify({'error': 'failed'}), 500

@app.route('/set_mode/<mode>', methods=['POST'])
def set_mode(mode):
    try:
        requests.post(f"{CONTROLLER_API}/mode", json={'mode': mode}, timeout=2)
        return jsonify({'status': 'ok'})
    except:
        return jsonify({'error': 'failed'}), 500

@app.route('/whitelist/add', methods=['POST'])
def add_whitelist():
    ip = request.json.get('ip')
    try:
        requests.post(f"{CONTROLLER_API}/whitelist/add", json={'ip': ip}, timeout=2)
        return jsonify({'status': 'ok'})
    except:
        return jsonify({'error': 'failed'}), 500

@app.route('/whitelist/remove', methods=['POST'])
def remove_whitelist():
    ip = request.json.get('ip')
    try:
        requests.post(f"{CONTROLLER_API}/whitelist/remove", json={'ip': ip}, timeout=2)
        return jsonify({'status': 'ok'})
    except:
        return jsonify({'error': 'failed'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)