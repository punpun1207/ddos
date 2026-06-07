from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from collections import defaultdict
import time
from flask import Flask, jsonify, request
import eventlet
from eventlet import wsgi

WINDOW_SEC = 3
API_PORT = 5000

class PacketInDetector(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packet_count = 0
        self.src_ips = set()
        self.last_reset = time.time()
        self.pending_alerts = []
        self.alert_id = 0
        self.mode = "manual"
        self.blocked_ips = {}
        hub.spawn(self._monitor_window)
        hub.spawn(self._run_api)

    def _monitor_window(self):
        while True:
            hub.sleep(WINDOW_SEC)
            now = time.time()
            elapsed = now - self.last_reset
            if elapsed < 1:
                continue
            pps = self.packet_count / elapsed
            ssip = len(self.src_ips)
            self.logger.info(f"Window: {self.packet_count} packets, {ssip} src IPs, {pps:.0f} pps")
            if ssip > 20 or pps > 500:
                victim = "unknown"
                alert = {
                    'id': self.alert_id,
                    'timestamp': now,
                    'victim': victim,
                    'attack_type': 1,
                    'confidence': 0.9,
                    'attackers': list(self.src_ips)[:5],
                    'total_flows': self.packet_count
                }
                self.alert_id += 1
                if self.mode == "auto":
                    self._block_attackers(list(self.src_ips)[:3])
                else:
                    self.pending_alerts.append(alert)
                self.logger.warning(f"Alert: {alert}")
            self.packet_count = 0
            self.src_ips.clear()
            self.last_reset = now

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            super()._packet_in_handler(ev)
        except Exception:
            pass
        msg = ev.msg
        try:
            from ryu.lib.packet import packet, ethernet, ipv4
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            if eth.ethertype == 0x0800:
                ip = pkt.get_protocol(ipv4.ipv4)
                if ip:
                    self.src_ips.add(ip.src)
        except:
            pass
        self.packet_count += 1

    def _block_attackers(self, attackers):
        for ip in attackers:
            if ip not in self.blocked_ips:
                self.blocked_ips[ip] = time.time() + 60
                self.logger.info(f"Would block {ip}")

    def _run_api(self):
        app = Flask(__name__)

        @app.route('/pending_alerts')
        def pending():
            return jsonify(self.pending_alerts)

        @app.route('/approve/<int:aid>', methods=['POST'])
        def approve(aid):
            for alert in self.pending_alerts:
                if alert['id'] == aid:
                    self._block_attackers(alert['attackers'][:3])
                    self.pending_alerts.remove(alert)
                    return jsonify({'status': 'approved'})
            return jsonify({'error': 'not found'}), 404

        @app.route('/reject/<int:aid>', methods=['POST'])
        def reject(aid):
            for alert in self.pending_alerts:
                if alert['id'] == aid:
                    self.pending_alerts.remove(alert)
                    return jsonify({'status': 'rejected'})
            return jsonify({'error': 'not found'}), 404

        @app.route('/mode', methods=['GET','POST'])
        def mode():
            if request.method == 'POST':
                self.mode = request.json.get('mode', 'manual')
                return jsonify({'mode': self.mode})
            return jsonify({'mode': self.mode})

        @app.route('/blocked_ips')
        def blocked():
            return jsonify(self.blocked_ips)

        @app.route('/topology')
        def topology():
            switches = [f's{i}' for i in range(1,7)]
            hosts = [f'h{i}' for i in range(1,19)]
            links = [{'source': f's{i}', 'target': f's{i+1}'} for i in range(1,6)]
            for i in range(1,19):
                sw = (i-1)//3 + 1
                links.append({'source': f'h{i}', 'target': f's{sw}'})
            return jsonify({'switches': switches, 'hosts': hosts, 'links': links})

        @app.route('/timeseries')
        def timeseries():
            return jsonify({'ddos_ratio': [0.1,0.2,0.3], 'entropy_dst': [2.5,2.0,1.5]})

        @app.route('/status')
        def status():
            return jsonify({'mode': self.mode, 'pending_alerts': len(self.pending_alerts), 'active_blocks': len(self.blocked_ips)})

        wsgi.server(eventlet.listen(('0.0.0.0', API_PORT)), app, log_output=False)

if __name__ == "__main__":
    from ryu import cfg
    from ryu.base.app_manager import AppManager
    app_mgr = AppManager.get_instance()
    app_mgr.instantiate_apps(PacketInDetector)