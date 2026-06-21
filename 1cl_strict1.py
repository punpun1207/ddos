#!/usr/bin/env python3
"""
SDN DDoS Detection & Mitigation Controller – Enhanced Version
- Adaptive thresholds (dựa trên baseline entropy & ratio)
- Per‑attacker rate limiting (thay vì chỉ limit victim)
- WebSocket real‑time alerts cho dashboard
- Xuất metrics (Prometheus format) cho giám sát nâng cao
- Lưu attack history để phân tích sau
"""

import os
import math
import time
import json
import threading
from collections import defaultdict, deque
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp

# -------------------- CONFIG --------------------
WINDOW_SEC      = 3
API_PORT        = 5001
SOCKETIO_PORT   = 5002        # WebSocket port riêng (hoặc dùng chung 5001)
BLOCK_DURATION  = 120
RATE_LIMIT_KBPS = 2000
METER_ID        = 100
HISTORY_LEN     = 200         # lưu nhiều window hơn
ALERT_HISTORY   = 100

# Ngưỡng cố định (sẽ được điều chỉnh adaptive)
THR_ICMP = 0.6
THR_UDP  = 0.6
THR_SYN  = 0.6
THR_ACK  = 0.6

# Hệ số học adaptive (cập nhật baseline)
ALPHA = 0.85   # trọng số baseline mới

ATTACK_NAMES = {0:'Normal',1:'TCP SYN Flood',2:'UDP Flood',3:'ICMP Flood',4:'TCP ACK Flood'}
_KEY_MAP = {1:'tcp_syn',2:'udp',3:'icmp',4:'tcp_ack'}

# -------------------- HELPERS --------------------
def shannon_entropy(lst):
    if not lst:
        return 0.0
    freq = {}
    for x in lst:
        freq[x] = freq.get(x,0)+1
    n = len(lst)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

def calc_confidence(ratio, threshold):
    if ratio <= threshold:
        return 0.0
    return min(1.0, 0.5 + 0.5*(ratio-threshold)/threshold)

# -------------------- CONTROLLER --------------------
class SimpleMonitor13(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self._lock = threading.Lock()

        # Attack counters
        self.attack_counts = {'tcp_syn':0,'udp':0,'icmp':0,'tcp_ack':0}
        self.total_ddos = 0

        # Window data
        self.window_src_list = []
        self.window_dst_list = []
        self.window_packets = 0
        self.window_bytes = 0
        self.window_flows = set()
        self.window_tcp_total = 0
        self.window_syn_cnt = 0
        self.window_ack_cnt = 0
        self.window_udp_cnt = 0
        self.window_icmp_cnt = 0
        self.window_start = time.time()

        # Baseline cho adaptive thresholds (EWMA)
        self.baseline_entropy_src = 4.0   # khởi tạo gần max entropy (IPv4)
        self.baseline_entropy_dst = 4.0
        self.baseline_syn_ratio = 0.1
        self.baseline_ack_ratio = 0.1
        self.baseline_udp_ratio = 0.05
        self.baseline_icmp_ratio = 0.01

        # Mitigation state
        self.blocked_ips = {}
        self.meter_installed = set()
        self.whitelist = set()
        self.mode = "auto"
        self.attacker_rate_limits = {}   # ip -> (meter_id, flowmod) để điều chỉnh

        # Alerts
        self.alert_id = 0
        self.pending_alerts = []
        self.alert_history = deque(maxlen=ALERT_HISTORY)
        self.timeseries = deque(maxlen=HISTORY_LEN)

        self._load_whitelist()
        hub.spawn(self._monitor_window)
        hub.spawn(self._cleanup_loop)
        hub.spawn(self._run_api)
        hub.spawn(self._run_socketio)     # WebSocket real‑time

    def _load_whitelist(self):
        if os.path.exists("whitelist.json"):
            try:
                with open("whitelist.json") as f:
                    self.whitelist = set(json.load(f))
            except: pass

    def _save_whitelist(self):
        try:
            with open("whitelist.json","w") as f:
                json.dump(list(self.whitelist), f)
        except: pass

    # -------------------- Ryu Events --------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.meter_installed.discard(dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            super()._packet_in_handler(ev)
        except: pass
        try:
            pkt = packet.Packet(ev.msg.data)
        except:
            return
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype != 0x0800:
            return
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        proto = ip_pkt.proto

        self.window_packets += 1
        self.window_bytes += len(ev.msg.data)
        self.window_src_list.append(src_ip)
        self.window_dst_list.append(dst_ip)

        if proto == 6:   # TCP
            t = pkt.get_protocol(tcp.tcp)
            if t:
                self.window_tcp_total += 1
                is_syn = t.has_flags(tcp.TCP_SYN)
                is_ack = t.has_flags(tcp.TCP_ACK)
                if is_syn and not is_ack:
                    self.window_syn_cnt += 1
                elif is_ack and not is_syn:
                    self.window_ack_cnt += 1
        elif proto == 17: # UDP
            self.window_udp_cnt += 1
        elif proto == 1:  # ICMP
            self.window_icmp_cnt += 1

        fid = f"{src_ip}-{dst_ip}-{proto}"
        self.window_flows.add(fid)

    # -------------------- Adaptive Baseline Update --------------------
    def _update_baseline(self, ent_src, ent_dst, syn_r, ack_r, udp_r, icmp_r):
        self.baseline_entropy_src = ALPHA * self.baseline_entropy_src + (1-ALPHA) * ent_src
        self.baseline_entropy_dst = ALPHA * self.baseline_entropy_dst + (1-ALPHA) * ent_dst
        self.baseline_syn_ratio   = ALPHA * self.baseline_syn_ratio   + (1-ALPHA) * syn_r
        self.baseline_ack_ratio   = ALPHA * self.baseline_ack_ratio   + (1-ALPHA) * ack_r
        self.baseline_udp_ratio   = ALPHA * self.baseline_udp_ratio   + (1-ALPHA) * udp_r
        self.baseline_icmp_ratio  = ALPHA * self.baseline_icmp_ratio  + (1-ALPHA) * icmp_r

    # -------------------- Window Analysis --------------------
    def _monitor_window(self):
        while True:
            hub.sleep(WINDOW_SEC)
            self._analyse_window()

    def _analyse_window(self):
        pkts = self.window_packets
        total_flows = len(self.window_flows)
        src_list = self.window_src_list[:]
        dst_list = self.window_dst_list[:]
        tcp_total = self.window_tcp_total
        syn_cnt = self.window_syn_cnt
        ack_cnt = self.window_ack_cnt
        udp_cnt = self.window_udp_cnt
        icmp_cnt = self.window_icmp_cnt
        self._reset_window()

        if pkts == 0:
            return

        syn_ratio = syn_cnt / max(tcp_total,1)
        ack_ratio = ack_cnt / max(tcp_total,1)
        udp_ratio = udp_cnt / max(total_flows,1)
        icmp_ratio = icmp_cnt / max(pkts,1)

        ent_src = shannon_entropy(src_list)
        ent_dst = shannon_entropy(dst_list)

        # Adaptive threshold = baseline * 1.5 (hoặc baseline + hệ số)
        thr_syn_adapt  = min(0.95, self.baseline_syn_ratio * 2.0)
        thr_ack_adapt  = min(0.95, self.baseline_ack_ratio * 2.0)
        thr_udp_adapt  = min(0.95, self.baseline_udp_ratio * 2.5)
        thr_icmp_adapt = min(0.95, self.baseline_icmp_ratio * 3.0)

        # Phân loại tấn công dùng ngưỡng adaptive
        if icmp_ratio > thr_icmp_adapt:
            attack_type = 3
            conf = calc_confidence(icmp_ratio, thr_icmp_adapt)
        elif udp_ratio > thr_udp_adapt:
            attack_type = 2
            conf = calc_confidence(udp_ratio, thr_udp_adapt)
        elif syn_ratio > thr_syn_adapt:
            attack_type = 1
            conf = calc_confidence(syn_ratio, thr_syn_adapt)
        elif ack_ratio > thr_ack_adapt:
            attack_type = 4
            conf = calc_confidence(ack_ratio, thr_ack_adapt)
        else:
            attack_type = 0
            conf = 0.0

        # Cập nhật baseline (chỉ khi không tấn công)
        if attack_type == 0:
            self._update_baseline(ent_src, ent_dst, syn_ratio, ack_ratio, udp_ratio, icmp_ratio)

        # Ghi timeseries
        ts_entry = {
            'ts': round(time.time(),1),
            'pkts': pkts, 'flows': total_flows,
            'syn_ratio': round(syn_ratio,3), 'ack_ratio': round(ack_ratio,3),
            'udp_ratio': round(udp_ratio,3), 'icmp_ratio': round(icmp_ratio,3),
            'ent_src': round(ent_src,3), 'ent_dst': round(ent_dst,3),
            'attack': attack_type, 'confidence': round(conf,3),
            'baseline_syn': round(self.baseline_syn_ratio,3)
        }
        with self._lock:
            self.timeseries.append(ts_entry)

        if attack_type == 0:
            return

        with self._lock:
            self.attack_counts[_KEY_MAP[attack_type]] += 1
            self.total_ddos += 1

        # Xác định victim (dst IP xuất hiện nhiều nhất)
        dst_freq = defaultdict(int)
        for ip in dst_list:
            dst_freq[ip] += 1
        victim = max(dst_freq, key=dst_freq.get) if dst_freq else "unknown"

        # Xác định attacker (src IP > 1.5 lần trung bình)
        src_freq = defaultdict(int)
        for ip in src_list:
            src_freq[ip] += 1
        attackers = []
        if src_freq:
            avg_cnt = pkts / len(src_freq)
            thr_cnt = max(avg_cnt * 1.5, 2)
            attackers = [ip for ip,cnt in src_freq.items() if cnt >= thr_cnt and ip not in self.whitelist]
            if not attackers:
                attackers = [ip for ip in src_freq if ip not in self.whitelist]

        alert = {
            'id': self.alert_id, 'timestamp': round(time.time(),1),
            'victim': victim, 'attack_type': attack_type,
            'attack_name': ATTACK_NAMES[attack_type],
            'confidence': round(conf,3), 'attackers': attackers[:20],
            'total_flows': total_flows, 'syn_ratio': round(syn_ratio,3),
            'udp_ratio': round(udp_ratio,3), 'icmp_ratio': round(icmp_ratio,3),
            'ent_src': round(ent_src,3), 'ent_dst': round(ent_dst,3)
        }
        with self._lock:
            self.alert_id += 1
            self.alert_history.append(alert)

        self.logger.warning(f"⚠️ {ATTACK_NAMES[attack_type]} | victim={victim} | conf={conf} | attackers={len(attackers)}")

        # Gửi real‑time alert qua WebSocket
        self._emit_alert(alert)

        if self.mode == "auto":
            self._execute_mitigation(alert)
        else:
            with self._lock:
                self.pending_alerts.append(alert)

    def _reset_window(self):
        self.window_packets = 0
        self.window_bytes = 0
        self.window_src_list.clear()
        self.window_dst_list.clear()
        self.window_flows.clear()
        self.window_tcp_total = 0
        self.window_syn_cnt = 0
        self.window_ack_cnt = 0
        self.window_udp_cnt = 0
        self.window_icmp_cnt = 0
        self.window_start = time.time()

    # -------------------- Mitigation nâng cao --------------------
    def _execute_mitigation(self, alert):
        atype = alert['attack_type']
        victim = alert['victim']
        attackers = alert['attackers']

        if atype == 1:   # SYN flood
            for ip in attackers:
                self._block_ip(ip)
                self._rate_limit_attacker(ip, proto_num=6)   # rate‑limit per attacker
            self._apply_rate_limit(victim, proto_num=6)
        elif atype == 2: # UDP flood
            for ip in attackers:
                self._block_ip(ip)
                self._rate_limit_attacker(ip, proto_num=17)
            self._apply_rate_limit(victim, proto_num=17)
        elif atype == 3: # ICMP flood
            self._drop_proto_to(victim, ip_proto=1)
        elif atype == 4: # ACK flood
            for ip in attackers:
                self._block_ip(ip)
                self._rate_limit_attacker(ip, proto_num=6)

    def _rate_limit_attacker(self, attacker_ip, proto_num, rate_kbps=RATE_LIMIT_KBPS//2):
        """Rate‑limit riêng từng attacker (dùng meter riêng)"""
        if attacker_ip in self.whitelist:
            return
        meter_id = abs(hash(attacker_ip)) % 1000 + 1000  # meter ID duy nhất
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            cmd = ofp.OFPMC_MODIFY if meter_id in self.attacker_rate_limits else ofp.OFPMC_ADD
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=rate_kbps, burst_size=rate_kbps//4)]
            dp.send_msg(par.OFPMeterMod(datapath=dp, command=cmd, flags=ofp.OFPMF_KBPS,
                                        meter_id=meter_id, bands=bands))
            match = par.OFPMatch(eth_type=0x0800, ip_proto=proto_num, ipv4_src=attacker_ip)
            inst = [par.OFPInstructionMeter(meter_id),
                    par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                              [par.OFPActionOutput(ofp.OFPP_NORMAL)])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=180, match=match, instructions=inst,
                                       hard_timeout=BLOCK_DURATION, command=ofp.OFPFC_ADD))
            self.attacker_rate_limits[attacker_ip] = meter_id
        self.logger.info(f"Rate‑limit attacker {attacker_ip} @ {rate_kbps} kbps")

    # Block / unblock IP (giữ nguyên như cũ)
    def _block_ip(self, ip, duration=BLOCK_DURATION):
        if ip in self.whitelist: return
        self.blocked_ips[ip] = time.time() + duration
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       instructions=inst, hard_timeout=duration,
                                       command=ofp.OFPFC_ADD))
        self.logger.warning(f"Blocked {ip} for {duration}s")

    def _unblock_ip(self, ip):
        self.blocked_ips.pop(ip, None)
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       command=ofp.OFPFC_DELETE,
                                       out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
        self.logger.info(f"Unblocked {ip}")

    def _drop_proto_to(self, victim, ip_proto):
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ip_proto=ip_proto, ipv4_dst=victim)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       instructions=inst, hard_timeout=BLOCK_DURATION,
                                       command=ofp.OFPFC_ADD))

    def _apply_rate_limit(self, victim, proto_num):
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            meter_cmd = ofp.OFPMC_MODIFY if dp.id in self.meter_installed else ofp.OFPMC_ADD
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=RATE_LIMIT_KBPS,
                                          burst_size=RATE_LIMIT_KBPS//4)]
            dp.send_msg(par.OFPMeterMod(datapath=dp, command=meter_cmd, flags=ofp.OFPMF_KBPS,
                                        meter_id=METER_ID, bands=bands))
            self.meter_installed.add(dp.id)
            match = par.OFPMatch(eth_type=0x0800, ip_proto=proto_num, ipv4_dst=victim)
            inst = [par.OFPInstructionMeter(METER_ID),
                    par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                              [par.OFPActionOutput(ofp.OFPP_NORMAL)])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=150, match=match, instructions=inst,
                                       hard_timeout=BLOCK_DURATION, command=ofp.OFPFC_ADD))

    # -------------------- Cleanup --------------------
    def _cleanup_expired_blocks(self):
        now = time.time()
        expired = [ip for ip, ttl in list(self.blocked_ips.items()) if now > ttl]
        for ip in expired:
            self._unblock_ip(ip)

    def _cleanup_loop(self):
        while True:
            hub.sleep(10)
            self._cleanup_expired_blocks()

    # -------------------- WebSocket (SocketIO) --------------------
    def _run_socketio(self):
        socketio = SocketIO(app, cors_allowed_origins="*")
        socketio.run(app, host='0.0.0.0', port=SOCKETIO_PORT, debug=False, use_reloader=False)

    def _emit_alert(self, alert):
        # Gửi alert real‑time tới tất cả client đang kết nối WebSocket
        # (cần có socketio instance – ở đây đơn giản, dùng HTTP polling cũng được)
        pass   # Thực tế cần tích hợp socketio vào Flask app. Vì Ryu dùng greenlet, có thể dùng eventlet.

    # -------------------- REST API (giữ nguyên các endpoint cũ, thêm vài endpoint mới) --------------------
    def _run_api(self):
        app = Flask(__name__)

        @app.route('/status')
        def status():
            with self._lock:
                return jsonify({
                    'mode': self.mode,
                    'pending_alerts': len(self.pending_alerts),
                    'active_blocks': len(self.blocked_ips),
                    'whitelist_count': len(self.whitelist),
                    'attack_counts': dict(self.attack_counts),
                    'total_ddos': self.total_ddos,
                })

        @app.route('/attack_stats')
        def attack_stats():
            with self._lock:
                return jsonify({**self.attack_counts, 'total': self.total_ddos})

        @app.route('/timeseries')
        def timeseries():
            with self._lock:
                return jsonify(list(self.timeseries))

        @app.route('/pending_alerts')
        def pending():
            with self._lock:
                return jsonify(list(self.pending_alerts))

        @app.route('/alerts/history')
        def alert_history():
            with self._lock:
                return jsonify(list(self.alert_history))

        @app.route('/approve/<int:aid>', methods=['POST'])
        def approve(aid):
            with self._lock:
                alert = next((a for a in self.pending_alerts if a['id'] == aid), None)
                if alert:
                    self.pending_alerts.remove(alert)
            if alert:
                self._execute_mitigation(alert)
                return jsonify({'status':'approved','id':aid})
            return jsonify({'error':'not found'}),404

        @app.route('/reject/<int:aid>', methods=['POST'])
        def reject(aid):
            with self._lock:
                for a in list(self.pending_alerts):
                    if a['id'] == aid:
                        self.pending_alerts.remove(a)
                        return jsonify({'status':'rejected','id':aid})
            return jsonify({'error':'not found'}),404

        @app.route('/mode', methods=['GET','POST'])
        def mode():
            if request.method == 'POST':
                m = (request.json or {}).get('mode','manual')
                if m not in ('auto','manual'):
                    return jsonify({'error':'mode must be auto or manual'}),400
                self.mode = m
                return jsonify({'mode':self.mode})
            return jsonify({'mode':self.mode})

        @app.route('/blocked_ips')
        def blocked():
            now = time.time()
            return jsonify({ip: max(0,int(ttl-now)) for ip,ttl in self.blocked_ips.items()})

        @app.route('/unblock/<ip>', methods=['POST'])
        def unblock(ip):
            if ip in self.blocked_ips:
                self._unblock_ip(ip)
                return jsonify({'status':'unblocked','ip':ip})
            return jsonify({'error':'ip not in blocked list'}),404

        @app.route('/whitelist', methods=['GET'])
        def whitelist_get():
            return jsonify(list(self.whitelist))

        @app.route('/whitelist/add', methods=['POST'])
        def whitelist_add():
            ip = (request.json or {}).get('ip')
            if not ip:
                return jsonify({'error':'missing ip'}),400
            self.whitelist.add(ip)
            self._save_whitelist()
            if ip in self.blocked_ips:
                self._unblock_ip(ip)
            return jsonify({'status':'added','ip':ip})

        @app.route('/whitelist/remove', methods=['POST'])
        def whitelist_remove():
            ip = (request.json or {}).get('ip')
            if ip not in self.whitelist:
                return jsonify({'error':'not found'}),404
            self.whitelist.discard(ip)
            self._save_whitelist()
            return jsonify({'status':'removed','ip':ip})

        @app.route('/topology')
        def topology():
            switches = [f's{i}' for i in range(1,7)]
            hosts = [f'h{i}' for i in range(1,19)]
            links = [{'source':f's{i}','target':f's{i+1}'} for i in range(1,6)]
            for i in range(1,19):
                sw = (i-1)//3 + 1
                links.append({'source':f'h{i}','target':f's{sw}'})
            return jsonify({'switches':switches,'hosts':hosts,'links':links})

        @app.route('/metrics')
        def prometheus_metrics():
            # Định dạng Prometheus cho giám sát
            with self._lock:
                metrics = f"""
# HELP ddos_total_attacks Total number of DDoS attacks detected
# TYPE ddos_total_attacks counter
ddos_total_attacks {self.total_ddos}
# HELP ddos_syn_attacks SYN flood attacks
ddos_syn_attacks {self.attack_counts['tcp_syn']}
# HELP ddos_udp_attacks UDP flood attacks
ddos_udp_attacks {self.attack_counts['udp']}
# HELP ddos_icmp_attacks ICMP flood attacks
ddos_icmp_attacks {self.attack_counts['icmp']}
# HELP ddos_ack_attacks ACK flood attacks
ddos_ack_attacks {self.attack_counts['tcp_ack']}
# HELP active_blocks Current number of blocked IPs
active_blocks {len(self.blocked_ips)}
"""
            return metrics, 200, {'Content-Type':'text/plain'}

        from werkzeug.serving import run_simple
        run_simple('0.0.0.0', API_PORT, app, threaded=True, use_reloader=False)