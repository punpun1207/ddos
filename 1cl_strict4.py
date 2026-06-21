#!/usr/bin/env python3
"""
SDN DDoS Detection & Mitigation Controller – LAYER 2 MITIGATION
- Chế độ Độc tài: Threshold quyết định, DNN làm cố vấn.
- Nâng cấp: Truy tìm và khóa chặn bằng địa chỉ MAC (Layer 2) để hủy diệt hoàn toàn IP Spoofing.
- FIX: Bỏ qua gói tin từ IP đã block để Attack Stats không tăng.
"""

import os
import math
import time
import json
import threading
import numpy as np
import joblib
from collections import defaultdict, deque
from flask import Flask, jsonify, request
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp

# -------------------- CONFIG --------------------
WINDOW_SEC      = 3
API_PORT        = 5001
BLOCK_DURATION  = 10
RATE_LIMIT_KBPS = 2000
METER_ID        = 100
HISTORY_LEN     = 200
ALERT_HISTORY   = 100

ALPHA = 0.85

ATTACK_NAMES = {0:'Normal',1:'TCP SYN Flood',2:'UDP Flood',3:'ICMP Flood',4:'TCP ACK Flood'}
_KEY_MAP = {1:'tcp_syn',2:'udp',3:'icmp',4:'tcp_ack'}

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

class SimpleMonitor13(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self._lock = threading.Lock()

        self.attack_counts = {'tcp_syn':0,'udp':0,'icmp':0,'tcp_ack':0}
        self.total_ddos = 0

        self.window_src_list = []
        self.window_dst_list = []
        self.window_mac_list = []
        self.ip_to_mac = {}

        self.window_packets = 0
        self.window_bytes = 0
        self.window_flows = set()
        self.window_tcp_total = 0
        self.window_syn_cnt = 0
        self.window_ack_cnt = 0
        self.window_udp_cnt = 0
        self.window_icmp_cnt = 0

        self.baseline_entropy_src = 4.0
        self.baseline_entropy_dst = 4.0
        self.baseline_syn_ratio = 0.1
        self.baseline_ack_ratio = 0.1
        self.baseline_udp_ratio = 0.05
        self.baseline_icmp_ratio = 0.01

        self.blocked_ips = {}
        self.blocked_macs = {}
        self.meter_installed = set()
        self.whitelist = set()
        self.mode = "auto"

        self.alert_id = 0
        self.pending_alerts = []
        self.alert_history = deque(maxlen=ALERT_HISTORY)
        self.timeseries = deque(maxlen=HISTORY_LEN)

        # DNN (optional)
        self.dnn_model = None
        self.scaler = None
        self.use_dnn = False
        try:
            from tensorflow import keras
            if os.path.exists("ddos_dnn.h5") and os.path.exists("scaler_dnn.pkl"):
                self.dnn_model = keras.models.load_model("ddos_dnn.h5", compile=False)
                self.scaler = joblib.load("scaler_dnn.pkl")
                self.use_dnn = True
                self.logger.info("✅ DNN loaded")
        except Exception as e:
            self.logger.warning(f"DNN load failed: {e}")

        self._load_whitelist()
        hub.spawn(self._monitor_window)
        hub.spawn(self._cleanup_loop)
        hub.spawn(self._run_api)

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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER and dp and dp.id is not None:
            self.datapaths[dp.id] = dp
            self.logger.info("Switch %016x connected", dp.id)
        elif ev.state == DEAD_DISPATCHER and dp and dp.id is not None:
            self.datapaths.pop(dp.id, None)
            self.logger.info("Switch %016x disconnected", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            super()._packet_in_handler(ev)
        except: pass

        try:
            pkt = packet.Packet(ev.msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            if not eth or eth.ethertype != 0x0800:
                return
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if not ip_pkt:
                return

            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            mac_src = eth.src
            proto = ip_pkt.proto

            # FIX: Nếu IP đã bị block, bỏ qua (không xử lý)
            if src_ip in self.blocked_ips:
                return

            self.window_packets += 1
            self.window_bytes += len(ev.msg.data)
            self.window_src_list.append(src_ip)
            self.window_dst_list.append(dst_ip)
            self.window_mac_list.append(mac_src)
            self.ip_to_mac[src_ip] = mac_src

            if proto == 6:
                t = pkt.get_protocol(tcp.tcp)
                if t:
                    is_syn = t.has_flags(tcp.TCP_SYN)
                    is_ack = t.has_flags(tcp.TCP_ACK)
                    is_rst = t.has_flags(tcp.TCP_RST)
                    if not is_rst:
                        self.window_tcp_total += 1
                    if is_syn and not is_ack:
                        self.window_syn_cnt += 1
                    elif is_ack and not is_syn and not is_rst:
                        self.window_ack_cnt += 1
            elif proto == 17:
                self.window_udp_cnt += 1
            elif proto == 1:
                self.window_icmp_cnt += 1

            self.window_flows.add(f"{src_ip}-{dst_ip}-{proto}")
        except:
            pass

    def _update_baseline(self, ent_src, ent_dst, syn_r, ack_r, udp_r, icmp_r):
        self.baseline_entropy_src = ALPHA * self.baseline_entropy_src + (1-ALPHA) * ent_src
        self.baseline_entropy_dst = ALPHA * self.baseline_entropy_dst + (1-ALPHA) * ent_dst
        self.baseline_syn_ratio   = ALPHA * self.baseline_syn_ratio   + (1-ALPHA) * syn_r
        self.baseline_ack_ratio   = ALPHA * self.baseline_ack_ratio   + (1-ALPHA) * ack_r
        self.baseline_udp_ratio   = ALPHA * self.baseline_udp_ratio   + (1-ALPHA) * udp_r
        self.baseline_icmp_ratio  = ALPHA * self.baseline_icmp_ratio  + (1-ALPHA) * icmp_r

    def _monitor_window(self):
        while True:
            hub.sleep(WINDOW_SEC)
            self._analyse_window()

    def _analyse_window(self):
        pkts = self.window_packets
        total_flows = len(self.window_flows)
        src_list = self.window_src_list[:]
        dst_list = self.window_dst_list[:]
        mac_list = self.window_mac_list[:]
        tcp_total = self.window_tcp_total
        syn_cnt = self.window_syn_cnt
        ack_cnt = self.window_ack_cnt
        udp_cnt = self.window_udp_cnt
        icmp_cnt = self.window_icmp_cnt
        self._reset_window()

        if pkts == 0:
            return

        syn_ratio = syn_cnt / max(tcp_total, 1)
        ack_ratio = ack_cnt / max(tcp_total, 1)
        udp_ratio = udp_cnt / max(total_flows, 1)
        icmp_ratio = icmp_cnt / max(pkts, 1)
        ent_src = shannon_entropy(src_list)
        ent_dst = shannon_entropy(dst_list)

        thr_syn_adapt  = min(0.95, self.baseline_syn_ratio * 2.0)
        thr_ack_adapt  = min(0.95, self.baseline_ack_ratio * 2.0)
        thr_udp_adapt  = min(0.95, self.baseline_udp_ratio * 2.5)
        thr_icmp_adapt = min(0.95, self.baseline_icmp_ratio * 3.0)

        thr_attack, thr_conf = 0, 0.0
        if icmp_ratio > thr_icmp_adapt:
            thr_attack, thr_conf = 3, calc_confidence(icmp_ratio, thr_icmp_adapt)
        elif udp_ratio > thr_udp_adapt:
            thr_attack, thr_conf = 2, calc_confidence(udp_ratio, thr_udp_adapt)
        elif syn_ratio > thr_syn_adapt:
            thr_attack, thr_conf = 1, calc_confidence(syn_ratio, thr_syn_adapt)
        elif ack_ratio > thr_ack_adapt:
            thr_attack, thr_conf = 4, calc_confidence(ack_ratio, thr_ack_adapt)

        dnn_attack, dnn_conf = 0, 0.0
        if self.use_dnn and self.dnn_model is not None:
            try:
                features = np.array([[syn_ratio, ack_ratio, udp_ratio, icmp_ratio,
                                      pkts/WINDOW_SEC, 0, ent_src, ent_dst]])
                features_scaled = self.scaler.transform(features)
                proba = self.dnn_model.predict(features_scaled, verbose=0)[0]
                dnn_attack, dnn_conf = int(np.argmax(proba)), float(np.max(proba))
            except:
                pass

        if thr_attack != 0:
            attack_type, confidence, used = thr_attack, thr_conf, "threshold"
            if dnn_attack == thr_attack:
                confidence = min(1.0, thr_conf + 0.15)
                used = "hybrid (thr+dnn)"
        else:
            attack_type, confidence, used = 0, 0.0, "none"

        if attack_type == 0:
            self._update_baseline(ent_src, ent_dst, syn_ratio, ack_ratio, udp_ratio, icmp_ratio)
            return

        with self._lock:
            self.attack_counts[_KEY_MAP[attack_type]] += 1
            self.total_ddos += 1

        ts_entry = {'ts': round(time.time(),1), 'attack': attack_type, 'confidence': round(confidence,3)}
        with self._lock:
            self.timeseries.append(ts_entry)

        # Victim
        dst_freq = defaultdict(int)
        for ip in dst_list:
            dst_freq[ip] += 1
        victim = max(dst_freq, key=dst_freq.get) if dst_freq else "unknown"
        victim_mac = self.ip_to_mac.get(victim, "unknown")

        # Attacker MACs
        mac_freq = defaultdict(int)
        for mac in mac_list:
            mac_freq[mac] += 1

        attacker_macs = [mac for mac, count in mac_freq.items() if mac != victim_mac and count > 1]
        if not attacker_macs and mac_freq:
            sorted_macs = sorted(mac_freq.items(), key=lambda x: x[1], reverse=True)
            for mac, count in sorted_macs:
                if mac != victim_mac:
                    attacker_macs = [mac]
                    break

        if not attacker_macs and src_list:
            first_src = src_list[0]
            mac = self.ip_to_mac.get(first_src)
            if mac and mac != victim_mac:
                attacker_macs = [mac]

        alert = {
            'id': self.alert_id, 'timestamp': round(time.time(),1),
            'victim': victim, 'attack_type': attack_type,
            'attack_name': ATTACK_NAMES[attack_type],
            'confidence': round(confidence,3),
            'attacker_macs': attacker_macs,
            'method': used
        }
        with self._lock:
            self.alert_id += 1
            self.alert_history.append(alert)

        self.logger.warning(f"⚠️ {ATTACK_NAMES[attack_type]} | victim={victim} | method={used} | Attacker MACs={attacker_macs}")

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
        self.window_mac_list.clear()
        self.window_flows.clear()
        self.window_tcp_total = 0
        self.window_syn_cnt = 0
        self.window_ack_cnt = 0
        self.window_udp_cnt = 0
        self.window_icmp_cnt = 0

    # -------------------- MITIGATION --------------------
    def _execute_mitigation(self, alert):
        atype = alert['attack_type']
        victim = alert['victim']
        attacker_macs = alert['attacker_macs']

        if not attacker_macs:
            self.logger.warning("No MAC to block, skipping mitigation")
            return

        for mac in attacker_macs:
            self._block_mac(mac)

        if atype in (1, 2, 4):
            self._apply_rate_limit(victim, proto_num=6 if atype != 2 else 17)
        elif atype == 3:
            self._drop_proto_to(victim, ip_proto=1)

        self.logger.info(f"Mitigation | {ATTACK_NAMES[atype]} | Blocked MACs: {attacker_macs}")

    def _block_mac(self, mac, duration=BLOCK_DURATION):
        self.blocked_macs[mac] = time.time() + duration

        # Tìm IP từ MAC
        ip = None
        for src_ip, src_mac in self.ip_to_mac.items():
            if src_mac == mac:
                ip = src_ip
                break

        if ip and ip not in self.whitelist:
            self.blocked_ips[ip] = time.time() + duration
            self.logger.warning(f"✅ Added IP {ip} to blocked_ips")
        else:
            self.logger.warning(f"⚠️ Could not add IP for MAC {mac}")

        # Block MAC
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_src=mac)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(
                datapath=dp, priority=250, match=match,
                instructions=inst, hard_timeout=duration,
                command=ofp.OFPFC_ADD
            ))
        self.logger.warning(f"🔒 Blocked MAC {mac} for {duration}s" + (f" (IP: {ip})" if ip else ""))

    def _unblock_ip(self, ip):
        self.blocked_ips.pop(ip, None)
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            dp.send_msg(par.OFPFlowMod(
                datapath=dp, priority=200, match=match,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY
            ))

    def _unblock_mac(self, mac):
        self.blocked_macs.pop(mac, None)
        for src_ip, src_mac in list(self.ip_to_mac.items()):
            if src_mac == mac:
                self.blocked_ips.pop(src_ip, None)
                break
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_src=mac)
            dp.send_msg(par.OFPFlowMod(
                datapath=dp, priority=250, match=match,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY
            ))

    def _drop_proto_to(self, victim, ip_proto):
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ip_proto=ip_proto, ipv4_dst=victim)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(
                datapath=dp, priority=200, match=match,
                instructions=inst, hard_timeout=BLOCK_DURATION,
                command=ofp.OFPFC_ADD
            ))

    def _apply_rate_limit(self, victim, proto_num):
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            meter_cmd = ofp.OFPMC_MODIFY if dp.id in self.meter_installed else ofp.OFPMC_ADD
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=RATE_LIMIT_KBPS, burst_size=RATE_LIMIT_KBPS//4)]
            dp.send_msg(par.OFPMeterMod(
                datapath=dp, command=meter_cmd, flags=ofp.OFPMF_KBPS,
                meter_id=METER_ID, bands=bands
            ))
            self.meter_installed.add(dp.id)
            match = par.OFPMatch(eth_type=0x0800, ip_proto=proto_num, ipv4_dst=victim)
            inst = [
                par.OFPInstructionMeter(METER_ID),
                par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                          [par.OFPActionOutput(ofp.OFPP_NORMAL)])
            ]
            dp.send_msg(par.OFPFlowMod(
                datapath=dp, priority=150, match=match,
                instructions=inst, hard_timeout=BLOCK_DURATION,
                command=ofp.OFPFC_ADD
            ))

    def _cleanup_expired_blocks(self):
        now = time.time()
        expired_macs = [mac for mac, ttl in list(self.blocked_macs.items()) if now > ttl]
        for mac in expired_macs:
            self._unblock_mac(mac)

    def _cleanup_loop(self):
        while True:
            hub.sleep(5)
            self._cleanup_expired_blocks()

    # -------------------- REST API --------------------
    def _run_api(self):
        app = Flask(__name__)

        @app.route('/status')
        def status():
            with self._lock:
                return jsonify({
                    'mode': self.mode,
                    'pending_alerts': len(self.pending_alerts),
                    'active_blocks': len(self.blocked_ips),
                    'blocked_macs': len(self.blocked_macs),
                    'whitelist_count': len(self.whitelist),
                    'attack_counts': dict(self.attack_counts),
                    'total_ddos': self.total_ddos,
                })

        @app.route('/blocked_macs')
        def blocked_macs():
            now = time.time()
            return jsonify({mac: max(0, int(ttl-now)) for mac, ttl in self.blocked_macs.items()})

        @app.route('/blocked_ips')
        def blocked_ips():
            now = time.time()
            return jsonify({ip: max(0, int(ttl-now)) for ip, ttl in self.blocked_ips.items()})

        @app.route('/attack_stats')
        def attack_stats():
            with self._lock:
                return jsonify({**self.attack_counts, 'total': self.total_ddos})

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
            with self._lock:
                metrics = f"""# HELP ddos_total_attacks Total number of DDoS attacks detected
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
active_blocks {len(self.blocked_ips)}"""
            return metrics, 200, {'Content-Type':'text/plain'}

        from werkzeug.serving import run_simple
        run_simple('0.0.0.0', API_PORT, app, threaded=True, use_reloader=False)

if __name__ == "__main__":
    pass