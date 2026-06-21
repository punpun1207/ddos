#!/usr/bin/env python3
"""
SDN DDoS Detection & Mitigation Controller – ULTIMATE (DICTATOR MODE)
- Chế độ Độc tài: Thuật toán Threshold quyết định chính, DNN làm cố vấn tăng độ tự tin.
- Bảo vệ Nạn nhân (Victim Protection): Cứu sống server, không block nhầm.
- Xóa bỏ Warm-up: Sẵn sàng chiến đấu từ giây số 0 nhờ kịch bản Sniper Ping.
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
BLOCK_DURATION  = 20
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
        self.unique_attackers = set()

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

        # Baseline adaptive (Học ngay từ giây đầu tiên)
        self.baseline_entropy_src = 4.0
        self.baseline_entropy_dst = 4.0
        self.baseline_syn_ratio = 0.1
        self.baseline_ack_ratio = 0.1
        self.baseline_udp_ratio = 0.05
        self.baseline_icmp_ratio = 0.01

        self.blocked_ips = {}
        self.meter_installed = set()
        self.whitelist = set()
        self.mode = "auto"
        self.attacker_rate_limits = {}

        self.alert_id = 0
        self.pending_alerts = []
        self.alert_history = deque(maxlen=ALERT_HISTORY)
        self.timeseries = deque(maxlen=HISTORY_LEN)

        # ---------- DNN ----------
        self.dnn_model = None
        self.scaler = None
        self.use_dnn = False
        try:
            from tensorflow import keras
            if os.path.exists("ddos_dnn.h5") and os.path.exists("scaler_dnn.pkl"):
                self.dnn_model = keras.models.load_model("ddos_dnn.h5", compile=False)
                self.scaler = joblib.load("scaler_dnn.pkl")
                self.use_dnn = True
                self.logger.info("✅ DNN model loaded successfully.")
            else:
                self.logger.warning("DNN files not found. Using Adaptive Thresholds only.")
        except Exception as e:
            self.logger.warning(f"DNN not loaded: {e} – using Thresholds only.")

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

    # -------------------- Ryu Events --------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER and dp and dp.id is not None:
            self.datapaths[dp.id] = dp
            self._install_mirror_flow(dp)
            self.logger.info("Switch %016x connected", dp.id)
        elif ev.state == DEAD_DISPATCHER and dp and dp.id is not None:
            self.datapaths.pop(dp.id, None)
            self.meter_installed.discard(dp.id)
            self.logger.info("Switch %016x disconnected", dp.id)

    def _install_mirror_flow(self, dp):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            super()._packet_in_handler(ev)
        except: 
            pass

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
            proto = ip_pkt.proto
            
            self.window_packets += 1
            self.window_bytes += len(ev.msg.data)
            self.window_src_list.append(src_ip)
            self.window_dst_list.append(dst_ip)
            
            if proto == 6:
                t = pkt.get_protocol(tcp.tcp)
                if t:
                    self.window_tcp_total += 1
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

    # -------------------- Baseline Update --------------------
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
        bytes_cnt = self.window_bytes
        self._reset_window()

        if pkts == 0:
            return

        syn_ratio = syn_cnt / max(tcp_total, 1)
        ack_ratio = ack_cnt / max(tcp_total, 1)
        udp_ratio = udp_cnt / max(total_flows, 1)
        icmp_ratio = icmp_cnt / max(pkts, 1)
        pkt_rate = pkts / WINDOW_SEC
        byte_rate = bytes_cnt / WINDOW_SEC
        ent_src = shannon_entropy(src_list)
        ent_dst = shannon_entropy(dst_list)

        # Adaptive thresholds
        thr_syn_adapt  = min(0.95, self.baseline_syn_ratio * 2.0)
        thr_ack_adapt  = min(0.95, self.baseline_ack_ratio * 2.0)
        thr_udp_adapt  = min(0.95, self.baseline_udp_ratio * 2.5)
        thr_icmp_adapt = min(0.95, self.baseline_icmp_ratio * 3.0)

        # 1. Threshold Detection (Toán học Bản 2)
        thr_attack = 0
        thr_conf = 0.0
        if icmp_ratio > thr_icmp_adapt:
            thr_attack = 3
            thr_conf = calc_confidence(icmp_ratio, thr_icmp_adapt)
        elif udp_ratio > thr_udp_adapt:
            thr_attack = 2
            thr_conf = calc_confidence(udp_ratio, thr_udp_adapt)
        elif syn_ratio > thr_syn_adapt:
            thr_attack = 1
            thr_conf = calc_confidence(syn_ratio, thr_syn_adapt)
        elif ack_ratio > thr_ack_adapt:
            thr_attack = 4
            thr_conf = calc_confidence(ack_ratio, thr_ack_adapt)

        # 2. DNN Detection (Trí tuệ nhân tạo)
        dnn_attack = 0
        dnn_conf = 0.0
        if self.use_dnn and self.dnn_model is not None:
            try:
                features = np.array([[syn_ratio, ack_ratio, udp_ratio, icmp_ratio,
                                       pkt_rate, byte_rate, ent_src, ent_dst]])
                features_scaled = self.scaler.transform(features)
                proba = self.dnn_model.predict(features_scaled, verbose=0)[0]
                dnn_attack = int(np.argmax(proba))
                dnn_conf = float(np.max(proba))
            except Exception as e:
                self.logger.warning(f"DNN predict error: {e}")

        # 3. ENSEMBLE CHẾ ĐỘ ĐỘC TÀI: THRESHOLD LÀM SẾP, DNN LÀM CỐ VẤN
        if thr_attack != 0:
            attack_type = thr_attack
            confidence = thr_conf
            used = "threshold"

            if dnn_attack == thr_attack:
                confidence = min(1.0, thr_conf + 0.15)
                used = "hybrid (thr+dnn)"
        else:
            attack_type = 0
            confidence = 0.0
            used = "none"

        # Update Baseline nếu an toàn
        if attack_type == 0:
            self._update_baseline(ent_src, ent_dst, syn_ratio, ack_ratio, udp_ratio, icmp_ratio)

        # Ghi Log Timeseries
        ts_entry = {
            'ts': round(time.time(),1), 'pkts': pkts, 'flows': total_flows,
            'syn_ratio': round(syn_ratio,3), 'ack_ratio': round(ack_ratio,3),
            'udp_ratio': round(udp_ratio,3), 'icmp_ratio': round(icmp_ratio,3),
            'ent_src': round(ent_src,3), 'ent_dst': round(ent_dst,3),
            'attack': attack_type, 'confidence': round(confidence,3),
            'baseline_syn': round(self.baseline_syn_ratio,3), 'method': used
        }
        with self._lock:
            self.timeseries.append(ts_entry)

        if attack_type == 0:
            return

        # Xác định Victim & Attacker
        dst_freq = defaultdict(int)
        for ip in dst_list:
            dst_freq[ip] += 1
        victim = max(dst_freq, key=dst_freq.get) if dst_freq else "unknown"

        src_freq = defaultdict(int)
        for ip in src_list:
            src_freq[ip] += 1
        attackers = [ip for ip in src_freq.keys() if ip != victim and ip not in self.whitelist]
        if not attackers and src_freq:
            attackers = list(src_freq.keys())[:1]

        with self._lock:
            self.attack_counts[_KEY_MAP[attack_type]] += 1
            self.total_ddos += 1
            for ip in attackers:
                self.unique_attackers.add(ip)

        alert = {
            'id': self.alert_id, 'timestamp': round(time.time(),1),
            'victim': victim, 'attack_type': attack_type,
            'attack_name': ATTACK_NAMES[attack_type],
            'confidence': round(confidence,3), 'attackers': attackers[:20],
            'total_flows': total_flows, 'syn_ratio': round(syn_ratio,3),
            'udp_ratio': round(udp_ratio,3), 'icmp_ratio': round(icmp_ratio,3),
            'ent_src': round(ent_src,3), 'ent_dst': round(ent_dst,3),
            'method': used
        }
        
        with self._lock:
            self.alert_id += 1
            self.alert_history.append(alert)

        self.logger.warning(f"⚠️ {ATTACK_NAMES[attack_type]} | victim={victim} | method={used} | conf={confidence:.2f} | attackers={len(attackers)}")

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

    # -------------------- Mitigation (Victim Protection & Attacker Blocking) --------------------
    def _execute_mitigation(self, alert):
        atype = alert['attack_type']
        victim = alert['victim']
        attackers = alert['attackers']

        # Xử lý Kẻ tấn công
        for ip in attackers:
            self._block_ip(ip)
            if atype in (1,2,4):
                proto = 6 if atype != 2 else 17
                self._rate_limit_attacker(ip, proto_num=proto)

        # Bảo vệ Nạn nhân
        if atype == 1:   # SYN
            self._apply_rate_limit(victim, proto_num=6)
        elif atype == 2: # UDP
            self._apply_rate_limit(victim, proto_num=17)
        elif atype == 3: # ICMP
            self._drop_proto_to(victim, ip_proto=1)
        elif atype == 4: # ACK
            self._apply_rate_limit(victim, proto_num=6)

        self.logger.info(f"Mitigation done | {ATTACK_NAMES[atype]} | victim={victim} | blocked={len(attackers)}")

    def _rate_limit_attacker(self, attacker_ip, proto_num, rate_kbps=RATE_LIMIT_KBPS//2):
        if attacker_ip in self.whitelist: return
        meter_id = abs(hash(attacker_ip)) % 1000 + 1000
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            cmd = ofp.OFPMC_MODIFY if meter_id in self.attacker_rate_limits else ofp.OFPMC_ADD
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=rate_kbps, burst_size=rate_kbps//4)]
            dp.send_msg(par.OFPMeterMod(datapath=dp, command=cmd, flags=ofp.OFPMF_KBPS, meter_id=meter_id, bands=bands))
            match = par.OFPMatch(eth_type=0x0800, ip_proto=proto_num, ipv4_src=attacker_ip)
            inst = [par.OFPInstructionMeter(meter_id), par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [par.OFPActionOutput(ofp.OFPP_NORMAL)])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=180, match=match, instructions=inst, hard_timeout=BLOCK_DURATION, command=ofp.OFPFC_ADD))
            self.attacker_rate_limits[attacker_ip] = meter_id

    def _block_ip(self, ip, duration=BLOCK_DURATION):
        if ip in self.whitelist: return
        self.blocked_ips[ip] = time.time() + duration
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match, instructions=inst, hard_timeout=duration, command=ofp.OFPFC_ADD))

    def _unblock_ip(self, ip):
        self.blocked_ips.pop(ip, None)
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match, command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

    def _drop_proto_to(self, victim, ip_proto):
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ip_proto=ip_proto, ipv4_dst=victim)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match, instructions=inst, hard_timeout=BLOCK_DURATION, command=ofp.OFPFC_ADD))

    def _apply_rate_limit(self, victim, proto_num):
        for dp in list(self.datapaths.values()):
            ofp, par = dp.ofproto, dp.ofproto_parser
            meter_cmd = ofp.OFPMC_MODIFY if dp.id in self.meter_installed else ofp.OFPMC_ADD
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=RATE_LIMIT_KBPS, burst_size=RATE_LIMIT_KBPS//4)]
            dp.send_msg(par.OFPMeterMod(datapath=dp, command=meter_cmd, flags=ofp.OFPMF_KBPS, meter_id=METER_ID, bands=bands))
            self.meter_installed.add(dp.id)
            match = par.OFPMatch(eth_type=0x0800, ip_proto=proto_num, ipv4_dst=victim)
            inst = [par.OFPInstructionMeter(METER_ID), par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [par.OFPActionOutput(ofp.OFPP_NORMAL)])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=150, match=match, instructions=inst, hard_timeout=BLOCK_DURATION, command=ofp.OFPFC_ADD))

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

    # -------------------- REST API --------------------
    def _run_api(self):
        app = Flask(__name__)

        @app.route('/status')
        def status():
            with self._lock:
                return jsonify({
                    'mode': self.mode, 'pending_alerts': len(self.pending_alerts),
                    'active_blocks': len(self.blocked_ips), 'whitelist_count': len(self.whitelist),
                    'attack_counts': dict(self.attack_counts), 'total_ddos': self.total_ddos,
                    'unique_attackers': len(self.unique_attackers), 'dnn_loaded': self.use_dnn,
                })

        @app.route('/attack_stats')
        def attack_stats():
            with self._lock:
                result = dict(self.attack_counts)
                result['total'] = self.total_ddos
                result['unique_attackers'] = len(self.unique_attackers)
                return jsonify(result)

        @app.route('/timeseries')
        def timeseries():
            with self._lock: return jsonify(list(self.timeseries))

        @app.route('/pending_alerts')
        def pending():
            with self._lock: return jsonify(list(self.pending_alerts))

        @app.route('/alerts/history')
        def alert_history():
            with self._lock: return jsonify(list(self.alert_history))

        @app.route('/approve/<int:aid>', methods=['POST'])
        def approve(aid):
            with self._lock:
                alert = next((a for a in self.pending_alerts if a['id'] == aid), None)
                if alert: self.pending_alerts.remove(alert)
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
                if m not in ('auto','manual'): return jsonify({'error':'mode must be auto or manual'}),400
                self.mode = m
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
            if not ip: return jsonify({'error':'missing ip'}),400
            self.whitelist.add(ip)
            self._save_whitelist()
            if ip in self.blocked_ips: self._unblock_ip(ip)
            return jsonify({'status':'added','ip':ip})

        @app.route('/whitelist/remove', methods=['POST'])
        def whitelist_remove():
            ip = (request.json or {}).get('ip')
            if ip not in self.whitelist: return jsonify({'error':'not found'}),404
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
                metrics = f"""# HELP ddos_total_attacks Total DDoS attacks detected
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
# HELP active_blocks Current blocked IPs
active_blocks {len(self.blocked_ips)}
# HELP unique_attackers Unique attacker IPs seen
unique_attackers {len(self.unique_attackers)}
# HELP dnn_loaded DNN model status
dnn_loaded {1 if self.use_dnn else 0}"""
            return metrics, 200, {'Content-Type':'text/plain'}

        from werkzeug.serving import run_simple
        run_simple('0.0.0.0', API_PORT, app, threaded=True, use_reloader=False)

if __name__ != "__main__":
    pass