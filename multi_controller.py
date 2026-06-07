#!/usr/bin/env python3
"""
controller_multi.py – Multi-class DDoS Detector for Ryu SDN
- 5+ features, multi-class output (normal, SYN, UDP, ICMP, ACK)
- Pending alerts queue (approve/reject via REST API)
- Baseline learning, adaptive threshold, async prediction
- Mitigation: block attackers, rate-limit, drop ICMP
"""

import os
import sys
import time
import json
import logging
import threading
import sqlite3
from collections import defaultdict
from datetime import datetime

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from keras.models import load_model
import joblib

# Flask
from flask import Flask, jsonify, request
import eventlet
from eventlet import wsgi

# ========== Configuration ==========
WINDOW_SEC = 4
BLOCK_DURATION = 120
RATE_LIMIT_KBPS = 2000
HIGH_CONF = 0.90
METER_ID = 100
DDOS_RATIO = 0.20
LEARN_WINDOW = 32
MAX_FLOWS_SAMPLE = 2000
DB_PATH = "ddos_data.db"
WEBHOOK_URL = ""
API_PORT = 5000

# Response levels
LVL_NORMAL, LVL_WARN, LVL_RATELIMIT, LVL_BLOCK = 0,1,2,3
LEVEL_LABEL = ["Normal","Warn","RateLimit","Block"]

# Feature columns (13 features)
FEATURE_COLS = [
    'SSIP','SDFP','SDFB','SFE','NIFE',
    'SYN_ratio','ACK_ratio','UDP_ratio','ICMP_ratio',
    'Pkt_rate','Byte_rate','entropy_src','entropy_dst'
]

# ========== Database helpers ==========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, victim TEXT, type TEXT,
        confidence REAL, response_level TEXT
    )''')
    conn.commit()
    conn.close()
    logging.getLogger('DDOSDetector').info("SQLite DB ready")

def log_attack(victim, atk_type, confidence, response_level):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO attacks (timestamp, victim, type, confidence, response_level) VALUES (?,?,?,?,?)",
                  (datetime.now().isoformat(), victim, atk_type, confidence, response_level))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.getLogger('DDOSDetector').error("DB insert failed: %s", e)

class SimpleMonitor13(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.prev_flows = set()
        self.scaler = None
        self.flow_model = None
        self.flow_buffer = []
        self.src_dst_map = defaultdict(set)
        self.window_count = 0
        self.baseline_ratios = []
        self.baseline_learned = False
        self.ddos_ratio_threshold = DDOS_RATIO

        self.blocked_ips = {}
        self.response_levels = defaultdict(int)
        self.pending_alerts = []
        self.alert_id = 0
        self.mode = "manual"   # "auto" or "manual"

        self._setup_logging()
        init_db()
        self.flow_training()   # load multi-class model & scaler

        # Queue for async prediction
        import queue
        self.predict_queue = queue.Queue()
        self.predict_thread = threading.Thread(target=self._predict_worker, daemon=True)
        self.predict_thread.start()

        self.monitor_thread = hub.spawn(self._monitor)
        self.baseline_thread = hub.spawn(self._learn_baseline)
        hub.spawn(self._run_api)   # API as greenlet

    def _setup_logging(self):
        from logging.handlers import RotatingFileHandler
        self.logger = logging.getLogger('DDOSDetector')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        try:
            fh = RotatingFileHandler("ddos_detector.log", maxBytes=10*1024*1024, backupCount=5)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
        except: pass

    # -------------------------- Baseline Learning --------------------------
    async def _learn_baseline(self):
        await hub.sleep(LEARN_WINDOW)
        if len(self.baseline_ratios) >= 5:
            mean = np.mean(self.baseline_ratios)
            std = np.std(self.baseline_ratios)
            self.ddos_ratio_threshold = max(0.05, mean + 2*std)
            self.baseline_learned = True
            self.logger.info("Baseline learned: mean=%.3f, std=%.3f → threshold=%.3f",
                             mean, std, self.ddos_ratio_threshold)
        else:
            self.ddos_ratio_threshold = DDOS_RATIO
            self.logger.warning("Not enough baseline data, using default threshold %.2f", DDOS_RATIO)

    # -------------------------- Ryu handlers --------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            super()._packet_in_handler(ev)
        except Exception as exc:
            self.logger.debug("PacketIn parse skipped: %s", exc)

    def _monitor(self):
        while True:
            self._cleanup_expired_blocks()
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(WINDOW_SEC)

    # -------------------------- FlowStats Handler --------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        src_ip_list, dst_ip_list = [], []
        pkt_list, byte_list = [], []
        proto_list, flags_list = [], []
        flows_this_round = set()
        interaction_keys = set()
        dst_flow_count = defaultdict(int)
        self.src_dst_map.clear()

        for st in ev.msg.body:
            if st.priority != 1: continue
            m = st.match
            ip_src = m.get('ipv4_src'); ip_dst = m.get('ipv4_dst'); proto = m.get('ip_proto')
            if not (ip_src and ip_dst and proto): continue
            tp_src = m.get('tcp_src') or m.get('udp_src') or 0
            tp_dst = m.get('tcp_dst') or m.get('udp_dst') or 0
            fid = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{proto}"
            flows_this_round.add(fid)
            interaction_keys.add((ip_src,tp_src,ip_dst,tp_dst,proto))
            src_ip_list.append(ip_src); dst_ip_list.append(ip_dst)
            pkt_list.append(st.packet_count); byte_list.append(st.byte_count)
            proto_list.append(proto)
            flags_list.append(getattr(st, 'tcp_flags', 0))
            dst_flow_count[ip_dst] += 1
            self.src_dst_map[ip_src].add(ip_dst)

        if not pkt_list:
            return

        # Sampling
        if len(src_ip_list) > MAX_FLOWS_SAMPLE:
            idx = np.random.choice(len(src_ip_list), MAX_FLOWS_SAMPLE, replace=False)
            src_ip_list = [src_ip_list[i] for i in idx]
            dst_ip_list = [dst_ip_list[i] for i in idx]
            pkt_list = [pkt_list[i] for i in idx]
            byte_list = [byte_list[i] for i in idx]
            proto_list = [proto_list[i] for i in idx]
            flags_list = [flags_list[i] for i in idx]
            # recompute dst_flow_count
            dst_flow_count = defaultdict(int)
            for d in dst_ip_list:
                dst_flow_count[d] += 1

        # Compute basic 5 features
        ssip = len(set(src_ip_list))
        sdfp = np.std(pkt_list) if len(pkt_list)>1 else 0.0
        sdfb = np.std(byte_list) if len(byte_list)>1 else 0.0
        sfe = len(flows_this_round - self.prev_flows)
        self.prev_flows = flows_this_round
        pair_cnt = sum(1 for (a1,p1,a2,p2,pr) in interaction_keys if (a2,p2,a1,p1,pr) in interaction_keys)
        nife = pair_cnt / max(sfe,1)

        # Additional features
        tcp_total = sum(1 for p in proto_list if p==6)
        syn_cnt = sum(1 for f, p in zip(flags_list, proto_list) if p==6 and (f & 0x02))
        ack_cnt = sum(1 for f, p in zip(flags_list, proto_list) if p==6 and (f & 0x10))
        udp_cnt = sum(1 for p in proto_list if p==17)
        icmp_cnt = sum(1 for p in proto_list if p==1)
        total_flows = len(pkt_list)
        syn_ratio = syn_cnt / max(tcp_total,1)
        ack_ratio = ack_cnt / max(tcp_total,1)
        udp_ratio = udp_cnt / max(total_flows,1)
        icmp_ratio = icmp_cnt / max(total_flows,1)
        pkt_rate = sum(pkt_list) / WINDOW_SEC
        byte_rate = sum(byte_list) / WINDOW_SEC

        # Entropy
        def entropy(lst):
            if not lst: return 0.0
            _, cnt = np.unique(lst, return_counts=True)
            p = cnt / len(lst)
            return -np.sum(p * np.log2(p))
        ent_src = entropy(src_ip_list)
        ent_dst = entropy(dst_ip_list)

        # Build feature vector for this window (one sample for all destinations)
        features = [ssip, sdfp, sdfb, sfe, nife,
                    syn_ratio, ack_ratio, udp_ratio, icmp_ratio,
                    pkt_rate, byte_rate, ent_src, ent_dst]

        # Push to prediction queue (only one prediction per window)
        self.predict_queue.put({
            'features': features,
            'dst_counts': dict(dst_flow_count)
        })

    # -------------------------- Prediction Worker --------------------------
    def _predict_worker(self):
        while True:
            item = self.predict_queue.get()
            if item is None:
                break
            X = np.array(item['features']).reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            probs = self.flow_model.predict(X_scaled, verbose=0)[0]  # shape (5,)
            pred_class = int(np.argmax(probs))
            confidence = float(probs[pred_class])

            # Ratio of attack flows (for baseline)
            ddos_ratio = confidence if pred_class != 0 else 0.0
            if not self.baseline_learned:
                self.baseline_ratios.append(ddos_ratio)
                if len(self.baseline_ratios) > (LEARN_WINDOW // WINDOW_SEC):
                    self.baseline_ratios = self.baseline_ratios[-10:]

            # Decision: if attack (class !=0) and ratio >= threshold
            if pred_class != 0 and ddos_ratio >= self.ddos_ratio_threshold:
                # Identify victim (destination with most flows)
                victim = max(item['dst_counts'], key=item['dst_counts'].get) if item['dst_counts'] else "unknown"
                attackers = [src for src, dsts in self.src_dst_map.items() if victim in dsts]
                alert = {
                    'id': self.alert_id,
                    'timestamp': time.time(),
                    'victim': victim,
                    'attack_type': pred_class,
                    'confidence': confidence,
                    'attackers': attackers[:5],
                    'total_flows': sum(item['dst_counts'].values())
                }
                self.alert_id += 1
                if self.mode == "auto":
                    self._execute_mitigation(alert)
                else:
                    self.pending_alerts.append(alert)
                self.logger.warning(f"Alert: {alert}")
            else:
                # De-escalate response levels for all victims
                for v in list(self.response_levels.keys()):
                    if self.response_levels[v] > LVL_NORMAL:
                        self.response_levels[v] -= 1

    # -------------------------- Mitigation --------------------------
    def _execute_mitigation(self, alert):
        atype = alert['attack_type']
        victim = alert['victim']
        attackers = alert['attackers']
        if atype == 1:  # SYN flood
            for ip in attackers[:3]:
                self._block_ip(ip, duration=BLOCK_DURATION)
            self._apply_rate_limit(victim, rate=RATE_LIMIT_KBPS, proto='tcp')
        elif atype == 2:  # UDP flood
            self._apply_rate_limit(victim, rate=RATE_LIMIT_KBPS, proto='udp')
        elif atype == 3:  # ICMP flood
            self._drop_icmp_to(victim)
        elif atype == 4:  # ACK flood
            for ip in attackers[:3]:
                self._block_ip(ip, duration=BLOCK_DURATION*2)
        self.logger.info(f"Mitigation executed for {victim}, type {atype}")

    def _block_ip(self, ip, duration=None):
        if duration is None:
            duration = BLOCK_DURATION
        self.blocked_ips[ip] = time.time() + duration
        for dp in self.datapaths.values():
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       instructions=inst, hard_timeout=duration,
                                       command=ofp.OFPFC_ADD))
        self.logger.warning(f"Blocked {ip} for {duration}s")

    def _unblock_ip(self, ip):
        for dp in self.datapaths.values():
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       command=ofp.OFPFC_DELETE,
                                       out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
        self.logger.info(f"Unblocked {ip}")

    def _drop_icmp_to(self, victim):
        for dp in self.datapaths.values():
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_dst=victim)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       instructions=inst, hard_timeout=BLOCK_DURATION,
                                       command=ofp.OFPFC_ADD))

    def _apply_rate_limit(self, victim, rate=RATE_LIMIT_KBPS, proto='tcp'):
        proto_num = 6 if proto == 'tcp' else 17 if proto == 'udp' else 0
        for dp in self.datapaths.values():
            ofp, par = dp.ofproto, dp.ofproto_parser
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=rate, burst_size=rate//4)]
            dp.send_msg(par.OFPMeterMod(datapath=dp, command=ofp.OFPMC_ADD, flags=ofp.OFPMF_KBPS,
                                        meter_id=METER_ID, bands=bands))
            match = par.OFPMatch(eth_type=0x0800, ip_proto=proto_num, ipv4_dst=victim)
            inst = [par.OFPInstructionMeter(METER_ID),
                    par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                              [par.OFPActionOutput(ofp.OFPP_NORMAL)])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=150, match=match,
                                       instructions=inst, hard_timeout=BLOCK_DURATION,
                                       command=ofp.OFPFC_ADD))

    def _cleanup_expired_blocks(self):
        now = time.time()
        expired = [ip for ip, ttl in self.blocked_ips.items() if now > ttl]
        for ip in expired:
            del self.blocked_ips[ip]
            self._unblock_ip(ip)

    # -------------------------- Model Loading --------------------------
    def flow_training(self):
        model_path = "ddos_multi_model.h5"
        scaler_path = "scaler_multi.pkl"
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.flow_model = load_model(model_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("Loaded multi-class model and scaler.")
            return
        self.logger.error("Multi-class model not found. Please run train_multi.py first.")
        sys.exit(1)

    # -------------------------- REST API --------------------------
    def _run_api(self):
        app = Flask(__name__)

        @app.route('/status', methods=['GET'])
        def status():
            return jsonify({
                'mode': self.mode,
                'pending_alerts': len(self.pending_alerts),
                'active_blocks': len(self.blocked_ips),
                'baseline_learned': self.baseline_learned,
                'ddos_ratio_threshold': self.ddos_ratio_threshold
            })

        @app.route('/pending_alerts', methods=['GET'])
        def pending():
            return jsonify(self.pending_alerts)

        @app.route('/approve/<int:aid>', methods=['POST'])
        def approve(aid):
            for alert in self.pending_alerts:
                if alert['id'] == aid:
                    self._execute_mitigation(alert)
                    self.pending_alerts.remove(alert)
                    return jsonify({'status': 'approved', 'id': aid})
            return jsonify({'error': 'not found'}), 404

        @app.route('/reject/<int:aid>', methods=['POST'])
        def reject(aid):
            for alert in self.pending_alerts:
                if alert['id'] == aid:
                    self.pending_alerts.remove(alert)
                    return jsonify({'status': 'rejected', 'id': aid})
            return jsonify({'error': 'not found'}), 404

        @app.route('/mode', methods=['GET', 'POST'])
        def mode():
            if request.method == 'POST':
                new_mode = request.json.get('mode')
                if new_mode in ['auto', 'manual']:
                    self.mode = new_mode
                    return jsonify({'mode': self.mode})
                return jsonify({'error': 'invalid mode'}), 400
            return jsonify({'mode': self.mode})

        @app.route('/blocked_ips', methods=['GET'])
        def blocked():
            now = time.time()
            return jsonify({ip: max(0, int(ttl-now)) for ip, ttl in self.blocked_ips.items()})

        @app.route('/topology', methods=['GET'])
        def topology():
            # Return static topology for 18 hosts, 6 switches
            switches = [f's{i}' for i in range(1,7)]
            hosts = [f'h{i}' for i in range(1,19)]
            links = [{'source': f's{i}', 'target': f's{i+1}'} for i in range(1,6)]
            for i in range(1,19):
                sw = (i-1)//3 + 1
                links.append({'source': f'h{i}', 'target': f's{sw}'})
            return jsonify({'switches': switches, 'hosts': hosts, 'links': links})

        @app.route('/timeseries', methods=['GET'])
        def timeseries():
            # Provide dummy timeseries for demo (you can extend)
            return jsonify({'ddos_ratio': [0.1,0.2,0.3,0.4,0.5], 'entropy_dst': [2.5,2.0,1.5,1.0,0.8]})

        wsgi.server(eventlet.listen(('0.0.0.0', API_PORT)), app, log_output=False)

# ========== Run ==========
if __name__ == "__main__":
    from ryu import cfg
    from ryu.base.app_manager import AppManager
    app_mgr = AppManager.get_instance()
    app_mgr.instantiate_apps(SimpleMonitor13)