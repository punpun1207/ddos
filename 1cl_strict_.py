#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()

import os
import sys
import time
import json
import numpy as np
from collections import defaultdict
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from flask import Flask, jsonify, request
from eventlet import wsgi

WINDOW_SEC = 3
API_PORT = 5001
BLOCK_DURATION = 120
RATE_LIMIT_KBPS = 2000
METER_ID = 100

class SimpleMonitor13(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}

        # Bộ đếm tấn công
        self.attack_counts = {'tcp_syn':0, 'udp':0, 'icmp':0, 'tcp_ack':0}
        self.total_ddos = 0

        # Cửa sổ
        self.window_packets = 0
        self.window_bytes = 0
        self.window_src_ips = set()
        self.window_dst_ips = set()
        self.window_flows = set()
        self.window_interactions = set()
        self.window_tcp_total = 0
        self.window_syn_cnt = 0
        self.window_ack_cnt = 0
        self.window_udp_cnt = 0
        self.window_icmp_cnt = 0
        self.window_start = time.time()

        self.prev_flows = set()
        self.pending_alerts = []
        self.alert_id = 0
        self.mode = "auto"
        self.blocked_ips = {}
        self.whitelist = set()

        self._load_whitelist()
        hub.spawn(self._monitor_window)
        hub.spawn(self._run_api)
        hub.spawn(self._cleanup_loop)

    def _load_whitelist(self):
        if os.path.exists("whitelist.json"):
            try:
                with open("whitelist.json", 'r') as f:
                    self.whitelist = set(json.load(f))
            except: pass

    def _save_whitelist(self):
        with open("whitelist.json", 'w') as f:
            json.dump(list(self.whitelist), f)

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
        except Exception:
            pass

        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype != 0x0800:
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            return

        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto

        self.window_packets += 1
        self.window_bytes += len(msg.data)
        self.window_src_ips.add(src_ip)
        self.window_dst_ips.add(dst_ip)

        src_port = dst_port = 0
        if proto == 6:
            t = pkt.get_protocol(tcp.tcp)
            if t:
                src_port = t.src_port
                dst_port = t.dst_port
                self.window_tcp_total += 1
                if t.has_flags(tcp.TCP_SYN):
                    self.window_syn_cnt += 1
                if t.has_flags(tcp.TCP_ACK):
                    self.window_ack_cnt += 1
        elif proto == 17:
            u = pkt.get_protocol(udp.udp)
            if u:
                src_port = u.src_port
                dst_port = u.dst_port
                self.window_udp_cnt += 1
        elif proto == 1:
            self.window_icmp_cnt += 1

        fid = f"{src_ip}-{src_port}-{dst_ip}-{dst_port}-{proto}"
        self.window_flows.add(fid)
        self.window_interactions.add((src_ip, src_port, dst_ip, dst_port, proto))

    def _monitor_window(self):
        while True:
            hub.sleep(WINDOW_SEC)
            if self.window_packets == 0:
                self._reset_window()
                continue

            total_flows = len(self.window_flows)
            syn_ratio = self.window_syn_cnt / max(self.window_tcp_total, 1)
            ack_ratio = self.window_ack_cnt / max(self.window_tcp_total, 1)
            udp_ratio = self.window_udp_cnt / max(total_flows, 1)
            icmp_ratio = self.window_icmp_cnt / max(total_flows, 1)

            # Phân loại dựa trên tỷ lệ
            if icmp_ratio > 0.6:
                attack_type = 3  # ICMP
            elif udp_ratio > 0.6:
                attack_type = 2  # UDP
            elif syn_ratio > 0.6:
                attack_type = 1  # SYN
            elif ack_ratio > 0.6:
                attack_type = 4  # ACK
            else:
                attack_type = 0  # Normal

            self.logger.info(f"Window: packets={self.window_packets}, "
                             f"syn={syn_ratio:.2f}, ack={ack_ratio:.2f}, udp={udp_ratio:.2f}, icmp={icmp_ratio:.2f}, "
                             f"attack_type={attack_type}")

            if attack_type != 0:
                # Cập nhật bộ đếm
                if attack_type == 1:
                    self.attack_counts['tcp_syn'] += 1
                elif attack_type == 2:
                    self.attack_counts['udp'] += 1
                elif attack_type == 3:
                    self.attack_counts['icmp'] += 1
                elif attack_type == 4:
                    self.attack_counts['tcp_ack'] += 1
                self.total_ddos += 1

                # Xác định victim
                dst_counts = defaultdict(int)
                for dst in self.window_dst_ips:
                    dst_counts[dst] += 1
                victim = max(dst_counts, key=dst_counts.get) if dst_counts else "unknown"
                attackers = list(self.window_src_ips)

                alert = {
                    'id': self.alert_id,
                    'timestamp': time.time(),
                    'victim': victim,
                    'attack_type': attack_type,
                    'confidence': 1.0,
                    'attackers': attackers,
                    'total_flows': total_flows
                }
                self.alert_id += 1
                if self.mode == "auto":
                    self._execute_mitigation(alert)
                else:
                    self.pending_alerts.append(alert)
                self.logger.warning(f"Alert: {alert}")
                self.logger.warning(f"📊 Attack counters - TCP_SYN: {self.attack_counts['tcp_syn']} | "
                                    f"UDP: {self.attack_counts['udp']} | ICMP: {self.attack_counts['icmp']} | "
                                    f"TCP_ACK: {self.attack_counts['tcp_ack']} | Total: {self.total_ddos}")
            else:
                # Không có tấn công
                pass

            self._reset_window()

    def _reset_window(self):
        self.window_packets = 0
        self.window_bytes = 0
        self.window_src_ips.clear()
        self.window_dst_ips.clear()
        self.window_flows.clear()
        self.window_interactions.clear()
        self.window_tcp_total = 0
        self.window_syn_cnt = 0
        self.window_ack_cnt = 0
        self.window_udp_cnt = 0
        self.window_icmp_cnt = 0
        self.window_start = time.time()

    # ------------------- Mitigation -------------------
    def _execute_mitigation(self, alert):
        atype = alert['attack_type']
        victim = alert['victim']
        attackers = alert['attackers']
        if atype == 1:   # SYN
            for ip in attackers:
                self._block_ip(ip)
            self._apply_rate_limit(victim, proto='tcp')
        elif atype == 2: # UDP
            self._apply_rate_limit(victim, proto='udp')
        elif atype == 3: # ICMP
            self._drop_icmp_to(victim)
        elif atype == 4: # ACK
            for ip in attackers:
                self._block_ip(ip)
        self.logger.info(f"Mitigation executed for {victim}")

    def _block_ip(self, ip, duration=BLOCK_DURATION):
        if ip in self.whitelist:
            return
        self.blocked_ips[ip] = time.time() + duration
        for dp in self.datapaths.values():
            ofp, par = dp.ofproto, dp.ofproto_parser
            match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(par.OFPFlowMod(datapath=dp, priority=200, match=match,
                                       instructions=inst, hard_timeout=duration,
                                       command=ofp.OFPFC_ADD))
        self.logger.info(f"Blocked {ip} for {duration}s")

    def _unblock_ip(self, ip):
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
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

    def _apply_rate_limit(self, victim, proto='tcp'):
        proto_num = 6 if proto == 'tcp' else 17 if proto == 'udp' else 0
        for dp in self.datapaths.values():
            ofp, par = dp.ofproto, dp.ofproto_parser
            bands = [par.OFPMeterBandDrop(type_=ofp.OFPMBT_DROP, rate=RATE_LIMIT_KBPS, burst_size=RATE_LIMIT_KBPS//4)]
            dp.send_msg(par.OFPMeterMod(datapath=dp, command=ofp.OFPMC_ADD,
                                        flags=ofp.OFPMF_KBPS, meter_id=METER_ID, bands=bands))
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
            self._unblock_ip(ip)

    def _cleanup_loop(self):
        while True:
            hub.sleep(10)
            self._cleanup_expired_blocks()

    # ------------------- REST API -------------------
    def _run_api(self):
        app = Flask(__name__)

        @app.route('/pending_alerts')
        def pending():
            return jsonify(self.pending_alerts)

        @app.route('/approve/<int:aid>', methods=['POST'])
        def approve(aid):
            for alert in self.pending_alerts:
                if alert['id'] == aid:
                    self._execute_mitigation(alert)
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

        @app.route('/whitelist', methods=['GET'])
        def whitelist():
            return jsonify(list(self.whitelist))

        @app.route('/whitelist/add', methods=['POST'])
        def add_whitelist():
            ip = request.json.get('ip')
            if ip:
                self.whitelist.add(ip)
                self._save_whitelist()
                if ip in self.blocked_ips:
                    self._unblock_ip(ip)
                return jsonify({'status': 'added'})
            return jsonify({'error': 'missing ip'}), 400

        @app.route('/whitelist/remove', methods=['POST'])
        def remove_whitelist():
            ip = request.json.get('ip')
            if ip in self.whitelist:
                self.whitelist.remove(ip)
                self._save_whitelist()
                return jsonify({'status': 'removed'})
            return jsonify({'error': 'not found'}), 404

        @app.route('/blocked_ips')
        def blocked():
            now = time.time()
            return jsonify({ip: max(0, int(ttl-now)) for ip, ttl in self.blocked_ips.items()})

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
            return jsonify({
                'mode': self.mode,
                'pending_alerts': len(self.pending_alerts),
                'active_blocks': len(self.blocked_ips),
                'whitelist': list(self.whitelist)
            })

        @app.route('/attack_stats')
        def attack_stats():
            return jsonify({
                'tcp_syn': self.attack_counts['tcp_syn'],
                'udp': self.attack_counts['udp'],
                'icmp': self.attack_counts['icmp'],
                'tcp_ack': self.attack_counts['tcp_ack'],
                'total': self.total_ddos
            })

        wsgi.server(eventlet.listen(('0.0.0.0', API_PORT)), app, log_output=False)

if __name__ == "__main__":
    from ryu.base.app_manager import AppManager
    app_mgr = AppManager.get_instance()
    app_mgr.instantiate_apps(SimpleMonitor13)