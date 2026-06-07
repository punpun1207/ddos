#!/usr/bin/env python3
# collect_multi.py - Thu thập 12 đặc trưng, label 0..4

import os
import psutil
import numpy as np
from collections import defaultdict
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
import newswitch as switch

WINDOW_SEC = 3
OUTPUT_CSV = "ddos_multi.csv"

FEATURE_COLS = [
    'SSIP','SDFP','SDFB','SFE','NIFE',
    'SYN_ratio','ACK_ratio','UDP_ratio','ICMP_ratio',
    'Pkt_rate','Byte_rate','entropy_src','entropy_dst','label'
]

if not os.path.exists(OUTPUT_CSV):
    with open(OUTPUT_CSV, 'w') as f:
        f.write(','.join(FEATURE_COLS) + '\n')

def shannon_entropy(lst):
    if not lst:
        return 0.0
    _, counts = np.unique(lst, return_counts=True)
    probs = counts / len(lst)
    return -np.sum(probs * np.log2(probs))

def detect_attack_type():
    """Duyệt tiến trình hping3 để xác định loại tấn công"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] and 'hping3' in proc.info['name'].lower():
                cmd = ' '.join(proc.info['cmdline'] or []).lower()
                if ' -s ' in cmd or ' --syn' in cmd:
                    return 1   # SYN flood
                if ' -2 ' in cmd or ' --udp' in cmd:
                    return 2   # UDP flood
                if ' -1 ' in cmd or ' --icmp' in cmd:
                    return 3   # ICMP flood
                if ' -a ' in cmd or ' --ack' in cmd:
                    return 4   # ACK flood
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return 0   # normal

class MultiCollector(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.prev_flows = set()
        self.sample_count = 0
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(WINDOW_SEC)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        src_ips, dst_ips = [], []
        pkt_counts, byte_counts = [], []
        tcp_total = syn_cnt = ack_cnt = 0
        udp_cnt = icmp_cnt = 0
        flows_this = set()
        interactions = set()
        total_pkts = total_bytes = 0

        for st in ev.msg.body:
            if st.priority != 1:
                continue
            m = st.match
            ip_src = m.get('ipv4_src')
            ip_dst = m.get('ipv4_dst')
            proto = m.get('ip_proto')
            if not (ip_src and ip_dst and proto):
                continue
            tp_src = m.get('tcp_src') or m.get('udp_src') or 0
            tp_dst = m.get('tcp_dst') or m.get('udp_dst') or 0
            fid = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{proto}"
            flows_this.add(fid)
            interactions.add((ip_src, tp_src, ip_dst, tp_dst, proto))
            src_ips.append(ip_src)
            dst_ips.append(ip_dst)
            pkt_counts.append(st.packet_count)
            byte_counts.append(st.byte_count)
            total_pkts += st.packet_count
            total_bytes += st.byte_count

            if proto == 6:
                tcp_total += 1
                flags = m.get('tcp_flags', 0)
                if flags & 0x02:
                    syn_cnt += 1
                if flags & 0x10:
                    ack_cnt += 1
            elif proto == 17:
                udp_cnt += 1
            elif proto == 1:
                icmp_cnt += 1

        if not pkt_counts:
            return

        ssip = len(set(src_ips))
        sdfp = np.std(pkt_counts) if len(pkt_counts) > 1 else 0.0
        sdfb = np.std(byte_counts) if len(byte_counts) > 1 else 0.0
        sfe = len(flows_this - self.prev_flows)
        self.prev_flows = flows_this
        pair_cnt = sum(1 for (a1,p1,a2,p2,pr) in interactions if (a2,p2,a1,p1,pr) in interactions)
        nife = pair_cnt / max(sfe, 1)

        total_flows = len(pkt_counts)
        syn_ratio = syn_cnt / max(tcp_total, 1)
        ack_ratio = ack_cnt / max(tcp_total, 1)
        udp_ratio = udp_cnt / max(total_flows, 1)
        icmp_ratio = icmp_cnt / max(total_flows, 1)
        pkt_rate = total_pkts / WINDOW_SEC
        byte_rate = total_bytes / WINDOW_SEC
        ent_src = shannon_entropy(src_ips)
        ent_dst = shannon_entropy(dst_ips)

        label = detect_attack_type()

        with open(OUTPUT_CSV, 'a') as f:
            row = [ssip, sdfp, sdfb, sfe, nife,
                   syn_ratio, ack_ratio, udp_ratio, icmp_ratio,
                   pkt_rate, byte_rate, ent_src, ent_dst, label]
            f.write(','.join(str(x) for x in row) + '\n')
        self.sample_count += 1
        print(f"Collected {self.sample_count}, label={label}")