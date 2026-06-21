#!/usr/bin/env python3
"""
multi_collect.py - Thu thập dữ liệu huấn luyện thủ công
Chạy trên victim host (ví dụ h1) trong Mininet.

Cách dùng:
1. Trong Mininet: h1 python3 multi_collect.py --output train.csv --label 0 --duration 60
2. Trong khi collector chạy, hãy thực hiện tấn công từ attacker (h2, h3,...) với loại tương ứng.
3. Collector sẽ tự động ghi mỗi cửa sổ 3 giây vào file CSV.

Các label:
0 = Normal (không tấn công)
1 = TCP SYN Flood
2 = UDP Flood
3 = ICMP Flood
4 = TCP ACK Flood
"""

import time
import argparse
import csv
import os
import math
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

WINDOW_SEC = 3
FEATURE_NAMES = [
    'pkt_rate', 'byte_rate', 'flow_rate',
    'ent_src', 'ent_dst',
    'syn_ratio', 'ack_ratio', 'udp_ratio', 'icmp_ratio'
]

class TrafficCollector:
    def __init__(self, output_file, duration):
        self.output_file = output_file
        self.duration = duration
        self.stop_flag = False
        self.lock = threading.Lock()
        self.reset_window()

        # Ghi header nếu file mới
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            with open(output_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(FEATURE_NAMES + ['label'])

    def reset_window(self):
        self.pkts = 0
        self.bytes = 0
        self.src_ips = []
        self.dst_ips = []
        self.flows = set()
        self.tcp_total = 0
        self.syn_cnt = 0
        self.ack_cnt = 0
        self.udp_cnt = 0
        self.icmp_cnt = 0
        self.start_time = time.time()

    def packet_handler(self, pkt):
        if self.stop_flag:
            return
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        size = len(pkt)

        with self.lock:
            self.pkts += 1
            self.bytes += size
            self.src_ips.append(src)
            self.dst_ips.append(dst)

            if proto == 6 and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                self.tcp_total += 1
                # SYN flag (bit 1)
                if tcp.flags & 0x02:
                    self.syn_cnt += 1
                # ACK flag (bit 4)
                if tcp.flags & 0x10:
                    self.ack_cnt += 1
                fid = f"{src}-{tcp.sport}-{dst}-{tcp.dport}-6"
                self.flows.add(fid)
            elif proto == 17 and pkt.haslayer(UDP):
                udp = pkt[UDP]
                self.udp_cnt += 1
                fid = f"{src}-{udp.sport}-{dst}-{udp.dport}-17"
                self.flows.add(fid)
            elif proto == 1:
                self.icmp_cnt += 1
                fid = f"{src}-0-{dst}-0-1"
                self.flows.add(fid)
            else:
                fid = f"{src}-0-{dst}-0-{proto}"
                self.flows.add(fid)

    def compute_features(self):
        total_flows = len(self.flows)
        tcp_total = self.tcp_total
        pkt_rate = self.pkts / WINDOW_SEC
        byte_rate = self.bytes / WINDOW_SEC
        flow_rate = total_flows / WINDOW_SEC

        # Entropy src/dst
        src_freq = defaultdict(int)
        for ip in self.src_ips:
            src_freq[ip] += 1
        dst_freq = defaultdict(int)
        for ip in self.dst_ips:
            dst_freq[ip] += 1

        def entropy(freq_dict):
            n = sum(freq_dict.values())
            if n == 0:
                return 0.0
            return -sum((c / n) * math.log2(c / n) for c in freq_dict.values())

        ent_src = entropy(src_freq)
        ent_dst = entropy(dst_freq)

        syn_ratio = self.syn_cnt / max(tcp_total, 1)
        ack_ratio = self.ack_cnt / max(tcp_total, 1)
        udp_ratio = self.udp_cnt / max(total_flows, 1)
        icmp_ratio = self.icmp_cnt / max(self.pkts, 1)

        return [pkt_rate, byte_rate, flow_rate, ent_src, ent_dst,
                syn_ratio, ack_ratio, udp_ratio, icmp_ratio]

    def run(self, label):
        print(f"[+] Starting collector for label {label} (duration {self.duration}s)")
        # Sniff in background thread
        sniff_thread = threading.Thread(target=lambda: sniff(prn=self.packet_handler, store=False, timeout=self.duration))
        sniff_thread.start()

        start = time.time()
        last_window = start
        while time.time() - start < self.duration and not self.stop_flag:
            now = time.time()
            if now - last_window >= WINDOW_SEC:
                with self.lock:
                    features = self.compute_features()
                    self.reset_window()
                # Write to CSV
                with open(self.output_file, 'a') as f:
                    writer = csv.writer(f)
                    writer.writerow(features + [label])
                print(f"[+] Window recorded: label={label}, pkt_rate={features[0]:.2f}, pkts={self.pkts}")
                last_window = now
            time.sleep(0.1)

        sniff_thread.join()
        print(f"[+] Collection finished for label {label}")

def main():
    parser = argparse.ArgumentParser(description='Collect training data from live network traffic')
    parser.add_argument('--output', default='training_data.csv', help='Output CSV file')
    parser.add_argument('--duration', type=int, default=60, help='Duration per label (seconds)')
    parser.add_argument('--label', type=int, required=True, choices=[0,1,2,3,4],
                        help='Label (0=Normal,1=SYN,2=UDP,3=ICMP,4=ACK)')
    args = parser.parse_args()

    collector = TrafficCollector(args.output, args.duration)
    collector.run(args.label)

if __name__ == '__main__':
    main()