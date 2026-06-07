from scapy.all import *
import random
import time

dst_ip = "10.0.0.5"  # IP đích (host cần gửi tới)
protocols = ['TCP', 'UDP', 'ICMP']
payload_sizes = [20, 100, 300, 600, 1200]  # Độ dài dữ liệu
ports = [21, 53, 80, 123, 443, 8080]  # Các cổng ứng dụng thường gặp

for i in range(30):  # 30 gói lưu lượng đa dạng
    proto = random.choice(protocols)
    sport = random.randint(1024, 65535)
    dport = random.choice(ports)
    payload = Raw(load="X" * random.choice(payload_sizes))

    if proto == 'TCP':
        pkt = IP(dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")/payload
    elif proto == 'UDP':
        pkt = IP(dst=dst_ip)/UDP(sport=sport, dport=dport)/payload
    else:  # ICMP
        pkt = IP(dst=dst_ip)/ICMP(type=8)/payload

    send(pkt, verbose=0)
    time.sleep(random.uniform(0.1, 0.3))  # Giãn cách gửi ngẫu nhiên

