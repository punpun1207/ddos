#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel
from time import sleep
from random import randrange, choice
from datetime import datetime

# ---------- Topology ----------
class MyTopo(Topo):
    def build(self):
        # 18 host + 6 switch tuyến tính (giữ nguyên như file gốc)
        sw = [self.addSwitch(f's{i}', cls=OVSKernelSwitch, protocols='OpenFlow13') for i in range(1, 7)]
        hosts = []
        for i in range(1, 19):
            h = self.addHost(f'h{i}', cpu=1.0/20, ip=f'10.0.0.{i}/24', mac=f'00:00:00:00:00:{i:02x}')
            hosts.append(h)
            self.addLink(h, sw[(i-1)//3])        # 3 host / switch
        for i in range(5):                        # nối chuỗi switch
            self.addLink(sw[i], sw[i+1])

def ip_random():           # IP 10.0.0.1 – 10.0.0.18
    return f"10.0.0.{randrange(1,19)}"

# ---------- Traffic generator ----------
def startNetwork():
    net = Mininet(topo=MyTopo(), link=TCLink,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653))
    net.start()

    # h1 làm web‑server (giống benign script)
    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/webserver && python -m SimpleHTTPServer 80 &')

    hosts = [net.get(f'h{i}') for i in range(1,19)]

    try:
        for itr in range(100):          # 30 vòng * 4 kiểu ≈ 120 đợt => đủ 20k mẫu
            print(f"================ Iteration {itr+1}/30 ================")

            # 1. ICMP Flood
            src, dst = choice(hosts), ip_random()
            print(f"{src} -> ICMP Flood to {dst}")
            src.cmd(f"timeout 6s hping3 -1 --rand-source --flood {dst} &")
            sleep(2)

            # 2. UDP Flood
            src, dst = choice(hosts), ip_random()
            print(f"{src} -> UDP Flood to {dst}")
            src.cmd(f"timeout 6s hping3 -2 --rand-source --flood {dst} &")
            sleep(2)

            # 3. TCP‑SYN Flood (đích web h1:80)
            src = choice(hosts)
            print(f"{src} -> TCP‑SYN Flood to 10.0.0.1:80")
            src.cmd("timeout 6s hping3 -S -p 80 --rand-source --flood 10.0.0.1 &")
            sleep(2)

            # 4. LAND Attack (spoof src=dst)
            src, dst = choice(hosts), ip_random()
            print(f"{src} -> LAND Attack {dst}")
            src.cmd(f"timeout 6s hping3 -1 --flood -a {dst} {dst} &")
            sleep(4)    # nghỉ thêm 4s để tổng 30s / vòng

    finally:
        net.stop()

# ---------- main ----------
if __name__ == '__main__':
    setLogLevel('info')
    start = datetime.now()
    startNetwork()
    print("Elapsed:", datetime.now() - start)
