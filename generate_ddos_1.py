
#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel
from time import sleep
from random import randrange, sample
from datetime import datetime

# ---------- Topology ----------
class MyTopo(Topo):
    def build(self):
        sw = [self.addSwitch(f's{i}', cls=OVSKernelSwitch, protocols='OpenFlow13') for i in range(1, 7)]
        for i in range(1, 19):
            h = self.addHost(f'h{i}', cpu=1.0/20, ip=f'10.0.0.{i}/24', mac=f'00:00:00:00:00:{i:02x}')
            self.addLink(h, sw[(i-1)//3])
        for i in range(5):
            self.addLink(sw[i], sw[i+1])

def ip_random():
    return f"10.0.0.{randrange(1,19)}"

# ---------- Traffic generator ----------
def startNetwork():
    net = Mininet(topo=MyTopo(), link=TCLink,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653))
    net.start()

    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/webserver && python -m SimpleHTTPServer 80 &')

    hosts = [net.get(f'h{i}') for i in range(1,19)]

    try:
        for itr in range(10000):
            print(f"========== Iteration {itr+1}/10000 ==========")

            # 1. ICMP Flood từ 3 host
            for src in sample(hosts, 3):
                dst = ip_random()
                print(f"{src} -> ICMP Flood to {dst}")
                src.cmd(f"timeout 5s hping3 -1 --rand-source --flood {dst} &")

            # 2. UDP Flood từ 3 host
            for src in sample(hosts, 3):
                dst = ip_random()
                print(f"{src} -> UDP Flood to {dst}")
                src.cmd(f"timeout 5s hping3 -2 --rand-source --flood {dst} &")

            # 3. TCP‑SYN Flood từ 3 host (web h1:80)
            for src in sample(hosts, 3):
                print(f"{src} -> TCP‑SYN Flood to 10.0.0.1:80")
                src.cmd("timeout 5s hping3 -S -p 80 --rand-source --flood 10.0.0.1 &")

            # 4. LAND Attack từ 3 host
            for src in sample(hosts, 3):
                dst = ip_random()
                print(f"{src} -> LAND Attack {dst}")
                src.cmd(f"timeout 5s hping3 -1 --flood -a {dst} {dst} &")

            sleep(4)  # nghỉ ngắn để chuyển iteration

    finally:
        net.stop()

# ---------- main ----------
if __name__ == '__main__':
    setLogLevel('info')
    start = datetime.now()
    startNetwork()
    print("Elapsed:", datetime.now() - start)
