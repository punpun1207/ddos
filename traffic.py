#!/usr/bin/env python3
"""
benign_traffic_generator.py
───────────────────────────
* Topology   : 6 switch, 18 host (3 host/switch)
* Controller : Ryu (OpenFlow-13) ở 127.0.0.1:6653
* Lưu lượng  : ping, iperf3 TCP/UDP, tải HTTP
* Chạy ~10 phút (600 vòng mỗi 1 s) ⇒ đủ vài nghìn flow để trích feature
"""

from mininet.topo        import Topo
from mininet.net         import Mininet
from mininet.link        import TCLink
from mininet.node        import OVSKernelSwitch, RemoteController
from mininet.log         import setLogLevel, info
from random              import choice, randrange
from time                import sleep
from datetime            import datetime

# ============ CẤU HÌNH =============
ITERATIONS   = 600          # số vòng lặp
PING_COUNT   = 100          # số ICMP / vòng
IPERF_PORT_T = 5050
IPERF_PORT_U = 5051
HTTP_FILES   = ["index.html", "test.zip"]
# ====================================

class SixSwitchEighteenHost(Topo):
    def build(self):
        # tạo 6 switch
        switches = [self.addSwitch(f's{i+1}', cls=OVSKernelSwitch,
                                   protocols='OpenFlow13')
                    for i in range(6)]

        # thêm 18 host (3 host / switch)
        hosts = []
        mac_i = 1
        for sw in switches:
            for _ in range(3):
                h = self.addHost(f'h{mac_i}',
                                 mac=f"00:00:00:00:00:{mac_i:02x}",
                                 ip=f"10.0.0.{mac_i}/24")
                hosts.append(h)
                self.addLink(h, sw)
                mac_i += 1

        # nối các switch thành đường thẳng
        for i in range(len(switches)-1):
            self.addLink(switches[i], switches[i+1])

def ip_random():
    return f"10.0.0.{randrange(1,19)}"

def main():
    setLogLevel('info')
    topo = SixSwitchEighteenHost()
    net  = Mininet(topo=topo, link=TCLink,
                   controller=lambda name: RemoteController(name,
                                ip='127.0.0.1', port=6653))
    net.start()

    # h1 = web-server & iperf-server
    h1 = net.get('h1')
    h1.cmd('cd /tmp')
    info("*** Khởi động web-server & iperf server trên h1\n")
    h1.cmd('python3 -m http.server 80 &')
    h1.cmd(f'iperf3 -s -p {IPERF_PORT_T} &')
    h1.cmd(f'iperf3 -s -u -p {IPERF_PORT_U} &')

    hosts = [net.get(f'h{i}') for i in range(1,19)]
    info("*** Bắt đầu sinh lưu lượng bình thường\n")
    start_ts = datetime.now()

    for i in range(ITERATIONS):
        info(f"--- Iteration {i+1}/{ITERATIONS}\n")
        src = choice(hosts)
        dst_ip = ip_random()

        # ICMP
        src.cmd(f"ping {dst_ip} -c {PING_COUNT} &")

        # iperf3 TCP & UDP về web server
        src.cmd(f"iperf3 -c 10.0.0.1 -p {IPERF_PORT_T} -t 1 -n 1M")
        src.cmd(f"iperf3 -u -b 5M -c 10.0.0.1 -p {IPERF_PORT_U} -t 1")

        # HTTP GET hai file
        for f in HTTP_FILES:
            src.cmd(f"wget -q -O /dev/null http://10.0.0.1/{f}")

        sleep(1)

    # dọn file tải
    for h in hosts:
        h.cmd("rm -f *.html *.zip")

    elapsed = datetime.now() - start_ts
    info(f"*** Hoàn tất sau {elapsed}\n")
    net.stop()

if __name__ == "__main__":
    main()

