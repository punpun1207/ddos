from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from time import sleep, time
import random, itertools, subprocess, signal, atexit

# ------------- Tham số kịch bản ---------------------------------------
NORMAL1 = 60          # giây pha Warm‑up
ATTACK  = 100         # giây pha DDoS
NORMAL2 = 60          # giây pha Cool‑down
VICTIM  = "h8"        # host bị tấn công
BG_PAIRS = 3          # số cặp iperf song song
IPERF_BW = "1M"       # băng thông iperf
BURST_ON  = 0.2       # giây gửi liên tục
BURST_OFF = 0.8       # giây nghỉ (lặp lại)

# ----------------------------------------------------------------------

class MyTopo(Topo):
    """18 host ‑ 6 switch line topology"""

    def build(self):
        switches = [self.addSwitch(f's{i}', cls=OVSKernelSwitch,
                                   protocols='OpenFlow13') for i in range(1,7)]
        hosts = []
        for hi in range(1,19):
            h = self.addHost(f'h{hi}', ip=f'10.0.0.{hi}/24',
                             mac=f"00:00:00:00:00:{hi:02x}")
            hosts.append(h)
        # link 3 host / switch
        for i, h in enumerate(hosts):
            self.addLink(h, switches[i//3])
        # chain switches s1‑s6
        for i in range(5):
            self.addLink(switches[i], switches[i+1])

# ----------------------------------------------------------------------

def iperf_pair(a, b, dur):
    """Start bidirectional iperf3 between host objects a, b for dur seconds."""
    b.cmd('pkill -9 iperf3')
    a.cmd('pkill -9 iperf3')
    b.cmd('iperf3 -s -D')
    a.cmd('iperf3 -s -D')
    a.cmd(f'iperf3 -c {b.IP()} -t {dur} -b {IPERF_BW} &')
    b.cmd(f'iperf3 -c {a.IP()} -t {dur} -b {IPERF_BW} &')


def start_background(net, total_time):
    hosts = [h for h in net.hosts if h.name not in (VICTIM,)]
    pairs = random.sample(list(itertools.permutations(hosts, 2)), BG_PAIRS)
    for a, b in pairs:
        iperf_pair(a, b, total_time)


def start_syn_burst(net):
    vic_ip = net.get(VICTIM).IP()
    attackers = [h for h in net.hosts if h.name != VICTIM]
    procs = []
    for h in attackers:
        # loop‑burst script executed in background shell
        cmd = (
            f"bash -c 'while true; do hping3 -S --rand-source -p 80 --fast {vic_ip} & "
            f"PID=$!; sleep {BURST_ON}; kill -9 $PID; sleep {BURST_OFF}; done'"
        )
        procs.append(h.popen(cmd, shell=True))
    return procs


def stop_procs(procs):
    for p in procs:
        try:
            p.terminate(); p.wait(timeout=0.5)
        except Exception:
            pass

# ----------------------------------------------------------------------

def run():
    topo = MyTopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=c0, link=TCLink)

    info("*** Starting network\n")
    net.start()

    # đảm bảo cleanup khi Ctrl‑C
    def cleanup():
        info('\n*** Stopping network\n')
        net.stop()
    atexit.register(cleanup)

    total_duration = NORMAL1 + ATTACK + NORMAL2 + 30
    start_background(net, total_duration)

    t0 = time()
    info("*** Phase A  – Normal traffic\n")
    sleep(NORMAL1)

    info("*** Phase B  – DDoS burst SYN flood\n")
    syn_procs = start_syn_burst(net)
    sleep(ATTACK)
    stop_procs(syn_procs)

    info("*** Phase C  – Normal traffic\n")
    sleep(NORMAL2)

    info("*** Experiment finished (%.1f s)\n" % (time()-t0))

    cleanup()

# ----------------------------------------------------------------------

if __name__ == '__main__':
    setLogLevel('info')
    run()
