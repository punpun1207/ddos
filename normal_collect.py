import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from datetime import datetime
from collections import defaultdict
import statistics, os

WINDOW_SEC = 3
TARGET_SAMPLES = 21000

def _init_csv(path: str):
    with open(path, "w") as f:
        f.write("SSIP,SDFP,SDFB,SFE,NIFE,label\n")

def _count_lines(path: str) -> int:
    try:
        with open(path) as f:
            return sum(1 for _ in f) - 1
    except FileNotFoundError:
        return 0

class _BaseCollector(switch.SimpleSwitch13):
    LABEL: int
    CSV_PATH: str

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.last_seen = {}
        _init_csv(self.CSV_PATH)

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
        flow_ids, ip_src_set, pkt_counts, byte_counts = set(), set(), [], []
        interaction_keys = set()

        for st in ev.msg.body:
            if st.priority != 1:
                continue
            m = st.match
            ip_src, ip_dst, proto = m.get('ipv4_src'), m.get('ipv4_dst'), m.get('ip_proto')
            if not (ip_src and ip_dst and proto):
                continue
            tp_src = m.get('tcp_src', m.get('udp_src', 0))
            tp_dst = m.get('tcp_dst', m.get('udp_dst', 0))
            fid = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{proto}"

            flow_ids.add(fid)
            ip_src_set.add(ip_src)
            pkt_counts.append(st.packet_count)
            byte_counts.append(st.byte_count)
            interaction_keys.add((ip_src, tp_src, ip_dst, tp_dst))

        ssip = len(ip_src_set)
        sdfp = statistics.stdev(pkt_counts) if len(pkt_counts) > 1 else 0
        sdfb = statistics.stdev(byte_counts) if len(byte_counts) > 1 else 0
        sfe  = len(flow_ids)

        pair_count = 0
        for (a1, p1, a2, p2) in interaction_keys:
            if (a2, p2, a1, p1) in interaction_keys:
                pair_count += 1
        nife = pair_count / sfe if sfe > 0 else 0

        # bỏ qua dòng toàn 0
        if ssip == 0 and sdfp == 0 and sdfb == 0 and sfe == 0 and nife == 0:
            return

        with open(self.CSV_PATH, "a") as f:
            f.write(f"{ssip},{sdfp},{sdfb},{sfe},{nife},{self.LABEL}\n")

        if _count_lines(self.CSV_PATH) >= TARGET_SAMPLES:
            self.logger.info("Đã thu đủ %d mẫu – dừng lại", TARGET_SAMPLES)
            os._exit(0)

class CollectNormalStatsApp(_BaseCollector):
    LABEL = 0
    CSV_PATH = "ddos_normal.csv"
