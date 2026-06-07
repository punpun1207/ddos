# -*- coding: utf-8 -*-
"""
feature_logger.py (simple version)
==================================
* Trích xuất **chính xác 5 đặc trưng**: SSIP, SDFP, SDFB, SFE, NIFE.
* Thêm cột `time` (epoch s) ở đầu, **không ghi nhãn**.
* Ghi liên tục vào `flow_feature_log.csv`.
* Không tích hợp DNN, không cảnh báo DDoS – chỉ ghi số liệu thô.

Chạy:
    ryu-manager feature_logger.py
    # (song song) sudo python3 topology_traffic.py
"""

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from datetime import datetime
import numpy as np
import newswitch as switch  # kế thừa SimpleSwitch13 để tự cài rule priority=1

FEATURE_LOG = "flow_feature_log.csv"
WINDOW_SEC  = 3

class FeatureLogger(switch.SimpleSwitch13):  # kế thừa switch L2 sẵn
    OFP_VERSIONS = [0x04]  # OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths  = {}
        self.prev_flows = set()
        with open(FEATURE_LOG, "w") as f:
            f.write("time,ssip,sdfp,sdfb,sfe,nife\n")
        self.monitor = hub.spawn(self._monitor)

    # -- đăng ký datapath -------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    # -- vòng lặp gửi FlowStatsRequest -----------------------------------
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(WINDOW_SEC)

    # -- xử lý FlowStatsReply & ghi log ----------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_reply(self, ev):
        ts_now = datetime.now().timestamp()
        flows_this, srcs, pkt_list, byte_list = set(), set(), [], []
        pairs = set()

        for st in ev.msg.body:
            if st.priority == 0:  # skip table‑miss / thấp nhất
                continue
            m = st.match
            s_ip = m.get('ipv4_src'); d_ip = m.get('ipv4_dst')
            proto= m.get('ip_proto')
            if not (s_ip and d_ip and proto):
                continue
            s_port = m.get('tcp_src', m.get('udp_src', 0))
            d_port = m.get('tcp_dst', m.get('udp_dst', 0))

            fid = f"{s_ip}-{s_port}-{d_ip}-{d_port}-{proto}"
            flows_this.add(fid); srcs.add(s_ip)
            pkt_list.append(st.packet_count); byte_list.append(st.byte_count)
            pairs.add((s_ip, s_port, d_ip, d_port))

        # ----- tính 5 đặc trưng -----------------------------------------
        ssip = len(srcs)
        sdfp = np.std(pkt_list) if len(pkt_list) > 1 else 0
        sdfb = np.std(byte_list) if len(byte_list) > 1 else 0
        sfe  = len(flows_this - self.prev_flows)
        self.prev_flows = flows_this
        pair_cnt = sum(1 for a,b,c,d in pairs if (c,d,a,b) in pairs)
        nife = pair_cnt / sfe if sfe else 0

        # ----- ghi file --------------------------------------------------
        with open(FEATURE_LOG, "a") as f:
            f.write(f"{ts_now},{ssip},{sdfp},{sdfb},{sfe},{nife}\n")