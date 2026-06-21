#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.lib.packet import packet, ethernet, ipv4
from collections import defaultdict
import time

class SimpleBlocker(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.blocked_ips = {}
        self.packet_count = defaultdict(int)
        hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype != 0x0800:
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            return
        src = ip.src
        dst = ip.dst

        # Nếu IP nguồn đã bị block, drop luôn
        if src in self.blocked_ips:
            if time.time() < self.blocked_ips[src]:
                return  # không xử lý, coi như drop
            else:
                del self.blocked_ips[src]

        self.packet_count[src] += 1
        self.logger.info(f"Packet from {src} to {dst}, count={self.packet_count[src]}")

        # Chuyển tiếp bình thường (học switch)
        super()._packet_in_handler(ev)

    def _monitor(self):
        while True:
            hub.sleep(5)
            now = time.time()
            for src, cnt in list(self.packet_count.items()):
                if cnt > 20:  # ngưỡng 20 gói trong 5 giây
                    self.logger.warning(f"Blocking {src} due to high rate ({cnt} packets)")
                    self._block_ip(src)
                    del self.packet_count[src]
                else:
                    # reset count sau mỗi chu kỳ
                    self.packet_count[src] = 0

    def _block_ip(self, ip, duration=60):
        if ip in self.blocked_ips:
            return
        self.blocked_ips[ip] = time.time() + duration
        for dp in self.datapaths.values():
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            actions = []
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, hard_timeout=duration)
            dp.send_msg(mod)
        self.logger.info(f"Blocked {ip}")

if __name__ == "__main__":
    from ryu.base.app_manager import AppManager
    app_mgr = AppManager.get_instance()
    app_mgr.instantiate_apps(SimpleBlocker)