
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
import newswitch as switch
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.preprocessing import StandardScaler
from keras import layers, regularizers, callbacks, models, optimizers
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

CSV_PREDICT = "PredictFlowStatsfile.csv"
WINDOW_SEC = 3

class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.last_seen = {}
        self.prev_flows = set()
        self.scaler = None
        self.flow_model = None
        self.flow_training()

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
            self.flow_predict()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        ts_now = datetime.now().timestamp()
        flows_this_round, src_ip_set, pkt_list, byte_list = set(), set(), [], []
        interaction_keys = set()

        for st in ev.msg.body:
            if st.priority != 1:
                continue
            m = st.match
            ip_src = m.get('ipv4_src'); ip_dst = m.get('ipv4_dst'); proto = m.get('ip_proto')
            if not (ip_src and ip_dst and proto): continue
            tp_src = m.get('tcp_src', m.get('udp_src', 0))
            tp_dst = m.get('tcp_dst', m.get('udp_dst', 0))
            fid = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{proto}"
            flows_this_round.add(fid)
            src_ip_set.add(ip_src)
            pkt_list.append(st.packet_count)
            byte_list.append(st.byte_count)
            interaction_keys.add((ip_src, tp_src, ip_dst, tp_dst))

        # SSIP
        ssip = len(src_ip_set)
        # SDFP
        sdfp = np.std(pkt_list) if len(pkt_list) > 1 else 0
        # SDFB
        sdfb = np.std(byte_list) if len(byte_list) > 1 else 0
        # SFE
        sfe = len(flows_this_round - self.prev_flows)
        self.prev_flows = flows_this_round
        # NIFE
        pair_count = 0
        for (a1, p1, a2, p2) in interaction_keys:
            if (a2, p2, a1, p1) in interaction_keys:
                pair_count += 1
        nife = pair_count / sfe if sfe > 0 else 0

        # Save for prediction
        with open(CSV_PREDICT, "w") as f:
            f.write("SSIP,SDFP,SDFB,SFE,NIFE,ip_dst\n")
            for (a1, p1, a2, p2) in interaction_keys:
                f.write(f"{ssip},{sdfp},{sdfb},{sfe},{nife},{a2}\n")

    def flow_training(self):
        df = pd.concat([pd.read_csv('normal.csv'), pd.read_csv('ddos_attack.csv')], ignore_index=True)
        X = df.drop(columns=['label'])
        y = df['label'].astype(int)
        self.scaler = StandardScaler().fit(X)
        X_scaled = self.scaler.transform(X)
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.25, stratify=y)

        # model = models.Sequential([
        #     layers.Dense(128, kernel_regularizer=regularizers.l2(1e-4), input_shape=(X.shape[1],)),
        #     layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.2),
        #     layers.Dense(64, kernel_regularizer=regularizers.l2(1e-4)),
        #     layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.3),
        #     layers.Dense(1, activation='sigmoid')
        # ])

        model = models.Sequential([
            layers.Dense(128, kernel_regularizer=regularizers.l2(1e-4), input_shape=(X.shape[1],)),
            layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.2),

            layers.Dense(256, kernel_regularizer=regularizers.l2(1e-4)),
            layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.3),

            layers.Dense(128, kernel_regularizer=regularizers.l2(1e-4)),
            layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.3),

            layers.Dense(64, kernel_regularizer=regularizers.l2(1e-4)),
            layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.3),

            layers.Dense(1, activation='sigmoid')
        ])


        model.compile(optimizer=optimizers.Adam(1e-3), loss='binary_crossentropy', metrics=['accuracy'])
        cb = [callbacks.ReduceLROnPlateau(patience=3, factor=0.5), callbacks.EarlyStopping(patience=6, restore_best_weights=True)]
        model.fit(X_train, y_train, epochs=100, batch_size=128, validation_split=0.2, callbacks=cb, verbose=0)

        self.flow_model = model
        acc = model.evaluate(X_test, y_test, verbose=0)[1]
        print(f"Test accuracy: {acc*100:.2f}%")

    def flow_predict(self):
        try:
            df = pd.read_csv(CSV_PREDICT)
            if df.empty: return
            ip_dst = df['ip_dst'].tolist()
            X_scaled = self.scaler.transform(df.drop(columns=['ip_dst']))
            y_pred = (self.flow_model.predict(X_scaled, verbose=0) > 0.5).astype(int).flatten()
            legit = np.sum(y_pred == 0); ddos = np.sum(y_pred == 1)

            # ✅ Lấy lại SSIP và SFE từ 1 dòng (chúng giống nhau ở tất cả dòng)
            ssip = df['SSIP'].iloc[0]
            sfe = df['SFE'].iloc[0]

            if ddos > 0.2 * len(y_pred):
                vc = {}
                for idx, lbl in enumerate(y_pred):
                    if lbl == 1:
                        vc[ip_dst[idx]] = vc.get(ip_dst[idx], 0)+1
                victim = max(vc, key=vc.get) if vc else 'unknown'
                self.logger.warning("DDoS detected! Victim IP: %s", victim)

                # ✅ Chặn theo ngưỡng SSIP + SFE
                if ssip > 100 and sfe > 300:
                    self.logger.warning("DDoS suspected based on high SSIP and SFE!")
                    self.logger.warning("SSIP: %d, SFE: %d → Blocking flow entries...", ssip, sfe)
                    self.block_suspect_traffic()
                    return
            else:
                self.logger.info("Traffic legitimate.")
        except Exception as e:
            self.logger.error("Prediction failed: %s", e)
        finally:
            open(CSV_PREDICT, 'w').write("SSIP,SDFP,SDFB,SFE,NIFE,ip_dst\n")

    def block_suspect_traffic(self):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            # Drop toàn bộ IPv4 (hoặc thêm điều kiện cụ thể hơn nếu muốn)
            match = parser.OFPMatch(eth_type=0x0800)  # IPv4
            actions = []  # drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=100,
                match=match,
                instructions=inst,
                command=ofproto.OFPFC_ADD
            )
            dp.send_msg(mod)
            self.logger.warning("Sent flow-mod to drop suspicious IPv4 traffic.")

