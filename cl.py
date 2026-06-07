from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
import newswitch as switch
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.optimizers import Adam
from keras import layers, regularizers, callbacks, models, optimizers
from sklearn.preprocessing import RobustScaler

CSV_PREDICT = "PredictFlowStatsfile.csv"
WINDOW_SEC = 10      # hub.sleep window

class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.last_seen = {}           # for inter‑arrival
        self.prev_flows = set()       # for SFE
        self.scaler = None
        self.flow_model = None
        # train once at start
        t0 = datetime.now(); self.flow_training();
        self.logger.info("Training Δt %s", datetime.now() - t0)

    # ---------------- Ryu state -----------------
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

    # --------------- Stats reply ----------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        ts_now = datetime.now().timestamp()
        rows, byte_list = [], []
        flows_this_round, src_ip_set = set(), set()
        src_ip_flow_cnt = {}

        for st in ev.msg.body:
            if st.priority != 1:
                continue
            m = st.match
            ip_src = m.get('ipv4_src'); ip_dst = m.get('ipv4_dst'); ip_proto = m.get('ip_proto')
            if not (ip_src and ip_dst and ip_proto):
                continue

            tp_src = m.get('tcp_src', m.get('udp_src', 0))
            tp_dst = m.get('tcp_dst', m.get('udp_dst', 0))
            fid = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{ip_proto}"

            # update sets for SSIP/SFE
            flows_this_round.add(fid)
            src_ip_set.add(ip_src)

            # basic counters
            dur = st.duration_sec + st.duration_nsec/1e9
            p_rate = st.packet_count/dur if dur > 0 else 0
            b_rate = st.byte_count/dur if dur > 0 else 0

            inter = 0
            if fid in self.last_seen:
                inter = ts_now - self.last_seen[fid]
            self.last_seen[fid] = ts_now

            src_ip_flow_cnt[ip_src] = src_ip_flow_cnt.get(ip_src, 0) + 1
            flow_per_src = src_ip_flow_cnt[ip_src]

            byte_list.append(st.byte_count)

            rows.append([st.packet_count, st.byte_count, dur, p_rate, b_rate,
                         flow_per_src, inter, ip_dst])

        # window‑level features
        ssip = len(src_ip_set)
        sdfb = np.std(byte_list) if len(byte_list) > 1 else 0
        sfe  = len(flows_this_round - self.prev_flows)
        self.prev_flows = flows_this_round

        # write CSV for predictor
        with open(CSV_PREDICT, "w") as f:
            f.write("packet_count,byte_count,duration,packet_rate,byte_rate,flow_count_per_src_ip,inter_arrival_time,SSIP,SDFB,SFE,ip_dst\n")
            for pkt, byt, dur, pr, br, fps, inter, ip_dst in rows:
                f.write(f"{pkt},{byt},{dur},{pr},{br},{fps},{inter},{ssip},{sdfb},{sfe},{ip_dst}\n")

    # --------------- Training ------------------
    def flow_training(self):
        self.logger.info("Flow Training …")
        df = pd.concat([pd.read_csv('ddos_normal.csv'), pd.read_csv('ddos_attack.csv')], ignore_index=True)
        df = df[df['packet_count'] > 0].sample(frac=1, random_state=42)

        X = df.drop(columns=['label']); y = df['label'].astype(int)
        self.scaler = RobustScaler().fit(X)
        X_scaled = self.scaler.transform(X)

        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.25, random_state=2, stratify=y)

        n_in = X_scaled.shape[1]

        model = models.Sequential([
            layers.Dense(128, kernel_regularizer=regularizers.l2(1e-4),
                        input_shape=(n_in,)),
            layers.BatchNormalization(),
            layers.LeakyReLU(),
            layers.Dropout(0.4),

            layers.Dense(64, kernel_regularizer=regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.LeakyReLU(),
            layers.Dropout(0.3),

            layers.Dense(32, kernel_regularizer=regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.LeakyReLU(),

            layers.Dense(1, activation='sigmoid')
        ])

        model.compile(optimizers.Adam(1e-3),
                    loss='binary_crossentropy',
                    metrics=['accuracy'])

        cb = [
            callbacks.ReduceLROnPlateau(patience=3, factor=0.5, verbose=1),
            callbacks.EarlyStopping(patience=6, restore_best_weights=True, verbose=1)
        ]

        history = model.fit(
            X_train, y_train,
            epochs=100,
            batch_size=128,
            validation_split=0.2,
            callbacks=cb,
            verbose=2
        )

        self.flow_model = model

        loss, acc = model.evaluate(X_test, y_test, verbose=0)
        print(f"Test accuracy: {acc*100:.2f}%")

        # Confusion matrix
        from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
        y_pred = (model.predict(X_test) > 0.5).astype(int).flatten()
        cm = confusion_matrix(y_test, y_pred)
        disp = ConfusionMatrixDisplay(cm, display_labels=['Benign','DDoS'])
        disp.plot(cmap='Blues')

    # --------------- Prediction ---------------
    def flow_predict(self):
        try:
            df = pd.read_csv(CSV_PREDICT)
            if df.empty:
                return
            ip_dst = df['ip_dst'].tolist()
            X_scaled = self.scaler.transform(df.drop(columns=['ip_dst']))
            y_pred = (self.flow_model.predict(X_scaled) > 0.7).astype(int).flatten()

            legit = np.sum(y_pred == 0); ddos = np.sum(y_pred == 1)
            self.logger.info("Legitimate=%d, DDoS=%d, Total=%d", legit, ddos, len(y_pred))

            if ddos > 0.2*len(y_pred):
                vc = {}
                for idx, lbl in enumerate(y_pred):
                    if lbl == 1:
                        vc[ip_dst[idx]] = vc.get(ip_dst[idx], 0)+1
                victim = max(vc, key=vc.get) if vc else 'unknown'
                self.logger.warning("DDoS detected! Victim IP: %s", victim)
            else:
                self.logger.info("Traffic legitimate …")
        except Exception as e:
            self.logger.error("Prediction failed: %s", e)
        finally:
            open(CSV_PREDICT, 'w').write('packet_count,byte_count,duration,packet_rate,byte_rate,flow_count_per_src_ip,inter_arrival_time,SSIP,SDFB,SFE,ip_dst\n')
