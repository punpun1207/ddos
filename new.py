# -*- coding: utf-8 -*-
"""
Updated controller (OpenFlow‑Ryu) with **feature logger**
-------------------------------------------------------
* Logs the five features (SSIP, SDFP, SDFB, SFE, NIFE) every WINDOW_SEC seconds
  into `flow_feature_log.csv`, together with a timestamp and an automatic label
  (0 = normal, 1 = attack) based on ATTACK_BEGIN / ATTACK_END.
* Keeps original PredictFlowStatsfile.csv workflow for the embedded DNN model.

How to use
~~~~~~~~~~~
1. Replace the old `cl_strict.py` with this file or rename accordingly.
2. Start the controller normally:

   ```bash
   ryu-manager cl_strict_logger.py
   ```
3. Generate traffic (normal + attack).  After the run you will have
   `flow_feature_log.csv` ready for offline plotting.
"""

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
import newswitch as switch
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from keras import layers, regularizers, callbacks, models, optimizers
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# ---------------------------------------------------------------------------
#  CONSTANTS
# ---------------------------------------------------------------------------
CSV_PREDICT   = "PredictFlowStatsfile.csv"      # temporary csv used for inference
FEATURE_LOG   = "flow_feature_log.csv"         # final dataset for plotting
WINDOW_SEC    = 3                               # stats polling window (seconds)

# phase boundaries (seconds, relative to controller start‑up) ----------------
ATTACK_BEGIN  = 60      # t >= 60 s  => label = 1 (attack)
ATTACK_END    = 180     # t < 180 s => label = 1, else 0
# ---------------------------------------------------------------------------

class SimpleMonitor13(switch.SimpleSwitch13):
    """Extended SimpleSwitch13 with feature extraction, DNN prediction
       *and* continuous feature logging."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # containers ---------------------------------------------------------
        self.datapaths   = {}
        self.prev_flows  = set()
        self.last_seen   = {}

        # ML assets ----------------------------------------------------------
        self.scaler      = None
        self.flow_model  = None
        self.flow_training()

        # timing  -----------------------------------------------------------
        self.start_time  = datetime.now().timestamp()

        # prepare log file header -------------------------------------------
        with open(FEATURE_LOG, "w") as f:
            f.write("time,ssip,sdfp,sdfb,sfe,nife,label\n")

        # start polling thread ----------------------------------------------
        self.monitor_thread = hub.spawn(self._monitor)

    # ---------------------------------------------------------------------
    #   Ryu event handlers
    # ---------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    # thread: poll flow stats every WINDOW_SEC ------------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(WINDOW_SEC)
            self.flow_predict()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        ts_now          = datetime.now().timestamp()
        elapsed         = ts_now - self.start_time

        flows_this_round, src_ip_set = set(), set()
        pkt_list, byte_list          = [], []
        interaction_keys             = set()

        # ---------------------- iterate over flow stats --------------------
        for st in ev.msg.body:
            if st.priority != 1:
                continue
            m       = st.match
            ip_src  = m.get('ipv4_src'); ip_dst = m.get('ipv4_dst'); proto  = m.get('ip_proto')
            if not (ip_src and ip_dst and proto):
                continue
            tp_src  = m.get('tcp_src', m.get('udp_src', 0))
            tp_dst  = m.get('tcp_dst', m.get('udp_dst', 0))
            fid     = f"{ip_src}-{tp_src}-{ip_dst}-{tp_dst}-{proto}"

            flows_this_round.add(fid)
            src_ip_set.add(ip_src)
            pkt_list.append(st.packet_count)
            byte_list.append(st.byte_count)
            interaction_keys.add((ip_src, tp_src, ip_dst, tp_dst))

        # ---------------------- compute 5 features -------------------------
        ssip = len(src_ip_set)
        sdfp = np.std(pkt_list)  if len(pkt_list)  > 1 else 0
        sdfb = np.std(byte_list) if len(byte_list) > 1 else 0
        sfe  = len(flows_this_round - self.prev_flows)
        self.prev_flows = flows_this_round
        pair_count = sum(1 for (a1, p1, a2, p2) in interaction_keys if (a2, p2, a1, p1) in interaction_keys)
        nife = pair_count / sfe if sfe > 0 else 0

        # ---------------------- write to *feature* log ---------------------
        label = int(ATTACK_BEGIN <= elapsed < ATTACK_END)
        with open(FEATURE_LOG, "a") as flog:
            flog.write(f"{ts_now:.3f},{ssip},{sdfp},{sdfb},{sfe},{nife},{label}\n")

        # ---------------------- prepare csv for inference ------------------
        with open(CSV_PREDICT, "w") as f:
            f.write("SSIP,SDFP,SDFB,SFE,NIFE,ip_dst\n")
            for (a1, p1, a2, p2) in interaction_keys:
                f.write(f"{ssip},{sdfp},{sdfb},{sfe},{nife},{a2}\n")

    # ---------------------------------------------------------------------
    #   Model training & inference
    # ---------------------------------------------------------------------
    def flow_training(self):
        """Train DNN on concatenated normal + attack CSVs (one‑shot)."""
        df       = pd.concat([pd.read_csv('normal.csv'), pd.read_csv('ddos_attack.csv')], ignore_index=True)
        X        = df.drop(columns=['label'])
        y        = df['label'].astype(int)

        self.scaler = StandardScaler().fit(X)
        X_scaled    = self.scaler.transform(X)
        X_tr, X_te, y_tr, y_te = train_test_split(X_scaled, y, test_size=0.25, stratify=y)

        model = models.Sequential([
            layers.Dense(128, kernel_regularizer=regularizers.l2(1e-4), input_shape=(X.shape[1],)),
            layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.2),
            layers.Dense(64,  kernel_regularizer=regularizers.l2(1e-4)),
            layers.BatchNormalization(), layers.LeakyReLU(), layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer=optimizers.Adam(1e-3), loss='binary_crossentropy', metrics=['accuracy'])
        cb = [callbacks.ReduceLROnPlateau(patience=3, factor=0.5),
              callbacks.EarlyStopping(patience=6, restore_best_weights=True)]
        model.fit(X_tr, y_tr, epochs=100, batch_size=128, validation_split=0.2, callbacks=cb, verbose=0)

        self.flow_model = model
        acc = model.evaluate(X_te, y_te, verbose=0)[1]
        print(f"[DNN] Test accuracy: {acc*100:.2f}%")

    def flow_predict(self):
        """Load PredictFlowStatsfile.csv ➜ scale ➜ predict ➜ print log."""
        try:
            df = pd.read_csv(CSV_PREDICT)
            if df.empty:
                return
            ip_dst = df['ip_dst'].tolist()
            X_scaled = self.scaler.transform(df.drop(columns=['ip_dst']))
            y_pred   = (self.flow_model.predict(X_scaled, verbose=0) > 0.5).astype(int).flatten()

            ddos = np.sum(y_pred)
            if ddos > 0.2 * len(y_pred):
                victims = {}
                for idx, lbl in enumerate(y_pred):
                    if lbl:
                        victims[ip_dst[idx]] = victims.get(ip_dst[idx], 0) + 1
                victim = max(victims, key=victims.get, default='unknown')
                self.logger.warning("DDoS detected! Victim IP: %s", victim)
            else:
                self.logger.info("Traffic legitimate (%.0f flows)", len(y_pred))
        except Exception as err:
            self.logger.error("Prediction failed: %s", err)
        finally:
            # reset csv for next polling round
            with open(CSV_PREDICT, 'w') as f:
                f.write("SSIP,SDFP,SDFB,SFE,NIFE,ip_dst\n")
