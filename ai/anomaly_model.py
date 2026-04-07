import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os
import threading

class AnomalyModel:
    def __init__(self, buffer_size=500):
        self.model = None
        self.feature_buffer = []
        self.buffer_size = buffer_size
        self.is_trained = False
        self.lock = threading.Lock()

    def _extract_features(self, packet_info):
        size = packet_info['size']
        proto = packet_info['protocol']
        proto_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
        proto_code = proto_map.get(proto, 3)
        return [size, proto_code]

    def add_packet(self, packet_info):
        feats = self._extract_features(packet_info)
        with self.lock:
            self.feature_buffer.append(feats)
            if len(self.feature_buffer) >= self.buffer_size and not self.is_trained:
                self._train()
            return feats

    def _train(self):
        X = np.array(self.feature_buffer)
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(X)
        self.is_trained = True
        print(f"[AI] Anomaly model trained on {len(X)} samples.")

    def predict_anomaly_score(self, packet_info):
        if not self.is_trained:
            return 0.0
        feats = self._extract_features(packet_info)
        pred = self.model.predict([feats])[0]
        if pred == -1:
            score = -self.model.decision_function([feats])[0]
            score = np.clip(score, 0, 1)
        else:
            score = 0.0
        return score