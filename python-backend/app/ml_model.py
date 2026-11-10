import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_NAMES = [
    "total_packets",
    "total_bytes",
    "mean_len",
    "tcp_ratio",
    "udp_ratio",
    "bytes_per_sec",
    "syn_count",
    "packets_per_sec",
    "connection_count",
    "avg_packets_per_connection",
    "avg_bytes_per_connection",
    "protocol_diversity",
    "unique_destination_ports",
    "syn_ratio",
    "avg_packets_per_port",
]

class AnomalyModel:
    def __init__(self, contamination, model_path):
        self.contamination = contamination
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,
            random_state=42,
        )
        self.feature_names = FEATURE_NAMES

    def train(self, baseline_data):
        X = np.array(baseline_data)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        joblib.dump((self.model, self.scaler), self.model_path)

    def load(self):
        self.model, self.scaler = joblib.load(self.model_path)

    def predict(self, features):
        X_scaled = self.scaler.transform([features])
        return self.model.predict(X_scaled)[0]

    def score(self, features):
        X_scaled = self.scaler.transform([features])
        return float(self.model.decision_function(X_scaled)[0])

    def explain(self, features):
        """
        Returns per-feature z-scores (deviation from baseline mean) sorted by
        absolute magnitude — higher = more abnormal for that feature.
        """
        z_scores = self.scaler.transform([features])[0]
        explanation = [(name, float(z)) for name, z in zip(self.feature_names, z_scores)]
        explanation.sort(key=lambda x: abs(x[1]), reverse=True)
        return explanation

    def get_severity(self, score):
        if score <= -0.09:
            return "Strong"
        elif score <= -0.05:
            return "Moderate"
        return "Mild"
