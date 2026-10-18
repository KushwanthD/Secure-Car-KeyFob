"""
sentinel.py - AI-Powered Threat Monitoring Layer ("Sentinel")

Role:
  Defense-in-depth security monitor for automotive keyless entry.
  Watches handshake metadata (timing, jitter, counter gaps, hop counts, failure rates)
  without touching cryptographic keys or plaintexts.

Failsafe Benchmark:
  Never overrides cryptography. If the AI model crashes, is uninitialized,
  or fails to predict, the core cryptographic handshake proceeds unaffected.
"""

import os
import time
import logging
import threading
import numpy as np

# Lazy/safe imports for machine learning dependencies
try:
    import joblib
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_models")

# Class labels for supervised classification
ATTACK_LABELS = {
    0: "NORMAL",
    1: "RELAY_ATTACK",
    2: "BRUTE_FORCE",
    3: "JAMMING_ATTACK",
    4: "ROLLJAM_ATTACK",
    5: "REPLAY_ATTACK",
}

FEATURE_NAMES = [
    "duration_ms",
    "jitter_ms",
    "failure_rate",
    "counter_gap",
    "hop_count",
    "attempts_needed",
    "time_delta_sec",
]


class SentinelMonitor:
    """
    Two-stage AI Threat Monitor:
      Stage 1: Isolation Forest (unsupervised anomaly detection trained strictly on verified owner baselines)
      Stage 2: Random Forest (supervised classifier for categorizing specific attack vectors)
    """

    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.lock = threading.Lock()
        
        # State tracking per device/IP (sliding window)
        self.device_history = {} # device_id -> list of recent session records
        self.last_session_time = {} # device_id -> timestamp
        self.recent_rtts = {} # device_id -> list of recent RTTs for jitter calculation
        
        # ML models
        self.scaler = None
        self.anomaly_detector = None
        self.attack_classifier = None
        self.is_loaded = False

        self._load_or_initialize()

    def _load_or_initialize(self):
        """Load trained models from disk if available, otherwise train baseline models."""
        if not SKLEARN_AVAILABLE:
            logging.warning("[SENTINEL] scikit-learn not available; running in heuristic fallback mode.")
            return

        scaler_path = os.path.join(self.model_dir, "scaler.joblib")
        iforest_path = os.path.join(self.model_dir, "isolation_forest.joblib")
        clf_path = os.path.join(self.model_dir, "attack_classifier.joblib")

        if os.path.exists(scaler_path) and os.path.exists(iforest_path) and os.path.exists(clf_path):
            try:
                self.scaler = joblib.load(scaler_path)
                self.anomaly_detector = joblib.load(iforest_path)
                self.attack_classifier = joblib.load(clf_path)
                self.is_loaded = True
                logging.info("[SENTINEL] AI Threat Monitor loaded successfully from %s", self.model_dir)
            except Exception as e:
                logging.error("[SENTINEL] Error loading models: %s. Using heuristic fallback.", e)
        else:
            logging.info("[SENTINEL] No pre-trained models found. Automatically training default baseline...")
            try:
                self.train_and_save_default_models()
            except Exception as e:
                logging.error("[SENTINEL] Automatic baseline training failed: %s. Running in heuristic mode.", e)

    def extract_features(self, device_id: str, telemetry: dict) -> np.ndarray:
        """
        Extract numerical features from raw session telemetry.
        Features: [duration_ms, jitter_ms, failure_rate, counter_gap, hop_count, attempts_needed, time_delta_sec]
        """
        with self.lock:
            now = time.time()
            last_time = self.last_session_time.get(device_id, now - 60.0)
            time_delta = max(0.01, now - last_time)
            self.last_session_time[device_id] = now

            duration_ms = float(telemetry.get("duration_ms", 15.0))

            if "jitter_ms" in telemetry:
                jitter_ms = float(telemetry["jitter_ms"])
            else:
                # Maintain sliding RTT window (last 10 sessions) for jitter calculation
                rtts = self.recent_rtts.setdefault(device_id, [])
                rtts.append(duration_ms)
                if len(rtts) > 10:
                    rtts.pop(0)

                mean_rtt = np.mean(rtts) if len(rtts) > 1 else duration_ms
                jitter_ms = abs(duration_ms - mean_rtt)

            failure_rate = float(telemetry.get("failure_rate", 0.0))
            counter_gap = float(max(0, telemetry.get("counter_gap", 0)))
            hop_count = float(telemetry.get("hop_count", 0))
            attempts_needed = float(telemetry.get("attempts_needed", 1))

            features = np.array([
                duration_ms,
                jitter_ms,
                failure_rate,
                counter_gap,
                hop_count,
                attempts_needed,
                time_delta,
            ], dtype=np.float32)

            return features

    def evaluate_session(self, device_id: str, telemetry: dict) -> dict:
        """
        Evaluates session metadata and returns risk assessment.
        Failsafe: Never throws an unhandled exception.
        """
        default_result = {
            "risk_score": 0.0,
            "level": "LOW",
            "action": "ALLOW",
            "attack_type": "NORMAL",
            "confidence": 1.0,
            "explanations": ["Session within expected baseline parameters."],
        }

        try:
            raw_features = self.extract_features(device_id, telemetry)
            
            # If models are loaded, perform ML evaluation
            if self.is_loaded and self.scaler and self.anomaly_detector and self.attack_classifier:
                scaled_features = self.scaler.transform([raw_features])
                
                # Stage 1: Isolation Forest Anomaly Score
                # decision_function: lower means more anomalous.
                raw_score = self.anomaly_detector.decision_function(scaled_features)[0]
                # Normalize decision function to approx [0, 1] anomaly score
                anomaly_score = float(np.clip(0.5 - (raw_score * 2.0), 0.0, 1.0))

                # Stage 2: Supervised Attack Classifier
                pred_class = int(self.attack_classifier.predict(scaled_features)[0])
                pred_proba = self.attack_classifier.predict_proba(scaled_features)[0]
                class_label = ATTACK_LABELS.get(pred_class, "NORMAL")
                class_confidence = float(pred_proba[pred_class])

                # Attack probability is 1.0 - P(NORMAL)
                attack_prob = float(1.0 - pred_proba[0])

                # Unified Risk Score combining anomaly and classified attack probability
                risk_score = float(max(anomaly_score, attack_prob))
            else:
                # Heuristic Rule-Based Fallback if ML is unavailable
                risk_score, class_label, class_confidence = self._heuristic_evaluation(raw_features)

            # Graduated response categorization
            explanations = self._generate_explanations(raw_features, class_label, risk_score)

            if risk_score < 0.40:
                level = "LOW"
                action = "ALLOW"
            elif risk_score < 0.75:
                level = "MEDIUM"
                action = "ADAPTIVE_CHALLENGE"  # Tighter rate limits, requires step-up / MFA
            else:
                level = "HIGH"
                action = "ELEVATED_DEFENSE"    # Refuse unlock, alert owner, block IP

            return {
                "risk_score": round(risk_score, 3),
                "level": level,
                "action": action,
                "attack_type": class_label,
                "confidence": round(class_confidence, 3),
                "explanations": explanations,
                "features": {name: round(float(val), 2) for name, val in zip(FEATURE_NAMES, raw_features)},
            }

        except Exception as e:
            logging.error("[SENTINEL FAILSAFE] Error during AI session evaluation: %s", e)
            return default_result

    def _heuristic_evaluation(self, features: np.ndarray) -> tuple[float, str, float]:
        """Heuristic fallback rule-engine in case ML libraries are not ready."""
        dur, jitter, fails, gap, hops, attempts, dt = features
        risk = 0.0
        label = "NORMAL"

        if dur > 250.0 or jitter > 100.0:
            risk = max(risk, 0.85)
            label = "RELAY_ATTACK"
        elif fails >= 3.0:
            risk = max(risk, 0.80)
            label = "BRUTE_FORCE"
        elif hops >= 2.0 or attempts >= 3.0:
            risk = max(risk, 0.75)
            label = "JAMMING_ATTACK"
        elif gap >= 4.0:
            risk = max(risk, 0.70)
            label = "ROLLJAM_ATTACK"
        
        return risk, label, 0.90

    def _generate_explanations(self, features: np.ndarray, attack_type: str, risk_score: float) -> list[str]:
        """Generate human-readable explanations of anomalous feature deviations."""
        dur, jitter, fails, gap, hops, attempts, dt = features
        reasons = []

        if dur > 150.0:
            reasons.append(f"Excessive round-trip latency ({dur:.1f}ms vs 20ms baseline) indicates signal forwarding.")
        if jitter > 40.0:
            reasons.append(f"Elevated transmission jitter ({jitter:.1f}ms) characteristic of relay hops.")
        if fails >= 2.0:
            reasons.append(f"High failure burst ({fails:.0f} prior failed attempts in window).")
        if gap >= 2.0:
            reasons.append(f"Abnormal rolling-code gap detected ({gap:.0f} counters skipped).")
        if hops >= 2.0 or attempts >= 2.0:
            reasons.append(f"Excessive FHSS frequency hops ({hops:.0f} hops across {attempts:.0f} attempts).")

        if not reasons and risk_score < 0.40:
            reasons.append("Handshake timing, counter continuity, and channel health are within normal owner baseline.")

        return reasons

    def train_and_save_default_models(self):
        """Generates realistic synthetic datasets, trains both stages, and saves to disk."""
        if not SKLEARN_AVAILABLE:
            return

        os.makedirs(self.model_dir, exist_ok=True)
        from train_sentinel import generate_synthetic_data, train_models

        X_normal, X_all, y_all = generate_synthetic_data(n_samples=2000)
        scaler, iforest, clf, metrics = train_models(X_normal, X_all, y_all)

        joblib.dump(scaler, os.path.join(self.model_dir, "scaler.joblib"))
        joblib.dump(iforest, os.path.join(self.model_dir, "isolation_forest.joblib"))
        joblib.dump(clf, os.path.join(self.model_dir, "attack_classifier.joblib"))

        self.scaler = scaler
        self.anomaly_detector = iforest
        self.attack_classifier = clf
        self.is_loaded = True
        logging.info("[SENTINEL] Models generated, evaluated, and saved to %s", self.model_dir)


# Global singleton instance
_sentinel_instance = None
_instance_lock = threading.Lock()

def get_sentinel() -> SentinelMonitor:
    """Get or initialize the global Sentinel singleton."""
    global _sentinel_instance
    with _instance_lock:
        if _sentinel_instance is None:
            _sentinel_instance = SentinelMonitor()
        return _sentinel_instance
