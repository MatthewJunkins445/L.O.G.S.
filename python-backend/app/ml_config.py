import os
import sys

def get_models_dir():
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "models")
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")

MODELS_DIR = get_models_dir()

WINDOW_SIZE = 15

MAX_BASELINE_WINDOWS = 150
BEST_WINDOW_COUNT = 100
RECENT_WINDOW_COUNT = 50
NEW_BATCH_OUTLIER_FRACTION = 0.10
COMBINED_OUTLIER_FRACTION = 0.05

CONTAMINATION = 0.01

# Windows to capture during initial user setup (10 × 15s ≈ 2.5 min)
SETUP_BASELINE_WINDOWS = 10

MODEL_PATH = os.path.join(MODELS_DIR, "user_anomaly_model.pkl")
USER_BASELINE_PATH = os.path.join(MODELS_DIR, "user_baseline.pkl")
