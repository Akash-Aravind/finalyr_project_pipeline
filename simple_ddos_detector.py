# single_random_prediction_to_file.py
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import joblib
import random

# CONFIG
FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
]
WINDOW_SIZE = 10
DROP_COLS = [
    "Flow Duration","Flow Bytes/s","Flow Packets/s","Fwd Packets/s","Bwd Packets/s",
    "Fwd Avg Bytes/Bulk","Bwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Bwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate","Bwd Avg Bulk Rate"
]
OUTPUT_FILE = "random_ddos_prediction.txt"

# Load model and preprocessing artifacts
model = load_model("lstm_network_traffic_model.h5")
scaler = joblib.load("scaler.pkl")
le = joblib.load("label_encoder.pkl")

# Load and clean data
df = pd.concat([pd.read_csv(f) for f in FILES], ignore_index=True)
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df.reset_index(drop=True, inplace=True)
df = df.drop(columns=[c for c in DROP_COLS if c in df.columns])

# Numeric features only
numeric = df.drop(columns=['Label']).select_dtypes(include=[np.number]).values
if numeric.shape[0] < WINDOW_SIZE:
    raise SystemExit("Not enough rows to form a window")

# Pick a random starting index
start_idx = random.randint(0, len(numeric) - WINDOW_SIZE)
end_idx = start_idx + WINDOW_SIZE

# Prepare single window for prediction
X_window = numeric[start_idx:end_idx]
X_scaled = scaler.transform(X_window).reshape(1, WINDOW_SIZE, X_window.shape[1])

# Predict
probs = model.predict(X_scaled, verbose=0)[0]
pred_class_index = np.argmax(probs)
pred_label = le.inverse_transform([pred_class_index])[0]
pred_prob = probs[pred_class_index]

# Prepare output text
output_lines = [
    f"Random window rows: {start_idx} -> {end_idx-1}",
    f"Predicted: {pred_label} (prob={pred_prob:.4f})",
    "Window data:",
    df.iloc[start_idx:end_idx].to_string(index=True)
]

# Write to file
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(output_lines))

print(f"Prediction written to {OUTPUT_FILE}")
