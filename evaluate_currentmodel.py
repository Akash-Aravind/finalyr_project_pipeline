import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, classification_report,
    roc_curve, auc, precision_recall_curve
)
from sklearn.preprocessing import label_binarize
from tensorflow.keras.models import load_model
from tensorflow.keras.utils import to_categorical
import joblib
import os

# === 1. Load Model, Scaler, and Label Encoder ===
model = load_model("lstm_network_traffic_model.h5")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

print("✅ Model and preprocessing objects loaded successfully!")

# === 2. Load Dataset (same as training) ===
files = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
]
df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

drop_cols = [
    "Flow Duration", "Flow Bytes/s", "Flow Packets/s",
    "Fwd Packets/s", "Bwd Packets/s",
    "Fwd Avg Bytes/Bulk", "Bwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Bwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bulk Rate"
]
df = df.drop(columns=[c for c in drop_cols if c in df.columns])

df['Label'] = label_encoder.transform(df['Label'])
num_classes = len(label_encoder.classes_)

# === 3. Recreate Sliding Window ===
WINDOW_SIZE = 10
features, labels = [], []
numeric_df = df.drop(columns=['Label']).select_dtypes(include=[np.number]).values
y = df['Label'].values

for i in range(WINDOW_SIZE, len(df)):
    window = numeric_df[i - WINDOW_SIZE:i]
    features.append(window)
    labels.append(y[i])

X = np.array(features)
y = np.array(labels)

# === 4. Apply the saved Scaler ===
num_samples, timesteps, num_features = X.shape
X_2d = X.reshape(-1, num_features)
X_scaled_2d = scaler.transform(X_2d)
X_scaled = X_scaled_2d.reshape(num_samples, timesteps, num_features)

# === 5. Predict ===
y_pred_prob = model.predict(X_scaled, verbose=0)
y_pred = np.argmax(y_pred_prob, axis=1)

# === 6. Metrics ===
print("\n📊 Classification Report:")
print(classification_report(y, y_pred, target_names=label_encoder.classes_))

# === 7. Confusion Matrix ===
cm = confusion_matrix(y, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# === 8. ROC & AUC ===
y_bin = to_categorical(y, num_classes=num_classes)
if num_classes == 2:
    fpr, tpr, _ = roc_curve(y, y_pred_prob[:, 1])
    roc_auc = auc(fpr, tpr)
    plt.figure()
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.show()
else:
    fpr, tpr, roc_auc = {}, {}, {}
    for i in range(num_classes):
        fpr[i], tpr[i], _ = roc_curve(y_bin[:, i], y_pred_prob[:, i])
        roc_auc[i] = auc(fpr[i], tpr[i])
    plt.figure()
    for i in range(num_classes):
        plt.plot(fpr[i], tpr[i], lw=2, label=f'{label_encoder.classes_[i]} (AUC = {roc_auc[i]:.2f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Multi-class ROC Curve')
    plt.legend()
    plt.show()

# === 9. Precision-Recall Curve ===
if num_classes == 2:
    precision, recall, _ = precision_recall_curve(y, y_pred_prob[:, 1])
    plt.figure()
    plt.plot(recall, precision, color='blue', lw=2)
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.show()

# === 10. Accuracy Bar ===
accuracy = np.mean(y == y_pred)
plt.figure()
plt.bar(['Accuracy'], [accuracy])
plt.ylim(0, 1)
plt.text(0, accuracy/2, f'{accuracy*100:.2f}%', ha='center', color='white', fontsize=12)
plt.title('Model Accuracy on Full Dataset')
plt.show()

print(f"\n✅ Overall Accuracy: {accuracy*100:.2f}%")

# === 11. Save Graphs Automatically ===
os.makedirs("results", exist_ok=True)
plt.figure()
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_)
plt.title("Confusion Matrix")
plt.savefig("results/confusion_matrix.png", dpi=300)
plt.close()

if num_classes == 2:
    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")
    plt.plot([0, 1], [0, 1], 'k--')
    plt.title("ROC Curve")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend()
    plt.savefig("results/roc_curve.png", dpi=300)
    plt.close()

print("📁 All result images saved to /results folder.")
