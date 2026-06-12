import pandas as pd
import numpy as np
import requests
import random
from datetime import datetime, timezone

# =====================================================
# CONFIG
# =====================================================

import os

CSV_FILE = os.getenv(
    "CSV_FILE",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

MODEL_SERVER = os.getenv(
    "MODEL_SERVER",
    "http://localhost:8000"
)

ELASTICSEARCH = os.getenv(
    "ELASTICSEARCH",
    "http://localhost:9200"
)

BATCH_SIZE = 100

# =====================================================
# LOAD CSV
# =====================================================

print("Loading CSV...")

df = pd.read_csv(CSV_FILE)

# CICIDS columns have leading spaces
df.columns = df.columns.str.strip()

# Replace bad values
df = df.replace([np.inf, -np.inf], np.nan)
df = df.fillna(0)

if "Label" not in df.columns:
    raise Exception("Label column not found")

labels = df["Label"].copy()

features_df = df.drop(columns=["Label"])

# =====================================================
# FIX CICIDS FEATURE NAMES
# =====================================================

COLUMN_RENAME = {
    "Total Length of Fwd Packets": "Fwd Packets Length Total",
    "Total Length of Bwd Packets": "Bwd Packets Length Total",
    "Average Packet Size": "Avg Packet Size",
    "Max Packet Length": "Packet Length Max",
    "Min Packet Length": "Packet Length Min",
    "Init_Win_bytes_forward": "Init Fwd Win Bytes",
    "Init_Win_bytes_backward": "Init Bwd Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Packets",
    "min_seg_size_forward": "Fwd Seg Size Min"
}

features_df.rename(columns=COLUMN_RENAME, inplace=True)

print(f"Loaded {len(features_df):,} flows")

# =====================================================
# GET MODEL FEATURE LIST
# =====================================================

resp = requests.get(
    f"{MODEL_SERVER}/features",
    timeout=10
)

model_features = resp.json()["features"]

model_set = set(model_features)
csv_set = set(features_df.columns)

extra_cols = csv_set - model_set
missing_cols = model_set - csv_set

print("\nModel expects:", len(model_features))
print("CSV has:", len(features_df.columns))

if extra_cols:
    print("\nExtra columns:")
    for c in sorted(extra_cols):
        print("  ", c)

if missing_cols:
    print("\nMissing columns:")
    for c in sorted(missing_cols):
        print("  ", c)

# Remove extra columns
if extra_cols:
    features_df = features_df.drop(columns=list(extra_cols))

# Add missing columns as 0
for col in missing_cols:
    features_df[col] = 0

# Reorder exactly as model expects
features_df = features_df[model_features]

print("\nFinal feature count:", len(features_df.columns))

# =====================================================
# FINAL SANITY CHECK
# =====================================================

features_df = features_df.replace([np.inf, -np.inf], 0)
features_df = features_df.fillna(0)

print(
    "Remaining inf:",
    np.isinf(
        features_df.select_dtypes(include=[np.number])
    ).sum().sum()
)

print(
    "Remaining NaN:",
    features_df.isna().sum().sum()
)

# =====================================================
# STATS
# =====================================================

total = 0
correct = 0

attack_predictions = 0
benign_predictions = 0

false_positive = 0
false_negative = 0

# =====================================================
# REPLAY
# =====================================================

print("\nStarting replay...\n")

for start in range(0, len(features_df), BATCH_SIZE):

    end = min(start + BATCH_SIZE, len(features_df))

    batch = []

    batch_labels = labels.iloc[start:end].tolist()

    for _, row in features_df.iloc[start:end].iterrows():

        batch.append({
            "features": row.to_dict()
        })

    try:

        response = requests.post(
            f"{MODEL_SERVER}/predict/batch",
            json=batch,
            timeout=60
        )

        if response.status_code != 200:
            print(
                f"Batch {start}-{end} failed "
                f"HTTP {response.status_code}"
            )
            continue

        results = response.json()["results"]

        for idx, pred in enumerate(results):

            row_num = start + idx

            prediction = pred["prediction"]
            confidence = pred["confidence"]
            alert = pred["alert"]

            label = str(batch_labels[idx]).strip()

            expected = (
                "Benign"
                if label.upper() == "BENIGN"
                else "Attack"
            )

            is_correct = (
                prediction == expected
            )

            total += 1

            if is_correct:
                correct += 1

            if prediction == "Attack":
                attack_predictions += 1
            else:
                benign_predictions += 1

            if prediction == "Attack" and expected == "Benign":
                false_positive += 1

            if prediction == "Benign" and expected == "Attack":
                false_negative += 1

            now = datetime.now(
                timezone.utc
            ).isoformat()

            record = {
                "timestamp": now,
                "@timestamp": now,

                "src_ip":
                    f"10.0.{random.randint(1,254)}."
                    f"{random.randint(1,254)}",

                "dst_ip":
                    "192.168.104.128",

                "src_port":
                    str(random.randint(1024,65535)),

                "dst_port":
                    str(
                        random.choice(
                            [80,443,22,21,3389]
                        )
                    ),

                "prediction":
                    prediction,

                "confidence":
                    confidence,

                "alert":
                    alert,

                "true_label":
                    expected,

                "correct":
                    is_correct,

                "detector":
                    "CSV-Replay"
            }

            requests.post(
                f"{ELASTICSEARCH}/ids-alerts/_doc",
                json=record,
                timeout=5
            )

            # Only print attacks or mistakes
            if prediction == "Attack" or not is_correct:

                print(
                    f"[{row_num}] "
                    f"Pred={prediction} "
                    f"True={expected} "
                    f"Conf={confidence:.2%} "
                    f"Correct={is_correct}"
                )

        if total % 1000 == 0:

            accuracy = (
                correct / total
            ) * 100

            print(
                f"\n"
                f"Processed: {total:,}/{len(features_df):,}\n"
                f"Accuracy: {accuracy:.2f}%\n"
                f"Attack Predictions: {attack_predictions:,}\n"
                f"Benign Predictions: {benign_predictions:,}\n"
                f"False Positives: {false_positive:,}\n"
                f"False Negatives: {false_negative:,}\n"
            )

    except Exception as e:

        print(
            f"Batch {start}-{end} failed: {e}"
        )

# =====================================================
# FINAL REPORT
# =====================================================

accuracy = (
    (correct / total) * 100
    if total > 0 else 0
)

print("\n========== FINAL REPORT ==========\n")

print(f"Total Flows        : {total:,}")
print(f"Correct            : {correct:,}")
print(f"Accuracy           : {accuracy:.2f}%")

print()

print(f"Attack Predictions : {attack_predictions:,}")
print(f"Benign Predictions : {benign_predictions:,}")

print()

print(f"False Positives    : {false_positive:,}")
print(f"False Negatives    : {false_negative:,}")

print("\n==================================")