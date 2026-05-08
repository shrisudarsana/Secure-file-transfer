"""
AI Model Training Script
========================
Trains a Random Forest classifier on a synthetic dataset
to classify files as SAFE (0) or SUSPICIOUS (1).

Run this script once to generate model.pkl:
    python ai_module/train_model.py
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ─── Synthetic Training Dataset ───────────────────────────────────────────────
# Features:
#   ext_risk        : 0=safe extension, 1=medium risk, 2=high risk
#   size_kb         : file size in kilobytes
#   suspicious_name : 1 if filename contains suspicious keywords
#   has_double_ext  : 1 if file has double extension (e.g. photo.jpg.exe)
#   transfer_freq   : simulated transfer frequency score (0-5)
#
# Label:
#   label           : 0 = SAFE, 1 = SUSPICIOUS
# ──────────────────────────────────────────────────────────────────────────────

data = [
    # ext_risk, size_kb, suspicious_name, has_double_ext, transfer_freq, label
    # --- SAFE files ---
    (0, 120,   0, 0, 1, 0),   # report.pdf
    (0, 340,   0, 0, 1, 0),   # image.jpg
    (0, 80,    0, 0, 2, 0),   # notes.txt
    (0, 1200,  0, 0, 1, 0),   # presentation.docx
    (0, 500,   0, 0, 2, 0),   # photo.png
    (0, 2500,  0, 0, 1, 0),   # spreadsheet.xlsx
    (0, 90,    0, 0, 1, 0),   # readme.md
    (0, 400,   0, 0, 3, 0),   # diagram.png
    (0, 150,   0, 0, 2, 0),   # letter.pdf
    (0, 600,   0, 0, 1, 0),   # data.csv
    (0, 700,   0, 0, 2, 0),   # summary.docx
    (0, 220,   0, 0, 1, 0),   # avatar.jpg
    (0, 180,   0, 0, 2, 0),   # logo.png
    (0, 3000,  0, 0, 1, 0),   # thesis.pdf  (large but safe)
    (0, 800,   0, 0, 1, 0),   # slides.pptx
    (1, 5000,  0, 0, 2, 0),   # archive.zip (medium risk extension, not suspicious name)
    (1, 2000,  0, 0, 1, 0),   # backup.rar

    # --- SUSPICIOUS files ---
    (2, 0,     0, 0, 1, 1),   # empty.exe (0-byte high risk should be suspicious)
    (2, 1,     1, 0, 5, 1),   # hack.bat
    (2, 1500,  0, 0, 5, 1),   # setup.exe
    (2, 800,   0, 0, 4, 1),   # install.bat
    (2, 300,   1, 0, 5, 1),   # hack_tool.bat
    (2, 200,   1, 0, 5, 1),   # virus_payload.exe
    (2, 1200,  1, 0, 4, 1),   # malware_dropper.exe
    (0, 900,   0, 1, 4, 1),   # photo.jpg.exe  (double extension)
    (2, 400,   0, 0, 5, 1),   # script.ps1
    (2, 100,   1, 0, 5, 1),   # keylogger.vbs
    (2, 600,   1, 0, 4, 1),   # crack_tool.sh
    (1, 50000, 0, 0, 5, 1),   # huge_archive.zip (abnormally large + high freq)
    (2, 250,   1, 0, 5, 1),   # trojan_downloader.exe
    (2, 180,   1, 0, 3, 1),   # exploit_kit.bat
    (0, 350,   1, 1, 4, 1),   # document.pdf.exe (double ext + suspicious)
    (2, 450,   0, 0, 4, 1),   # run.sh
    (1, 75000, 0, 0, 5, 1),   # dump.zip (very large zip, high freq)
    (2, 520,   1, 0, 5, 1),   # ransomware_test.exe
]

columns = ["ext_risk", "size_kb", "suspicious_name", "has_double_ext", "transfer_freq", "label"]
df = pd.DataFrame(data, columns=columns)

X = df.drop("label", axis=1)
y = df["label"]

# ─── Train / Test Split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ─── Model Training ────────────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=5,
    random_state=42
)
model.fit(X_train, y_train)

# ─── Evaluation ───────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print("=" * 50)
print("  AI Model Training Complete")
print("=" * 50)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred) * 100:.1f}%\n")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["SAFE", "SUSPICIOUS"]))

# Feature importances (great for viva explanation)
print("\nFeature Importances:")
for feat, imp in sorted(zip(columns[:-1], model.feature_importances_), key=lambda x: -x[1]):
    bar = "#" * int(imp * 40)
    print(f"  {feat:<20} {bar} {imp:.3f}")

# ─── Save Model ───────────────────────────────────────────────────────────────
model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(model, f)

print(f"\n[OK] Model saved to: {model_path}")
