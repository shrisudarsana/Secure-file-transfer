"""
AI Detector Module
==================
Provides file threat detection using a pre-trained Random Forest model.

Usage:
    from ai_module.detector import predict
    result = predict("photo.jpg.exe", 1500 * 1024)
    # → {"label": "SUSPICIOUS", "confidence": 0.92, "reason": "...", "features": {...}}
"""

import os
import pickle
import random

# ─── Constants ────────────────────────────────────────────────────────────────

SAFE_EXTENSIONS = {
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".docx",
    ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".csv", ".md", ".mp4",
    ".mp3", ".avi", ".mkv", ".svg", ".json", ".xml", ".html", ".css"
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".dmg", ".pkg"
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".bat", ".sh", ".ps1", ".vbs", ".js", ".msi", ".cmd",
    ".com", ".scr", ".pif", ".application", ".gadget", ".hta",
    ".cpl", ".msc", ".jar", ".wsf"
}

SUSPICIOUS_KEYWORDS = {
    "hack", "crack", "virus", "malware", "trojan", "exploit",
    "payload", "keylog", "ransomware", "spyware", "rootkit",
    "backdoor", "inject", "dump", "bypass", "stealer", "worm",
    "botnet", "ddos", "phish"
}

LARGE_FILE_THRESHOLD_KB = 30_000   # 30 MB — anything above is flagged as high freq


# ─── Lazy-load model ──────────────────────────────────────────────────────────
_model = None

def _load_model():
    global _model
    if _model is None:
        model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                "model.pkl not found. Run: python ai_module/train_model.py"
            )
        with open(model_path, "rb") as f:
            _model = pickle.load(f)
    return _model


# ─── Feature Extraction ───────────────────────────────────────────────────────

def extract_features(filename: str, file_size_bytes: int) -> dict:
    """
    Extract numeric features from a filename and file size.

    Returns a dict with keys matching the training dataset columns.
    """
    name_lower = filename.lower()
    # Split name and extension(s)
    parts = name_lower.split(".")
    primary_ext = ("." + parts[-1]) if len(parts) > 1 else ""

    # 1. Extension risk score
    if primary_ext in HIGH_RISK_EXTENSIONS:
        ext_risk = 2
    elif primary_ext in MEDIUM_RISK_EXTENSIONS:
        ext_risk = 1
    else:
        ext_risk = 0

    # 2. File size in KB
    size_kb = file_size_bytes / 1024.0

    # 3. Suspicious keywords in filename (stem only)
    stem = parts[0] if parts else name_lower
    suspicious_name = int(any(kw in name_lower for kw in SUSPICIOUS_KEYWORDS))

    # 4. Double extension check (e.g. photo.jpg.exe)
    has_double_ext = int(
        len(parts) > 2 and
        ("." + parts[-2]) in SAFE_EXTENSIONS and
        ("." + parts[-1]) in HIGH_RISK_EXTENSIONS
    )

    # 5. Transfer frequency score — based on file size as a proxy
    if size_kb > LARGE_FILE_THRESHOLD_KB:
        transfer_freq = 5
    elif size_kb > 10_000:
        transfer_freq = 4
    elif size_kb > 5_000:
        transfer_freq = 3
    elif size_kb > 1_000:
        transfer_freq = 2
    else:
        transfer_freq = 1

    return {
        "ext_risk": ext_risk,
        "size_kb": round(size_kb, 2),
        "suspicious_name": suspicious_name,
        "has_double_ext": has_double_ext,
        "transfer_freq": transfer_freq,
    }


def _build_reason(features: dict, filename: str) -> str:
    """Generate a human-readable reason string for the UI."""
    reasons = []
    if features["ext_risk"] == 2:
        # Robustly get extension even for .exe or path/to/.bat
        ext = os.path.splitext(filename)[1]
        if not ext and filename.startswith('.'):
            ext = filename
        reasons.append(f"High-risk file extension ({ext})")
    elif features["ext_risk"] == 1:
        reasons.append("Medium-risk compressed archive")
    if features["suspicious_name"]:
        reasons.append("Filename contains suspicious keywords")
    if features["has_double_ext"]:
        reasons.append("Double file extension detected (masquerading)")
    if features["transfer_freq"] >= 4:
        reasons.append(f"Abnormally large file ({features['size_kb']:.0f} KB)")
    if not reasons:
        reasons.append("No significant threat indicators found")
    return "; ".join(reasons)


# ─── Prediction ───────────────────────────────────────────────────────────────

def predict(filename: str, file_size_bytes: int) -> dict:
    """
    Run AI threat detection on a file.

    Args:
        filename        : Original filename (e.g. "report.pdf")
        file_size_bytes : File size in bytes

    Returns:
        {
          "label"      : "SAFE" | "SUSPICIOUS",
          "confidence" : float (0.0 – 1.0),
          "reason"     : str,
          "features"   : dict of extracted features
        }
    """
    model = _load_model()
    features = extract_features(filename, file_size_bytes)

    feature_vector = [[
        features["ext_risk"],
        features["size_kb"],
        features["suspicious_name"],
        features["has_double_ext"],
        features["transfer_freq"],
    ]]

    prediction = model.predict(feature_vector)[0]
    proba = model.predict_proba(feature_vector)[0]
    confidence = float(proba[prediction])

    label = "SUSPICIOUS" if prediction == 1 else "SAFE"
    reason = _build_reason(features, filename)

    return {
        "label": label,
        "confidence": round(confidence * 100, 1),
        "reason": reason,
        "features": features,
    }
