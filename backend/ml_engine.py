import hashlib
import math
import os
from collections import Counter
from typing import Dict, List

import joblib
import numpy as np
import pefile
from sklearn.ensemble import RandomForestClassifier

from core.config import settings

FEATURE_NAMES: List[str] = [
    "file_size",
    "num_sections",
    "entry_point",
    "image_base",
    "mean_entropy",
    "max_entropy",
    "min_entropy",
    "has_debug",
    "has_relocs",
    "has_tls",
    "num_imports",
    "num_exports",
    "has_resources",
    "has_rich_header",
    "has_signature",
]


def verify_sha256(file_path: str, expected_hash: str) -> bool:
    if not expected_hash:
        return True
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest() == expected_hash


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def extract_pe_features(file_path: str) -> Dict[str, float]:
    features: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}

    try:
        pe = pefile.PE(file_path, fast_load=True)
    except Exception:
        return features

    features["file_size"] = float(os.path.getsize(file_path))
    features["num_sections"] = float(pe.FILE_HEADER.NumberOfSections)
    features["entry_point"] = float(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    features["image_base"] = float(pe.OPTIONAL_HEADER.ImageBase)

    entropies: List[float] = []
    for section in pe.sections:
        entropies.append(shannon_entropy(section.get_data()))

    if entropies:
        features["mean_entropy"] = sum(entropies) / len(entropies)
        features["max_entropy"] = max(entropies)
        features["min_entropy"] = min(entropies)

    features["has_debug"] = 1.0 if hasattr(pe, "DEBUG_DIRECTORY") and pe.DEBUG_DIRECTORY else 0.0
    features["has_relocs"] = 1.0 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0 else 0.0
    features["has_tls"] = 1.0 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size > 0 else 0.0
    features["has_resources"] = 1.0 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size > 0 else 0.0
    features["has_rich_header"] = 1.0 if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER else 0.0
    features["has_signature"] = 1.0 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0 else 0.0

    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
    except Exception:
        pass

    features["num_imports"] = float(len(pe.DIRECTORY_ENTRY_IMPORT)) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0.0
    features["num_exports"] = float(len(pe.DIRECTORY_ENTRY_EXPORT.symbols)) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0.0

    return features


def load_model():
    model_path = settings.MODEL_PATH
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")

    if not verify_sha256(model_path, settings.MODEL_EXPECTED_HASH):
        raise RuntimeError("Model file SHA256 verification failed")

    return joblib.load(model_path)


try:
    _model = load_model()
except Exception as exc:
    raise RuntimeError(f"Failed to load model: {exc}") from exc


def predict_file(file_path: str) -> Dict:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        header = f.read(2)

    if header != b"MZ":
        return {
            "prediction": 0,
            "probability": 0.0,
            "features": {name: 0.0 for name in FEATURE_NAMES},
            "analysis_pending": True,
        }

    features = extract_pe_features(file_path)
    feature_vector = np.array([features[name] for name in FEATURE_NAMES]).reshape(1, -1)

    try:
        proba = _model.predict_proba(feature_vector)[0]
        prediction = int(_model.predict(feature_vector)[0])
    except Exception as exc:
        raise RuntimeError(f"Model inference failed: {exc}") from exc

    return {
        "prediction": prediction,
        "probability": float(proba[prediction]),
        "features": features,
        "analysis_pending": False,
    }
