import json
import random
import warnings
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

warnings.filterwarnings("ignore")
random.seed(42)

BASE_DIR = Path(__file__).resolve().parent
STREAM_PATH = BASE_DIR / "sample_stream_full_1000.json"


class ThreatCorrelationEngine:
    """
    Rule-based threat matrix for independent ML scores.
    It deliberately does not average scores because cross-domain overlap
    is more meaningful than a blended risk number.
    """

    def correlate(self, fraud_score=0.0, cyber_score=0.0, quantum_score=0.0):
        s_f = float(fraud_score or 0)
        s_c = float(cyber_score or 0)
        s_q = float(quantum_score or 0)

        high = lambda score: score >= 70.0
        mid = lambda score: 30.0 <= score < 70.0

        if high(s_f) and high(s_c):
            return 4, "MULTI_DOMAIN_CORRELATED_ATTACK"
        if high(s_q) and high(s_c):
            return 4, "QUANTUM_HARVEST_CONFIRMED"
        if high(s_q) and high(s_f):
            return 4, "FINANCIAL_QUANTUM_THREAT"

        if high(s_q):
            return 3, "QUANTUM_EXFIL_SUSPECTED"

        if high(s_f):
            return 2, "FRAUD_ONLY_ANOMALY"
        if high(s_c):
            return 2, "CYBER_ONLY_ANOMALY"
        if sum([mid(s_f), mid(s_c), mid(s_q)]) >= 2:
            return 2, "MULTIPLE_MILD_SIGNALS"

        if mid(s_f) or mid(s_c) or mid(s_q):
            return 1, "LOW_RISK_WATCH"

        return 0, "NORMAL"

    def correlate_vector(self, scores_vector):
        return self.correlate(
            fraud_score=scores_vector.get("fraud_score", 0),
            cyber_score=scores_vector.get("cyber_score", 0),
            quantum_score=scores_vector.get("quantum_score", 0),
        )


@dataclass
class ModelBundle:
    fraud_model: object
    fraud_features: list
    fraud_types: list
    fraud_cat_maps: dict
    cyber_model: object
    cyber_features: list
    cyber_types: list
    cyber_benign_idx: int
    quantum_model: object
    quantum_score_min: float
    quantum_score_max: float
    quantum_features: list


def _feature_types_or_numeric(feature_types, feature_names):
    if not feature_types:
        return ["q"] * len(feature_names)
    return list(feature_types)


def strict_cast(row, feature_names, feature_types, cat_maps=None):
    cat_maps = cat_maps or {}
    feature_types = _feature_types_or_numeric(feature_types, feature_names)
    out = row.reindex(columns=feature_names).copy()

    for col, ftype in zip(feature_names, feature_types):
        if ftype == "c":
            known_categories = cat_maps.get(col) or ["missing"]
            out[col] = pd.Categorical(
                out[col].fillna("missing").astype(str),
                categories=known_categories,
            )
        else:
            out[col] = pd.to_numeric(out[col], errors="coerce")

    return out


def quantum_cast(row, quantum_features):
    return (
        row.reindex(columns=quantum_features)
        .apply(pd.to_numeric, errors="coerce")
        .fillna(0)
    )


def load_models(base_dir=BASE_DIR):
    base_dir = Path(base_dir)

    fraud_model = xgb.XGBClassifier()
    fraud_model.load_model(base_dir / "xgboost_fraud_model.json")
    fraud_booster = fraud_model.get_booster()
    fraud_features = list(fraud_booster.feature_names)
    fraud_types = _feature_types_or_numeric(fraud_booster.feature_types, fraud_features)
    fraud_cat_maps = joblib.load(base_dir / "fraud_category_maps.joblib")

    cyber_model = joblib.load(base_dir / "cyber_xgboost_model.joblib")
    cyber_features = list(joblib.load(base_dir / "cyber_feature_columns.joblib"))
    cyber_types = _feature_types_or_numeric(
        cyber_model.get_booster().feature_types,
        cyber_features,
    )
    cyber_label_encoder = joblib.load(base_dir / "cyber_label_encoder.joblib")
    cyber_benign_idx = list(cyber_label_encoder.classes_).index("BENIGN")

    quantum_payload = joblib.load(base_dir / "quantum_risk_engine.joblib")

    return ModelBundle(
        fraud_model=fraud_model,
        fraud_features=fraud_features,
        fraud_types=fraud_types,
        fraud_cat_maps=fraud_cat_maps,
        cyber_model=cyber_model,
        cyber_features=cyber_features,
        cyber_types=cyber_types,
        cyber_benign_idx=cyber_benign_idx,
        quantum_model=quantum_payload["model"],
        quantum_score_min=quantum_payload["score_min"],
        quantum_score_max=quantum_payload["score_max"],
        quantum_features=list(quantum_payload["features"]),
    )


def score_models(event, models):
    row = pd.DataFrame([event])

    fraud_df = strict_cast(
        row,
        models.fraud_features,
        models.fraud_types,
        cat_maps=models.fraud_cat_maps,
    )
    fraud_score = float(models.fraud_model.predict_proba(fraud_df)[:, 1][0]) * 100

    cyber_df = strict_cast(row, models.cyber_features, models.cyber_types)
    if hasattr(models.cyber_model, "predict_proba"):
        cyber_probs = models.cyber_model.predict_proba(cyber_df)[0]
        cyber_score = float(1 - cyber_probs[models.cyber_benign_idx]) * 100
    else:
        cyber_score = 0.0

    quantum_df = quantum_cast(row, models.quantum_features)
    raw_quantum_score = models.quantum_model.decision_function(quantum_df)[0]
    quantum_range = models.quantum_score_max - models.quantum_score_min
    if quantum_range == 0:
        quantum_score = 0.0
    else:
        quantum_score = 100 - (
            (raw_quantum_score - models.quantum_score_min) / quantum_range * 100
        )
    quantum_score = float(np.clip(quantum_score, 0, 100))

    return {
        "fraud_score": round(fraud_score, 2),
        "cyber_score": round(cyber_score, 2),
        "quantum_score": round(quantum_score, 2),
    }


def score_and_correlate(event, models, engine=None):
    engine = engine or ThreatCorrelationEngine()
    scores = score_models(event, models)
    tier, tag = engine.correlate(
        scores["fraud_score"],
        scores["cyber_score"],
        scores["quantum_score"],
    )
    return {
        **scores,
        "Threat_Tier": tier,
        "Context_Tag": tag,
    }


def load_stream(path=STREAM_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
