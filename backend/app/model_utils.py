import joblib
import pandas as pd
import numpy as np
import os

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "artifacts")

def _load(name):
    return joblib.load(os.path.join(ARTIFACTS_DIR, name))

rf_binary = None
rf_multiclass = None
iso_forest = None
scaler = None
le_binary = None
le_multi = None
feature_columns = None
numeric_cols = None
categorical_cols = None

def reload_models():
    global rf_binary, rf_multiclass, iso_forest, scaler, le_binary, le_multi, feature_columns, numeric_cols, categorical_cols
    rf_binary = _load("rf_binary_model.pkl")
    rf_multiclass = _load("rf_multiclass_model.pkl")
    iso_forest = _load("iso_forest.pkl") if os.path.exists(os.path.join(ARTIFACTS_DIR, "iso_forest.pkl")) else None
    scaler = _load("scaler.pkl")
    le_binary = _load("label_encoder_binary.pkl")
    le_multi = _load("label_encoder_multiclass.pkl")
    feature_columns = _load("feature_columns.pkl")
    numeric_cols = _load("numeric_cols.pkl")
    categorical_cols = _load("categorical_cols.pkl")

reload_models()

RAW_FEATURE_ORDER = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
]

# sensible defaults so a caller can send a PARTIAL feature dict (e.g. from a
# simplified live-capture agent) and still get a valid prediction
DEFAULTS = {c: (0.0 if c not in categorical_cols else "other") for c in RAW_FEATURE_ORDER}
DEFAULTS.update({"protocol_type": "tcp", "service": "other", "flag": "SF", "logged_in": 0})


def predict_record(raw_record: dict):
    """raw_record: dict of some/all of RAW_FEATURE_ORDER fields (extra fields ignored).
    Returns binary + multiclass predictions with confidence."""
    row = {**DEFAULTS, **{k: v for k, v in raw_record.items() if k in RAW_FEATURE_ORDER}}
    df = pd.DataFrame([row])[RAW_FEATURE_ORDER]

    enc = pd.get_dummies(df, columns=categorical_cols)
    enc = enc.reindex(columns=feature_columns, fill_value=0)
    enc[numeric_cols] = scaler.transform(enc[numeric_cols])

    X = enc.values
    bin_pred = rf_binary.predict(X)[0]
    bin_proba = rf_binary.predict_proba(X)[0]
    bin_label = le_binary.inverse_transform([bin_pred])[0]
    bin_conf = float(np.max(bin_proba))

    multi_pred = rf_multiclass.predict(X)[0]
    multi_proba = rf_multiclass.predict_proba(X)[0]
    multi_label = le_multi.inverse_transform([multi_pred])[0]
    multi_conf = float(np.max(multi_proba))
    
    anomaly_score = 0.0
    is_anomaly = False
    if iso_forest is not None:
        # decision_function returns > 0 for inliers, < 0 for outliers
        score = iso_forest.decision_function(X)[0]
        # Normalize to 0-100 where higher is more anomalous
        # score is typically roughly between -0.5 and 0.5
        anomaly_score = float(max(0, min(100, (0.2 - score) * 100))) 
        is_anomaly = bool(iso_forest.predict(X)[0] == -1)

    return {
        "binary_label": bin_label,
        "binary_confidence": round(bin_conf * 100, 1),
        "attack_category": multi_label,
        "category_confidence": round(multi_conf * 100, 1),
        "anomaly_score": round(anomaly_score, 1),
        "is_anomaly": is_anomaly
    }
