import os
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
import joblib

from sqlalchemy.orm import Session
from app.models import Event
from app.model_utils import reload_models, categorical_cols as CATEGORICAL_COLS, RAW_FEATURE_ORDER

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "artifacts")

def run_retraining_pipeline(db: Session):
    # 1. Fetch newly labeled events from the database
    labeled_events = db.query(Event).filter(Event.analyst_label != None).all()
    if not labeled_events:
        return {"status": "skipped", "message": "No new manually labeled events found"}
    
    new_rows = []
    for event in labeled_events:
        try:
            raw_dict = json.loads(event.raw_features)
            # Ensure it conforms to the feature order
            row = {c: raw_dict.get(c, 0.0) for c in RAW_FEATURE_ORDER}
            row['attack_category'] = event.analyst_label
            row['binary_label'] = 'Normal' if event.analyst_label == 'Normal' else 'Attack'
            new_rows.append(row)
        except Exception:
            pass

    if not new_rows:
        return {"status": "skipped", "message": "Failed to parse features for new events"}

    new_df = pd.DataFrame(new_rows)
    
    # 2. Load the original base dataset (simulation_seed)
    seed_path = os.path.join(ARTIFACTS_DIR, "simulation_seed.csv")
    if os.path.exists(seed_path):
        base_df = pd.read_csv(seed_path)
    else:
        # If seed is missing, we can only train on what we have (not recommended)
        base_df = pd.DataFrame(columns=RAW_FEATURE_ORDER + ['attack_category', 'binary_label'])
        
    # Append the targets if they don't exist in base
    if 'binary_label' not in base_df.columns and 'attack_category' in base_df.columns:
        base_df['binary_label'] = np.where(base_df['attack_category'] == 'Normal', 'Normal', 'Attack')
        
    combined_df = pd.concat([base_df, new_df], ignore_index=True)
    
    drop_cols = ['label', 'difficulty', 'attack_category', 'binary_label']
    drop_cols = [c for c in drop_cols if c in combined_df.columns]
    
    X_raw = combined_df.drop(columns=drop_cols)
    numeric_cols = [c for c in X_raw.columns if c not in CATEGORICAL_COLS]
    
    # Preprocessing
    X_enc = pd.get_dummies(X_raw, columns=CATEGORICAL_COLS)
    feature_columns = list(X_enc.columns)
    
    scaler = StandardScaler()
    X_enc[numeric_cols] = scaler.fit_transform(X_enc[numeric_cols])
    
    le_binary = LabelEncoder()
    y_bin = le_binary.fit_transform(combined_df['binary_label'])
    
    le_multi = LabelEncoder()
    y_multi = le_multi.fit_transform(combined_df['attack_category'])
    
    # Train binary model
    rf_bin = RandomForestClassifier(n_estimators=150, max_depth=18, random_state=42, n_jobs=-1)
    rf_bin.fit(X_enc.values, y_bin)
    
    # Train multiclass model
    rf_multi = RandomForestClassifier(n_estimators=150, max_depth=22, random_state=42, n_jobs=-1, class_weight='balanced')
    rf_multi.fit(X_enc.values, y_multi)
    
    # Train anomaly model
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    iso_forest.fit(X_enc.values)
    
    # Calculate training accuracy (since we appended to test/seed, we'll just check train accuracy)
    bin_acc = rf_bin.score(X_enc.values, y_bin)
    multi_acc = rf_multi.score(X_enc.values, y_multi)
    
    # Save artifacts
    joblib.dump(rf_bin, os.path.join(ARTIFACTS_DIR, "rf_binary_model.pkl"))
    joblib.dump(rf_multi, os.path.join(ARTIFACTS_DIR, "rf_multiclass_model.pkl"))
    joblib.dump(iso_forest, os.path.join(ARTIFACTS_DIR, "iso_forest.pkl"))
    joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, "scaler.pkl"))
    joblib.dump(le_binary, os.path.join(ARTIFACTS_DIR, "label_encoder_binary.pkl"))
    joblib.dump(le_multi, os.path.join(ARTIFACTS_DIR, "label_encoder_multiclass.pkl"))
    joblib.dump(feature_columns, os.path.join(ARTIFACTS_DIR, "feature_columns.pkl"))
    joblib.dump(numeric_cols, os.path.join(ARTIFACTS_DIR, "numeric_cols.pkl"))
    joblib.dump(CATEGORICAL_COLS, os.path.join(ARTIFACTS_DIR, "categorical_cols.pkl"))
    
    metrics_path = os.path.join(ARTIFACTS_DIR, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump({"binary_accuracy": bin_acc, "multiclass_accuracy": multi_acc}, f, indent=2)

    # Hot-reload in memory
    reload_models()
    
    return {
        "status": "success",
        "message": f"Retrained on {len(combined_df)} total events ({len(new_rows)} new)",
        "metrics": {"binary_accuracy": bin_acc, "multiclass_accuracy": multi_acc}
    }
