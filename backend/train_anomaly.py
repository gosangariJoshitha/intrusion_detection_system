import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

def main():
    print("Loading simulation seed for anomaly training...")
    seed_path = os.path.join(ARTIFACTS_DIR, "simulation_seed.csv")
    if not os.path.exists(seed_path):
        print("simulation_seed.csv not found! Run train_artifacts.py first.")
        return

    df = pd.read_csv(seed_path)
    
    # We ideally train the anomaly detector only on Normal traffic, or the entire dataset 
    # to find the most outlying outliers. We'll use the entire dataset and assume 
    # attacks are outliers, but let's see. Using only normal is common for semi-supervised.
    # We will use all traffic so it learns the "common" behaviors and flags highly unusual ones.
    
    # Preprocessing
    CATEGORICAL_COLS = joblib.load(os.path.join(ARTIFACTS_DIR, "categorical_cols.pkl"))
    numeric_cols = joblib.load(os.path.join(ARTIFACTS_DIR, "numeric_cols.pkl"))
    feature_columns = joblib.load(os.path.join(ARTIFACTS_DIR, "feature_columns.pkl"))
    scaler = joblib.load(os.path.join(ARTIFACTS_DIR, "scaler.pkl"))
    
    drop_cols = ['label', 'difficulty', 'attack_category', 'binary_label']
    drop_cols = [c for c in drop_cols if c in df.columns]
    
    X_raw = df.drop(columns=drop_cols)
    X_enc = pd.get_dummies(X_raw, columns=CATEGORICAL_COLS)
    X_enc = X_enc.reindex(columns=feature_columns, fill_value=0)
    X_enc[numeric_cols] = scaler.transform(X_enc[numeric_cols])
    
    print("Training IsolationForest...")
    # contamination 'auto' allows the model to determine the outlier threshold
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    iso_forest.fit(X_enc.values)
    
    joblib.dump(iso_forest, os.path.join(ARTIFACTS_DIR, "iso_forest.pkl"))
    print("Anomaly Detection model saved to artifacts/iso_forest.pkl")

if __name__ == "__main__":
    main()
