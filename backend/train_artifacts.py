"""
One-time training script. Run once to populate ./artifacts/ with a working
model. Uses the same NSL-KDD dataset + preprocessing as the Colab notebook.
Swap these files later with better-trained artifacts exported from the
notebook (same filenames) for higher accuracy — this script exists so the
backend works out of the box without waiting on a Colab run.
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import json

COL_NAMES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

ATTACK_MAP = {
    'normal': 'Normal','back':'DoS','land':'DoS','neptune':'DoS','pod':'DoS','smurf':'DoS','teardrop':'DoS',
    'mailbomb':'DoS','processtable':'DoS','udpstorm':'DoS','apache2':'DoS','worm':'DoS',
    'satan':'Probe','ipsweep':'Probe','nmap':'Probe','portsweep':'Probe','mscan':'Probe','saint':'Probe',
    'guess_passwd':'R2L','ftp_write':'R2L','imap':'R2L','phf':'R2L','multihop':'R2L',
    'warezmaster':'R2L','warezclient':'R2L','spy':'R2L','xlock':'R2L','xsnoop':'R2L',
    'snmpguess':'R2L','snmpgetattack':'R2L','httptunnel':'R2L','sendmail':'R2L','named':'R2L',
    'buffer_overflow':'U2R','loadmodule':'U2R','perl':'U2R','rootkit':'U2R','ps':'U2R','sqlattack':'U2R','xterm':'U2R'
}

CATEGORICAL_COLS = ['protocol_type','service','flag']

def add_targets(df):
    df = df.copy()
    df['attack_category'] = df['label'].map(ATTACK_MAP).fillna('Attack')
    df['binary_label'] = np.where(df['attack_category'] == 'Normal', 'Normal', 'Attack')
    return df

def main():
    train_df = pd.read_csv("/home/claude/test.txt", names=COL_NAMES)
    test_df = pd.read_csv("/home/claude/test2.txt", names=COL_NAMES)
    train_df = add_targets(train_df)
    test_df = add_targets(test_df)

    drop_cols = ['label','difficulty','attack_category','binary_label']
    X_train_raw = train_df.drop(columns=drop_cols)
    numeric_cols = [c for c in X_train_raw.columns if c not in CATEGORICAL_COLS]

    X_train_enc = pd.get_dummies(X_train_raw, columns=CATEGORICAL_COLS)
    feature_columns = list(X_train_enc.columns)

    scaler = StandardScaler()
    X_train_enc[numeric_cols] = scaler.fit_transform(X_train_enc[numeric_cols])

    le_binary = LabelEncoder()
    y_train_bin = le_binary.fit_transform(train_df['binary_label'])

    le_multi = LabelEncoder()
    y_train_multi = le_multi.fit_transform(train_df['attack_category'])

    rf_bin = RandomForestClassifier(n_estimators=150, max_depth=18, random_state=42, n_jobs=-1)
    rf_bin.fit(X_train_enc.values, y_train_bin)

    rf_multi = RandomForestClassifier(n_estimators=150, max_depth=22, random_state=42, n_jobs=-1, class_weight='balanced')
    rf_multi.fit(X_train_enc.values, y_train_multi)

    os.makedirs("artifacts", exist_ok=True)
    joblib.dump(rf_bin, "artifacts/rf_binary_model.pkl")
    joblib.dump(rf_multi, "artifacts/rf_multiclass_model.pkl")
    joblib.dump(scaler, "artifacts/scaler.pkl")
    joblib.dump(le_binary, "artifacts/label_encoder_binary.pkl")
    joblib.dump(le_multi, "artifacts/label_encoder_multiclass.pkl")
    joblib.dump(feature_columns, "artifacts/feature_columns.pkl")
    joblib.dump(numeric_cols, "artifacts/numeric_cols.pkl")
    joblib.dump(CATEGORICAL_COLS, "artifacts/categorical_cols.pkl")

    # quick holdout accuracy check, saved for the README
    X_test_raw = test_df.drop(columns=drop_cols)
    X_test_enc = pd.get_dummies(X_test_raw, columns=CATEGORICAL_COLS)
    X_test_enc = X_test_enc.reindex(columns=feature_columns, fill_value=0)
    X_test_enc[numeric_cols] = scaler.transform(X_test_enc[numeric_cols])
    y_test_bin = le_binary.transform(test_df['binary_label'])
    y_test_multi = le_multi.transform(test_df['attack_category'])
    bin_acc = rf_bin.score(X_test_enc.values, y_test_bin)
    multi_acc = rf_multi.score(X_test_enc.values, y_test_multi)
    print(f"Binary test accuracy: {bin_acc:.4f}")
    print(f"Multiclass test accuracy: {multi_acc:.4f}")

    # Build a simulation seed file: real raw test rows (pre-encoding) for the
    # traffic simulator to sample from, balanced-ish across categories.
    seed_frames = []
    for cat, n in [('Normal', 120), ('DoS', 60), ('Probe', 40), ('R2L', 20), ('U2R', 10)]:
        sub = test_df[test_df['attack_category'] == cat]
        if len(sub) > 0:
            seed_frames.append(sub.sample(n=min(n, len(sub)), random_state=1))
    seed_df = pd.concat(seed_frames).drop(columns=['difficulty']).reset_index(drop=True)
    seed_df.to_csv("artifacts/simulation_seed.csv", index=False)

    with open("artifacts/metrics.json", "w") as f:
        json.dump({"binary_accuracy": bin_acc, "multiclass_accuracy": multi_acc}, f, indent=2)

    print("Artifacts written to ./artifacts/")
    print("Seed rows for simulator:", len(seed_df))

if __name__ == "__main__":
    main()
