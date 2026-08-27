import pandas as pd
import numpy as np
import random
import os

SEED_PATH = os.path.join(os.path.dirname(__file__), "..", "artifacts", "simulation_seed.csv")
_seed_df = pd.read_csv(SEED_PATH)

NUMERIC_JITTER_COLS = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]


def _rand_ip(private=True):
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_dest():
    return f"10.0.0.{random.randint(1,254)}"


def generate_event():
    """Pull a real NSL-KDD row (any label) and jitter a few numeric fields
    so repeated draws don't look identical, then attach fake IPs/timestamp.
    The label columns are dropped — the model scores it blind, like real traffic."""
    row = _seed_df.sample(n=1).iloc[0].to_dict()
    true_category = row.pop("attack_category", "Unknown")
    row.pop("binary_label", None)
    row.pop("label", None)

    for col in NUMERIC_JITTER_COLS:
        if col in row and isinstance(row[col], (int, float)) and row[col] > 0:
            jitter = np.random.uniform(0.85, 1.15)
            row[col] = max(0, row[col] * jitter)

    row["_source_ip"] = _rand_ip()
    row["_dest_ip"] = _rand_dest()
    row["_true_category"] = true_category  # for demo/debug only, not used by the model
    return row
