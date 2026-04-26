import pandas as pd
import json
import random

# ── 1. Load data & re-run DBSCAN (same as Task 2) ──────────────────────────
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN

df = pd.read_csv('cybersecurity_intrusion_data.csv')

le = LabelEncoder()
df['protocol_type_enc'] = le.fit_transform(df['protocol_type'])
df['encryption_enc']    = le.fit_transform(df['encryption_used'])
df['browser_enc']       = le.fit_transform(df['browser_type'])

features = [
    'network_packet_size', 'login_attempts', 'session_duration',
    'ip_reputation_score', 'failed_logins', 'unusual_time_access',
    'protocol_type_enc', 'encryption_enc'
]

X = df[features].copy()
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

dbscan = DBSCAN(eps=1.2, min_samples=10)
df['dbscan_label'] = dbscan.fit_predict(X_scaled)

# ── 2. Cluster attack rate lookup ───────────────────────────────────────────
attack_rate = (
    df.groupby('dbscan_label')['attack_detected']
    .mean()
    .mul(100)
    .round(1)
    .to_dict()
)

# ── 3. Build SFT samples ────────────────────────────────────────────────────
def make_output(row):
    label    = int(row['dbscan_label'])
    attacked = int(row['attack_detected'])
    rate     = attack_rate.get(label, 0)

    if label == -1:
        cluster_desc = (
            f"This session was flagged as an anomaly (noise) by DBSCAN. "
            f"Sessions in this group have a {rate}% attack rate, "
            f"which is the highest among all clusters."
        )
    else:
        cluster_desc = (
            f"This session belongs to cluster {label}, "
            f"which has an attack rate of {rate}%."
        )

    verdict = "This session is likely malicious." if attacked else "This session appears to be benign."
    return f"{verdict} {cluster_desc}"

records = []
for _, row in df.iterrows():
    inp = (
        f"network_packet_size={int(row['network_packet_size'])}, "
        f"protocol={row['protocol_type']}, "
        f"login_attempts={int(row['login_attempts'])}, "
        f"session_duration={row['session_duration']:.1f}, "
        f"encryption={row['encryption_used']}, "
        f"ip_reputation_score={row['ip_reputation_score']:.3f}, "
        f"failed_logins={int(row['failed_logins'])}, "
        f"unusual_time_access={int(row['unusual_time_access'])}"
    )
    records.append({
        "instruction": "Analyze this network session and determine whether it is an attack based on its features and cluster assignment.",
        "input": inp,
        "output": make_output(row)
    })

# ── 4. Split: data-rich vs data-scarce clusters ─────────────────────────────
cluster_counts = df['dbscan_label'].value_counts()
rich_clusters  = cluster_counts[cluster_counts >= 500].index.tolist()   # clusters 0,1,3,4,6
scarce_clusters = cluster_counts[cluster_counts < 100].index.tolist()   # clusters 9,10,11,12,13

df_rich   = df[df['dbscan_label'].isin(rich_clusters)]
df_scarce = df[df['dbscan_label'].isin(scarce_clusters)]

print(f"Total samples     : {len(records)}")
print(f"Rich clusters     : {rich_clusters}  → {len(df_rich)} samples")
print(f"Scarce clusters   : {scarce_clusters} → {len(df_scarce)} samples")

# ── 5. Save JSON files ───────────────────────────────────────────────────────
def save_json(rows, path):
    with open(path, 'w') as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(rows)} records → {path}")

# Full dataset (for main SFT run)
save_json(records, 'cybersec_sft_full.json')

# Rich-cluster subset
rich_idx = df_rich.index.tolist()
save_json([records[i] for i in rich_idx], 'cybersec_sft_rich.json')

# Scarce-cluster subset
scarce_idx = df_scarce.index.tolist()
save_json([records[i] for i in scarce_idx], 'cybersec_sft_scarce.json')

# ── 6. Preview ───────────────────────────────────────────────────────────────
print("\n── Sample record ──")
print(json.dumps(records[0], indent=2))
