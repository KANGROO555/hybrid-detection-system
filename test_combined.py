import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

print("[*] Loading combined model...")
model         = joblib.load('best_model_combined.pkl')
feature_names = joblib.load('feature_names_combined.pkl')

def evaluate(name, X, y):
    X = X.fillna(0).replace([np.inf, -np.inf], 0)
    for col in feature_names:
        if col not in X.columns:
            X[col] = 0
    X = X[feature_names]
    y_pred = model.predict(X)
    acc  = accuracy_score(y, y_pred)
    cm   = confusion_matrix(y, y_pred)
    print(f"\n=== {name} ===")
    print(f"Samples  : {len(X)}")
    print(f"Accuracy : {acc:.4f}")
    print(f"TN: {cm[0][0]}  FP: {cm[0][1]}")
    print(f"FN: {cm[1][0]}  TP: {cm[1][1]}")
    print(classification_report(y, y_pred,
          target_names=['BENIGN', 'ATTACK'], digits=4))

# ── Test 1: Unseen CICIDS2017 rows (skip first 50000 per file) ─
print("\n[*] Loading unseen CICIDS2017 data...")
import glob
dfs = []
for f in glob.glob('archive/*.csv'):
    chunk = pd.read_csv(f, low_memory=False, skiprows=range(1, 50001), nrows=50000)
    dfs.append(chunk)

cic = pd.concat(dfs, ignore_index=True)
cic.columns = cic.columns.str.strip()
cic.replace([np.inf, -np.inf], np.nan, inplace=True)
cic_y = (cic['Label'].str.strip() != 'BENIGN').astype(int)

cic_X = pd.DataFrame()
cic_X['dst_port']                     = cic.get('Destination Port', 0)
cic_X['bidirectional_duration_ms']    = cic.get('Flow Duration', 0)
cic_X['bidirectional_packets']        = cic.get('Total Fwd Packets', 0) + cic.get('Total Backward Packets', 0)
cic_X['bidirectional_bytes']          = cic.get('Total Length of Fwd Packets', 0) + cic.get('Total Length of Bwd Packets', 0)
cic_X['src2dst_packets']              = cic.get('Total Fwd Packets', 0)
cic_X['src2dst_bytes']                = cic.get('Total Length of Fwd Packets', 0)
cic_X['dst2src_packets']              = cic.get('Total Backward Packets', 0)
cic_X['dst2src_bytes']                = cic.get('Total Length of Bwd Packets', 0)
cic_X['src2dst_mean_ps']              = cic.get('Avg Fwd Segment Size', 0)
cic_X['dst2src_mean_ps']              = cic.get('Avg Bwd Segment Size', 0)
cic_X['bidirectional_min_ps']         = cic.get('Min Packet Length', 0)
cic_X['bidirectional_max_ps']         = cic.get('Max Packet Length', 0)
cic_X['bidirectional_mean_ps']        = cic.get('Packet Length Mean', 0)
cic_X['bidirectional_stddev_ps']      = cic.get('Packet Length Std', 0)
cic_X['bidirectional_mean_piat_ms']   = cic.get('Flow IAT Mean', 0)
cic_X['bidirectional_stddev_piat_ms'] = cic.get('Flow IAT Std', 0)
cic_X['bidirectional_max_piat_ms']    = cic.get('Flow IAT Max', 0)
cic_X['bidirectional_min_piat_ms']    = cic.get('Flow IAT Min', 0)
cic_X['src2dst_min_piat_ms']          = cic.get('Fwd IAT Min', 0)
cic_X['src2dst_max_piat_ms']          = cic.get('Fwd IAT Max', 0)
cic_X['src2dst_mean_piat_ms']         = cic.get('Fwd IAT Mean', 0)
cic_X['src2dst_stddev_piat_ms']       = cic.get('Fwd IAT Std', 0)
cic_X['dst2src_min_piat_ms']          = cic.get('Bwd IAT Min', 0)
cic_X['dst2src_max_piat_ms']          = cic.get('Bwd IAT Max', 0)
cic_X['dst2src_mean_piat_ms']         = cic.get('Bwd IAT Mean', 0)
cic_X['dst2src_stddev_piat_ms']       = cic.get('Bwd IAT Std', 0)
cic_X['bidirectional_syn_packets']    = cic.get('SYN Flag Count', 0)
cic_X['bidirectional_fin_packets']    = cic.get('FIN Flag Count', 0)
cic_X['bidirectional_rst_packets']    = cic.get('RST Flag Count', 0)
cic_X['bidirectional_ack_packets']    = cic.get('ACK Flag Count', 0)
cic_X['bidirectional_psh_packets']    = cic.get('PSH Flag Count', 0)
cic_X['bidirectional_urg_packets']    = cic.get('URG Flag Count', 0)
cic_X['bidirectional_cwr_packets']    = cic.get('CWE Flag Count', 0)
cic_X['bidirectional_ece_packets']    = cic.get('ECE Flag Count', 0)

cic_X = cic_X.fillna(0).replace([np.inf, -np.inf], 0)
# Sample for speed
idx = np.random.choice(len(cic_X), min(20000, len(cic_X)), replace=False)
evaluate("CICIDS2017 (unseen rows)", cic_X.iloc[idx], cic_y.iloc[idx])

# ── Test 2: Custom NFStream live captures ──────────────────────
print("\n[*] Loading custom NFStream captures...")
benign  = pd.read_csv('benign_flows.csv')
attacks = pd.read_csv('attack_flows.csv')
custom  = pd.concat([benign, attacks], ignore_index=True)

drop_cols = ['id','expiration_id','src_ip','dst_ip','src_mac','dst_mac',
             'src_oui','dst_oui','application_name','application_category_name',
             'requested_server_name','client_fingerprint','server_fingerprint',
             'user_agent','content_type','bidirectional_first_seen_ms',
             'bidirectional_last_seen_ms','src2dst_first_seen_ms',
             'src2dst_last_seen_ms','dst2src_first_seen_ms','dst2src_last_seen_ms']
custom_y = custom['label'].astype(int)
custom_X = custom.drop(columns=[c for c in drop_cols + ['label'] if c in custom.columns])
custom_X = custom_X.select_dtypes(include=[np.number])

evaluate("Custom NFStream captures", custom_X, custom_y)

print("\n[*] Done.")
