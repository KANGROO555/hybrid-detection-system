import pandas as pd
import numpy as np
import glob
import joblib
import warnings
warnings.filterwarnings('ignore')

print("[*] Building combined dataset from 3 sources...")

# ── NFStream feature names (target space) ────────────────────
FEATURES = [
    'src_port', 'dst_port', 'protocol',
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
    'bidirectional_min_ps', 'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_max_ps',
    'src2dst_min_ps', 'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps',
    'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps', 'dst2src_max_ps',
    'bidirectional_min_piat_ms', 'bidirectional_mean_piat_ms',
    'bidirectional_stddev_piat_ms', 'bidirectional_max_piat_ms',
    'src2dst_min_piat_ms', 'src2dst_mean_piat_ms',
    'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms',
    'dst2src_min_piat_ms', 'dst2src_mean_piat_ms',
    'dst2src_stddev_piat_ms', 'dst2src_max_piat_ms',
    'bidirectional_syn_packets', 'bidirectional_cwr_packets',
    'bidirectional_ece_packets', 'bidirectional_urg_packets',
    'bidirectional_ack_packets', 'bidirectional_psh_packets',
    'bidirectional_rst_packets', 'bidirectional_fin_packets',
    'src2dst_syn_packets', 'src2dst_ack_packets', 'src2dst_psh_packets',
    'src2dst_rst_packets', 'src2dst_fin_packets',
    'dst2src_syn_packets', 'dst2src_ack_packets', 'dst2src_psh_packets',
    'dst2src_rst_packets', 'dst2src_fin_packets',
    'application_is_guessed', 'application_confidence',
    'ip_version', 'vlan_id', 'tunnel_id',
]

# ── 1. Load custom NFStream dataset ──────────────────────────
print("\n[*] Loading custom NFStream dataset...")
drop_cols = ['id', 'expiration_id', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac',
             'src_oui', 'dst_oui', 'application_name', 'application_category_name',
             'requested_server_name', 'client_fingerprint', 'server_fingerprint',
             'user_agent', 'content_type', 'bidirectional_first_seen_ms',
             'bidirectional_last_seen_ms', 'src2dst_first_seen_ms',
             'src2dst_last_seen_ms', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms']

benign  = pd.read_csv('benign_flows.csv')
attacks = pd.read_csv('attack_flows.csv')
custom  = pd.concat([benign, attacks], ignore_index=True)
custom  = custom.drop(columns=[c for c in drop_cols if c in custom.columns])
custom_X = custom.select_dtypes(include=[np.number]).drop(columns=['label'], errors='ignore')
custom_y = custom['label'].astype(int)

# Align to feature space
for col in FEATURES:
    if col not in custom_X.columns:
        custom_X[col] = 0
custom_X = custom_X[FEATURES]

print(f"[+] Custom dataset: {len(custom_X)} rows")

# ── 2. Load and map CICIDS2017 ────────────────────────────────
print("\n[*] Loading CICIDS2017...")
files = glob.glob('archive/*.csv')
dfs = []
for f in files:
    chunk = pd.read_csv(f, low_memory=False, nrows=50000)
    dfs.append(chunk)

cic = pd.concat(dfs, ignore_index=True)
cic.columns = cic.columns.str.strip()
cic.replace([np.inf, -np.inf], np.nan, inplace=True)
cic.dropna(subset=['Label'], inplace=True)

cic_y = (cic['Label'].str.strip() != 'BENIGN').astype(int)

cic_X = pd.DataFrame()
cic_X['dst_port']                    = cic.get('Destination Port', 0)
cic_X['bidirectional_duration_ms']   = cic.get('Flow Duration', 0)
cic_X['bidirectional_packets']       = cic.get('Total Fwd Packets', 0) + cic.get('Total Backward Packets', 0)
cic_X['bidirectional_bytes']         = cic.get('Total Length of Fwd Packets', 0) + cic.get('Total Length of Bwd Packets', 0)
cic_X['src2dst_packets']             = cic.get('Total Fwd Packets', 0)
cic_X['src2dst_bytes']               = cic.get('Total Length of Fwd Packets', 0)
cic_X['dst2src_packets']             = cic.get('Total Backward Packets', 0)
cic_X['dst2src_bytes']               = cic.get('Total Length of Bwd Packets', 0)
cic_X['src2dst_mean_ps']             = cic.get('Avg Fwd Segment Size', 0)
cic_X['dst2src_mean_ps']             = cic.get('Avg Bwd Segment Size', 0)
cic_X['bidirectional_min_ps']        = cic.get('Min Packet Length', 0)
cic_X['bidirectional_max_ps']        = cic.get('Max Packet Length', 0)
cic_X['bidirectional_mean_ps']       = cic.get('Packet Length Mean', 0)
cic_X['bidirectional_stddev_ps']     = cic.get('Packet Length Std', 0)
cic_X['bidirectional_mean_piat_ms']  = cic.get('Flow IAT Mean', 0)
cic_X['bidirectional_stddev_piat_ms']= cic.get('Flow IAT Std', 0)
cic_X['bidirectional_max_piat_ms']   = cic.get('Flow IAT Max', 0)
cic_X['bidirectional_min_piat_ms']   = cic.get('Flow IAT Min', 0)
cic_X['src2dst_min_piat_ms']         = cic.get('Fwd IAT Min', 0)
cic_X['src2dst_max_piat_ms']         = cic.get('Fwd IAT Max', 0)
cic_X['src2dst_mean_piat_ms']        = cic.get('Fwd IAT Mean', 0)
cic_X['src2dst_stddev_piat_ms']      = cic.get('Fwd IAT Std', 0)
cic_X['dst2src_min_piat_ms']         = cic.get('Bwd IAT Min', 0)
cic_X['dst2src_max_piat_ms']         = cic.get('Bwd IAT Max', 0)
cic_X['dst2src_mean_piat_ms']        = cic.get('Bwd IAT Mean', 0)
cic_X['dst2src_stddev_piat_ms']      = cic.get('Bwd IAT Std', 0)
cic_X['bidirectional_syn_packets']   = cic.get('SYN Flag Count', 0)
cic_X['bidirectional_fin_packets']   = cic.get('FIN Flag Count', 0)
cic_X['bidirectional_rst_packets']   = cic.get('RST Flag Count', 0)
cic_X['bidirectional_ack_packets']   = cic.get('ACK Flag Count', 0)
cic_X['bidirectional_psh_packets']   = cic.get('PSH Flag Count', 0)
cic_X['bidirectional_urg_packets']   = cic.get('URG Flag Count', 0)
cic_X['bidirectional_cwr_packets']   = cic.get('CWE Flag Count', 0)
cic_X['bidirectional_ece_packets']   = cic.get('ECE Flag Count', 0)

# Fill missing features with 0
for col in FEATURES:
    if col not in cic_X.columns:
        cic_X[col] = 0
cic_X = cic_X[FEATURES]
cic_X = cic_X.fillna(0).replace([np.inf, -np.inf], 0)

print(f"[+] CICIDS2017: {len(cic_X)} rows")

# ── 3. Load and map UNSW-NB15 ─────────────────────────────────
print("\n[*] Loading UNSW-NB15...")
UNSW_COLS = ['srcip','sport','dstip','dsport','proto','state','dur','sbytes',
             'dbytes','sttl','dttl','sloss','dloss','service','sload','dload',
             'spkts','dpkts','swin','dwin','stcpb','dtcpb','smeansz','dmeansz',
             'trans_depth','res_bdy_len','sjit','djit','stime','ltime','sintpkt',
             'dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports','ct_state_ttl',
             'ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd','ct_srv_src',
             'ct_srv_dst','ct_dst_ltm','ct_src_ltm','ct_src_dport_ltm',
             'ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label']

unsw = pd.read_csv('UNSW-NB15_1.csv', header=None, names=UNSW_COLS,
                   low_memory=False)
unsw['attack_cat'] = unsw['attack_cat'].fillna('Normal')
unsw.replace([np.inf, -np.inf], np.nan, inplace=True)
unsw_y = unsw['label'].astype(int)

unsw_X = pd.DataFrame()
unsw_X['src_port']                   = pd.to_numeric(unsw['sport'], errors='coerce').fillna(0)
unsw_X['dst_port']                   = pd.to_numeric(unsw['dsport'], errors='coerce').fillna(0)
unsw_X['bidirectional_duration_ms']  = unsw['dur'] * 1000
unsw_X['src2dst_packets']            = unsw['spkts']
unsw_X['dst2src_packets']            = unsw['dpkts']
unsw_X['bidirectional_packets']      = unsw['spkts'] + unsw['dpkts']
unsw_X['src2dst_bytes']              = unsw['sbytes']
unsw_X['dst2src_bytes']              = unsw['dbytes']
unsw_X['bidirectional_bytes']        = unsw['sbytes'] + unsw['dbytes']
unsw_X['src2dst_mean_ps']            = unsw['smeansz']
unsw_X['dst2src_mean_ps']            = unsw['dmeansz']
unsw_X['bidirectional_mean_ps']      = (unsw['smeansz'] + unsw['dmeansz']) / 2
unsw_X['bidirectional_mean_piat_ms'] = unsw['sintpkt']
unsw_X['dst2src_mean_piat_ms']       = unsw['dintpkt']
unsw_X['src2dst_stddev_piat_ms']     = unsw['sjit']
unsw_X['dst2src_stddev_piat_ms']     = unsw['djit']

# Fill missing features with 0
for col in FEATURES:
    if col not in unsw_X.columns:
        unsw_X[col] = 0
unsw_X = unsw_X[FEATURES]
unsw_X = unsw_X.fillna(0).replace([np.inf, -np.inf], 0)

print(f"[+] UNSW-NB15: {len(unsw_X)} rows")

# ── 4. Combine all datasets ───────────────────────────────────
print("\n[*] Combining datasets...")
X = pd.concat([custom_X, cic_X, unsw_X], ignore_index=True)
y = pd.concat([custom_y, cic_y, unsw_y], ignore_index=True).astype(int)

X = X.fillna(0).replace([np.inf, -np.inf], 0)

print(f"[+] Total records : {len(X)}")
print(f"[+] Label distribution: {y.value_counts().to_dict()}")

# ── 5. Balance ────────────────────────────────────────────────
benign_idx  = y[y == 0].index
attack_idx  = y[y == 1].index
n = min(len(benign_idx), len(attack_idx))
print(f"[+] Balancing to {n} samples per class ({n*2} total)")

b_sample = np.random.choice(benign_idx,  n, replace=False)
a_sample = np.random.choice(attack_idx,  n, replace=False)
idx = np.concatenate([b_sample, a_sample])
np.random.shuffle(idx)

X = X.loc[idx].reset_index(drop=True)
y = y.loc[idx].reset_index(drop=True)

print(f"[+] Balanced: {y.value_counts().to_dict()}")

# ── 6. Save combined dataset ──────────────────────────────────
joblib.dump((X, y), 'combined_dataset.pkl')
joblib.dump(FEATURES, 'feature_names_combined.pkl')
print(f"\n[+] Saved combined_dataset.pkl")
print(f"[+] Features: {len(FEATURES)}")

