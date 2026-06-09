# Hybrid Detection System

A real-time network intrusion detection system that combines **Suricata NIDS** (signature-based) with **LightGBM machine learning** (anomaly-based) through an intelligent **Fusion Layer**, enriched with **MITRE ATT&CK** mapping, **Wazuh SIEM** integration, and an **AI analyst agent** powered by Llama 3.2.

> **Senior Project 2 (CCCY 421) — University of Jeddah, Cybersecurity Department, 2026**  
> Supervised by Dr. Naif Alzahrani

---

## Key Results

| Metric | Value |
|---|---|
| Total alerts (full attack session) | 38,516 |
| ML-only detections (Suricata missed) | 9,814 — **72.3%** of attacks |
| Custom model accuracy | **95.30%** (FPR = 0.44%) |
| Benchmark model accuracy | **99.55%** (120,504 samples) |
| AI agent response time | **~5.6 seconds** (GPU) |
| Stealth scan (T0 timing) | Suricata = **0 alerts**, ML = **18 L4 alerts** |

---

## System Architecture

```
Network Traffic (enp0s3 promiscuous mode)
         │
    ┌────┴────┐
    │         │
Suricata    NFStream
  NIDS      (65 features)
    │         │
    └────┬────┘
         │
   Fusion Layer
   (R1–R12 rules)
   L0 → L4 decision
         │
  MITRE ATT&CK
    Mapping
  (3-tier system)
         │
   AI Agent (async)
  Llama 3.2 on GPU
         │
   Wazuh SIEM
  Dashboard + Alerts
         │
   SOC Analyst
```

---

## Features

- **Hybrid detection** — Suricata signatures + ML anomaly detection running in parallel
- **Fusion Layer** — 12 decision rules (R1–R12) combining both detection streams into L0–L4 confidence levels
- **Three-tier MITRE ATT&CK mapping** — ET rule embedded metadata → MITRE DB lookup → port/behavior fallback
- **AI analyst agent** — Llama 3.2 (3B) provides structured incident reports for L3/L4 alerts asynchronously
- **Alert deduplication** — 60-second cooldown per (source IP, attack category) prevents alert storms
- **Behavioral heuristics** — port scan boost (>15 unique ports) and brute force boost (>50 flows to auth port)
- **Wazuh SIEM integration** — enriched JSON alerts with custom decoder and detection rules

---

## Lab Environment

| VM | OS | IP | Role |
|---|---|---|---|
| Kali Linux | Kali 2024 | 10.0.0.5 | Attacker |
| Ubuntu Desktop | Ubuntu 22.04 |   10.0.0.6 | Victim |
| IDS/SIEM VM | Ubuntu Server | 10.0.0.4 | Detection (12GB RAM) |
| Windows Host | Windows 11 | 192.168.1.74 | Ollama GPU inference |

**Network:**VirtualBox NAT Network (10.0.0.0/24), promiscuous mode enabled via VBoxManage

---

## Installation

### Prerequisites

- Ubuntu Server (IDS VM) with at least 8GB RAM
- Python 3.10+
- Suricata 7.x
- Wazuh 4.7.x (bare-metal, NOT Docker)
- Ollama on host machine with `llama3.2:3b` pulled

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/hybrid-detection-system.git
cd hybrid-detection-system
```

### 2. Set up Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Download required files (not included in repo)

```bash
# MITRE ATT&CK database
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# Datasets (for training)
# CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
# UNSW-NB15:  https://research.unsw.edu.au/projects/unsw-nb15-dataset
```

### 4. Train the model (or use pre-trained)

```bash
# Capture custom lab traffic first, then:
python3 train_custom.py

# Or train on combined benchmark datasets:
python3 build_combined_dataset.py
python3 train_combined.py
```

### 5. Install Suricata rules

```bash
sudo cp suricata/local.rules /var/lib/suricata/rules/local.rules

# Add to /etc/suricata/suricata.yaml under rule-files:
#   - local.rules

sudo systemctl restart suricata
```

### 6. Install Wazuh integration

```bash
sudo cp wazuh/hybrid_ids_decoder.xml /var/ossec/etc/decoders/
sudo cp wazuh/hybrid_ids_rules.xml /var/ossec/etc/rules/

# Add to /var/ossec/etc/ossec.conf before </ossec_config>:
# <localfile>
#   <log_format>json</log_format>
#   <location>/var/ossec/logs/active-responses.log</location>
# </localfile>

sudo systemctl restart wazuh-manager
```

### 7. Configure Ollama on host machine (Windows/Linux/Mac)

```bash
# Set to listen on all interfaces
# Windows PowerShell (Admin):
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0", "Machine")

# Linux/Mac:
export OLLAMA_HOST=0.0.0.0

# Pull the model
ollama pull llama3.2:3b

# Allow firewall (Windows):
New-NetFirewallRule -DisplayName "Ollama" -Direction Inbound -Protocol TCP -LocalPort 11434 -Action Allow
```

### 8. Update pipeline configuration

Edit `pipeline.py` and set your values:

```python
VICTIM_IP    = '10.0.0.6'       # Your victim VM IP
IDS_IP       = '10.0.0.4'       # Your IDS VM IP
OLLAMA_URL   = 'http://192.168.1.74:11434/api/generate'  # Your host IP
```

---

## Usage

### Run the pipeline

```bash
cd ~/ml-ids
sudo venv/bin/python3 pipeline.py
```

Expected output:
```
[*] Hybrid Detection Pipeline started
    ML Model   : LGBMClassifier
    AI Model   : llama3.2:3b (async)
    Victim IP  : 10.0.0.6
    Cooldown   : 60s per attack category
    MITRE      : Suricata metadata > DB lookup > port fallback
```

### On-demand AI analyst

```bash
python3 explain.py
```

Lets you select any alert from the log and get a detailed incident report.

### Check alerts

```bash
# Live pipeline output
tail -f /home/IDS/ml-ids/alerts.json

# Wazuh enriched alerts
tail -f /var/ossec/logs/active-responses.log

# Alert summary
cat alerts.json | python3 -c "
import json, sys
from collections import Counter
alerts = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'Total: {len(alerts)}')
print(f'L4: {sum(1 for a in alerts if a[\"level\"]==\"L4\")}')
print(f'L3: {sum(1 for a in alerts if a[\"level\"]==\"L3\")}')
cats = Counter(a[\"category\"] for a in alerts)
for c, n in cats.most_common(): print(f'  {c}: {n}')
"
```

---

## Fusion Layer Decision Rules

| Rule | Conditions | Level | Description |
|---|---|---|---|
| R1 | Suricata high/critical + ML ≥ 0.4 | **L4** | Confirmed known high-severity attack |
| R2 | Suricata high/critical + ML < 0.4 | L3 | Known high-severity, ML not triggered |
| R3 | Suricata medium + ML ≥ 0.5 | L3 | Medium signature + anomalous behavior |
| R4 | Suricata medium + ML < 0.4 | L2 | Medium signature only |
| R5 | Suricata low + ML ≥ 0.75 | L3 | Low signature + strong anomaly |
| R6 | Suricata low + ML < 0.3 | L1 | Likely false positive |
| R7 | Suricata low + 0.3 ≤ ML < 0.75 | L2 | Weak signature + some anomaly |
| R8 | No Suricata + ML ≥ 0.9 | **L4** | Strong anomaly — likely zero-day |
| R9 | No Suricata + 0.75 ≤ ML < 0.9 | L3 | High-priority unknown attack |
| R10 | No Suricata + 0.6 ≤ ML < 0.75 | L2 | Suspicious, not extreme |
| R11 | No Suricata + 0.4 ≤ ML < 0.6 | L1 | Mild anomaly — log only |
| R12 | No Suricata + ML < 0.4 | L0 | Normal / benign |

---

## ML Model Comparison

### Custom Lab Dataset (n=10,000)

| Model | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| **LightGBM** ★ | **0.9530** | 0.9956 | 0.9100 | 0.9509 | **0.0044** |
| XGBoost | 0.9520 | 0.9902 | 0.9130 | 0.9501 | 0.0098 |
| MLP | 0.9515 | 0.9934 | 0.9090 | 0.9493 | 0.0066 |
| AdaBoost | 0.9490 | 0.9967 | 0.9010 | 0.9464 | 0.0033 |
| RandomForest | 0.9425 | 0.9743 | 0.9090 | 0.9405 | 0.0257 |
| DecisionTree | 0.9250 | 0.9233 | 0.9270 | 0.9251 | 0.0767 |

★ LightGBM selected for live pipeline — lowest FPR (0.44%)

### Combined Benchmark Dataset (n=120,504)

| Model | Accuracy | F1 | FPR |
|---|---|---|---|
| **XGBoost** ★ | **0.9955** | 0.9955 | 0.0065 |
| LightGBM | 0.9950 | 0.9950 | 0.0075 |
| RandomForest | 0.9950 | 0.9950 | 0.0062 |

> ⚠️ **Domain mismatch**: Combined model detected only 21 live alerts vs 38,516 for custom model. Training data must match the deployment environment.

---

## MITRE ATT&CK Mapping

| Attack | Technique | Source |
|---|---|---|
| Cisco ASA CVE-2020-3452 | T1083 File & Dir Discovery | `suricata_metadata` ✓ |
| GPL ATTACK_RESPONSE | T1190 Exploit Public-Facing | `mitre_db_lookup` |
| SSH Brute Force | T1110 Brute Force | `mitre_db_lookup` |
| nmap SYN scan | T1595 Active Scanning | `mitre_db_lookup` |
| Stealth scan (ML only) | T1595 Active Scanning | `port_fallback` |

---

## Project Structure

```
.
├── pipeline.py              # Main detection pipeline
├── explain.py               # On-demand AI analyst tool
├── fusion.py                # Fusion Layer (R1-R12 rules)
├── mitre.py                 # MITRE ATT&CK mapping (3-tier)
├── train_custom.py          # Train on custom NFStream dataset
├── train_combined.py        # Train on combined benchmark datasets
├── build_combined_dataset.py
├── test_combined.py
├── requirements.txt
├── .gitignore
├── suricata/
│   └── local.rules          # 12 custom Suricata rules
├── wazuh/
│   ├── hybrid_ids_rules.xml
│   └── hybrid_ids_decoder.xml
└── docs/
    ├── PROJECT_STATUS.md
    └── diagram.png
```

---

## Team

| Name | Role |
|---|---|
| Abdullah Asaad Ladjal | AI Agent + Main Pipeline |
| Tal Mohammed Faden | Fusion Layer + Wazuh SIEM |
| Ahmed Khalid Humadi | Suricata Rules + MITRE Mapping |
| Khalid Ali AL-Mufarrih | System Architecture + Lab Setup |
| Abdulmajeed Meshal Almalki | ML Training + Dataset Engineering |

---

## References

1. Comparative Analysis of Snort, Suricata and Bro IDS. E.P. College, Ghana, 2019.
2. Anita S. & Gupta S. An effective model for anomaly IDS. ICGCIoT, 2015.
3. Alnasser O. et al. Signature and anomaly based IDS for IoTs, 2021.
4. Aslam U. et al. Hybrid NIDS using ML and Rule Based Learning, 2020.
5. Moustafa N. & Slay J. UNSW-NB15 dataset. MilCIS, 2015.
6. Sharafaldin I. et al. CICIDS2017 dataset. ICISSP, 2018.
7. The MITRE Corporation. MITRE ATT&CK Enterprise v14. https://attack.mitre.org
8. Proofpoint Emerging Threats. ET/Open Ruleset. https://rules.emergingthreats.net

---

## License

This project was developed as part of CCCY 421 Senior Project at the University of Jeddah.
