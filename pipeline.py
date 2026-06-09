import json
import time
import joblib
import hashlib
import numpy as np
import pandas as pd
import threading
import requests
from collections import defaultdict
from nfstream import NFStreamer
from fusion import fusion_layer, LEVEL_INFO
from mitre import get_mitre

# ── Load model ────────────────────────────────────────────────
model         = joblib.load('best_model_custom.pkl')
feature_names = joblib.load('feature_names_custom.pkl')

# ── Config ────────────────────────────────────────────────────
THRESHOLD           = 0.85
WINDOW              = 30
PORT_SCAN_THRESHOLD = 15
VICTIM_IP           = '10.0.0.6'
IDS_IP              = '10.0.0.4'
EVE_LOG             = '/var/log/suricata/eve.json'
ALERTS_FILE         = '/home/IDS/ml-ids/alerts.json'
WAZUH_LOG           = '/var/ossec/logs/active-responses.log'
WHITELIST_PORTS     = {1514, 1515, 55000}
AI_MODEL            = 'llama3.2:3b'
OLLAMA_URL          = 'http://192.168.1.74:11434/api/generate'
ALERT_COOLDOWN      = 0

# ── Suricata alert cache ──────────────────────────────────────
suricata_alerts = {}
suricata_lock   = threading.Lock()

def severity_from_suricata(sev_num):
    return {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}.get(sev_num, 'low')

def suricata_reader():
    with open(EVE_LOG, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            try:
                event = json.loads(line.strip())
                if event.get('event_type') != 'alert':
                    continue

                sev_num   = event.get('alert', {}).get('severity', 3)
                meta      = event.get('alert', {}).get('metadata', {})
                src_ip    = event.get('src_ip')
                dest_ip   = event.get('dest_ip')
                dest_port = event.get('dest_port')
                src_port  = event.get('src_port')

                mitre_tid     = meta.get('mitre_technique_id',   [None])[0]
                mitre_tname   = meta.get('mitre_technique_name', [None])[0]
                mitre_tacid   = meta.get('mitre_tactic_id',      [None])[0]
                mitre_tacname = meta.get('mitre_tactic_name',    [None])[0]

                alert_data = {
                    'alert':                1,
                    'severity':             severity_from_suricata(sev_num),
                    'signature':            event.get('alert', {}).get('signature', ''),
                    'timestamp':            time.time(),
                    'mitre_technique_id':   mitre_tid,
                    'mitre_technique_name': mitre_tname,
                    'mitre_tactic_id':      mitre_tacid,
                    'mitre_tactic_name':    mitre_tacname,
                }

                # Store under all port/direction combinations
                with suricata_lock:
                    suricata_alerts[(src_ip,  dest_ip,  dest_port)] = alert_data
                    suricata_alerts[(dest_ip, src_ip,   dest_port)] = alert_data
                    suricata_alerts[(src_ip,  dest_ip,  src_port)]  = alert_data
                    suricata_alerts[(dest_ip, src_ip,   src_port)]  = alert_data
                    suricata_alerts[(src_ip,  dest_ip,  None)]      = alert_data
                    suricata_alerts[(dest_ip, src_ip,   None)]      = alert_data

            except:
                continue

def get_suricata_alert(src_ip, dest_ip, dst_port, src_port=None):
    now  = time.time()
    keys = [
        (src_ip,  dest_ip,  dst_port),
        (dest_ip, src_ip,   dst_port),
        (src_ip,  dest_ip,  src_port),
        (dest_ip, src_ip,   src_port),
        (src_ip,  dest_ip,  None),
        (dest_ip, src_ip,   None),
    ]
    with suricata_lock:
        for key in keys:
            alert = suricata_alerts.get(key)
            if alert and now - alert['timestamp'] < 60:
                return alert
    return {
        'alert': 0, 'severity': 'low', 'signature': '',
        'mitre_technique_id': None, 'mitre_technique_name': None,
        'mitre_tactic_id': None, 'mitre_tactic_name': None,
    }

# ── Per-source tracking ───────────────────────────────────────
src_stats = defaultdict(lambda: {
    'ports': set(), 'flows': 0, 'bytes': 0, 'first_seen': time.time()
})

def update_src_stats(src, dst_port, flow_bytes):
    now = time.time()
    if now - src_stats[src]['first_seen'] > WINDOW:
        src_stats[src] = {'ports': set(), 'flows': 0, 'bytes': 0, 'first_seen': now}
    src_stats[src]['ports'].add(dst_port)
    src_stats[src]['flows'] += 1
    src_stats[src]['bytes'] += flow_bytes
    return len(src_stats[src]['ports'])

# ── Attack category classifier ────────────────────────────────
def get_attack_category(src, dst_port, tag, s_sig):
    sig     = s_sig.lower() if s_sig else ''
    tag_low = tag.lower()
    ports   = src_stats[src]['ports']

    if s_sig:
        if 'scan' in sig:                                   return 'PORT_SCAN'
        if 'brute' in sig:                                  return 'BRUTE_FORCE'
        if 'ssh' in sig:                                    return 'SSH_ATTACK'
        if 'ftp' in sig:                                    return 'FTP_ATTACK'
        if 'attack_response' in sig or 'attack response' in sig: return 'ATTACK_RESPONSE'
        if 'exploit' in sig:                                return 'EXPLOIT'
        if 'web' in sig or 'http' in sig:                  return 'WEB_ATTACK'
        return 'SURICATA_ALERT'

    if 'portscan' in tag_low or len(ports) >= PORT_SCAN_THRESHOLD:
        return 'PORT_SCAN'
    if dst_port == 22:                  return 'SSH_BRUTE_FORCE'
    if dst_port == 21:                  return 'FTP_BRUTE_FORCE'
    if dst_port in (80, 443, 8080):     return 'WEB_ATTACK'
    if dst_port in (139, 445):          return 'SMB_ATTACK'
    if dst_port == 3389:                return 'RDP_ATTACK'
    if dst_port == 23:                  return 'TELNET_ATTACK'
    if dst_port == 25:                  return 'SMTP_ATTACK'
    return 'ANOMALY'

# ── Alert deduplication ───────────────────────────────────────
alert_cooldown = {}

def should_alert(src, category):
    now = time.time()
    key = (src, category)
    last = alert_cooldown.get(key, 0)
    if now - last < ALERT_COOLDOWN:
        return False
    alert_cooldown[key] = now
    return True

# ── ML scoring ───────────────────────────────────────────────
def map_flow(flow):
    return {
        'src_port':                      flow.src_port,
        'dst_port':                      flow.dst_port,
        'protocol':                      flow.protocol,
        'bidirectional_duration_ms':     flow.bidirectional_duration_ms,
        'bidirectional_packets':         flow.bidirectional_packets,
        'bidirectional_bytes':           flow.bidirectional_bytes,
        'src2dst_duration_ms':           flow.src2dst_duration_ms,
        'src2dst_packets':               flow.src2dst_packets,
        'src2dst_bytes':                 flow.src2dst_bytes,
        'dst2src_duration_ms':           flow.dst2src_duration_ms,
        'dst2src_packets':               flow.dst2src_packets,
        'dst2src_bytes':                 flow.dst2src_bytes,
        'bidirectional_min_ps':          flow.bidirectional_min_ps,
        'bidirectional_mean_ps':         flow.bidirectional_mean_ps,
        'bidirectional_stddev_ps':       flow.bidirectional_stddev_ps,
        'bidirectional_max_ps':          flow.bidirectional_max_ps,
        'src2dst_min_ps':                flow.src2dst_min_ps,
        'src2dst_mean_ps':               flow.src2dst_mean_ps,
        'src2dst_stddev_ps':             flow.src2dst_stddev_ps,
        'src2dst_max_ps':                flow.src2dst_max_ps,
        'dst2src_min_ps':                flow.dst2src_min_ps,
        'dst2src_mean_ps':               flow.dst2src_mean_ps,
        'dst2src_stddev_ps':             flow.dst2src_stddev_ps,
        'dst2src_max_ps':                flow.dst2src_max_ps,
        'bidirectional_min_piat_ms':     flow.bidirectional_min_piat_ms,
        'bidirectional_mean_piat_ms':    flow.bidirectional_mean_piat_ms,
        'bidirectional_stddev_piat_ms':  flow.bidirectional_stddev_piat_ms,
        'bidirectional_max_piat_ms':     flow.bidirectional_max_piat_ms,
        'src2dst_min_piat_ms':           flow.src2dst_min_piat_ms,
        'src2dst_mean_piat_ms':          flow.src2dst_mean_piat_ms,
        'src2dst_stddev_piat_ms':        flow.src2dst_stddev_piat_ms,
        'src2dst_max_piat_ms':           flow.src2dst_max_piat_ms,
        'dst2src_min_piat_ms':           flow.dst2src_min_piat_ms,
        'dst2src_mean_piat_ms':          flow.dst2src_mean_piat_ms,
        'dst2src_stddev_piat_ms':        flow.dst2src_stddev_piat_ms,
        'dst2src_max_piat_ms':           flow.dst2src_max_piat_ms,
        'bidirectional_syn_packets':     flow.bidirectional_syn_packets,
        'bidirectional_cwr_packets':     flow.bidirectional_cwr_packets,
        'bidirectional_ece_packets':     flow.bidirectional_ece_packets,
        'bidirectional_urg_packets':     flow.bidirectional_urg_packets,
        'bidirectional_ack_packets':     flow.bidirectional_ack_packets,
        'bidirectional_psh_packets':     flow.bidirectional_psh_packets,
        'bidirectional_rst_packets':     flow.bidirectional_rst_packets,
        'bidirectional_fin_packets':     flow.bidirectional_fin_packets,
        'src2dst_syn_packets':           flow.src2dst_syn_packets,
        'src2dst_cwr_packets':           flow.src2dst_cwr_packets,
        'src2dst_ece_packets':           flow.src2dst_ece_packets,
        'src2dst_urg_packets':           flow.src2dst_urg_packets,
        'src2dst_ack_packets':           flow.src2dst_ack_packets,
        'src2dst_psh_packets':           flow.src2dst_psh_packets,
        'src2dst_rst_packets':           flow.src2dst_rst_packets,
        'src2dst_fin_packets':           flow.src2dst_fin_packets,
        'dst2src_syn_packets':           flow.dst2src_syn_packets,
        'dst2src_cwr_packets':           flow.dst2src_cwr_packets,
        'dst2src_ece_packets':           flow.dst2src_ece_packets,
        'dst2src_urg_packets':           flow.dst2src_urg_packets,
        'dst2src_ack_packets':           flow.dst2src_ack_packets,
        'dst2src_psh_packets':           flow.dst2src_psh_packets,
        'dst2src_rst_packets':           flow.dst2src_rst_packets,
        'dst2src_fin_packets':           flow.dst2src_fin_packets,
        'application_is_guessed':        flow.application_is_guessed,
        'application_confidence':        flow.application_confidence,
        'ip_version':                    flow.ip_version,
        'vlan_id':                       flow.vlan_id,
        'tunnel_id':                     flow.tunnel_id,
    }

def score_flow(flow):
    features = map_flow(flow)
    row = pd.DataFrame([features])
    for col in feature_names:
        if col not in row.columns:
            row[col] = 0
    row = row[feature_names]
    row = row.fillna(0).replace([np.inf, -np.inf], 0)
    return round(model.predict_proba(row)[0][1], 4)

# ── MITRE resolution ──────────────────────────────────────────
def resolve_mitre(s_info, proto, dst_port, tag, s_sig):
    tid   = s_info.get('mitre_technique_id')
    tname = s_info.get('mitre_technique_name')
    tac   = s_info.get('mitre_tactic_name')

    if tid and tname and tac:
        return {
            'tactic':    tac.replace('_', ' '),
            'technique': f"{tid} - {tname.replace('_', ' ')}",
            'stage':     'Extracted from Suricata ET rule metadata (authoritative)',
            'source':    'suricata_metadata'
        }

    result = get_mitre(proto, dst_port, tag, s_sig)
    result['source'] = 'mitre_db_lookup'
    return result

# ── AI agent ─────────────────────────────────────────────────
def get_ai_explanation(entry):
    mitre  = entry.get('mitre', {})
    prompt = f"""You are a cybersecurity analyst. Analyze this alert in 2 sentences maximum.
What is happening and what should the analyst do immediately?
When mentioning mitigation recommendations, list 3 critical points without extra words.

Alert: {entry['proto']} {entry['src']}:{entry['src_port']} -> {entry['dst']}:{entry['dst_port']}
Category: {entry['category']}
ML Score: {entry['ml_score']} | Decision: {entry['level']}
MITRE: {mitre.get('technique', 'Unknown')} ({mitre.get('tactic', 'Unknown')})
MITRE Source: {mitre.get('source', 'unknown')}
Fusion tag: {entry['tag']}
Suricata: {'Matched: ' + entry['s_sig'] if entry['s_alert'] else 'No signature matched'}"""

    try:
        r = requests.post(
            OLLAMA_URL,
            json={'model': AI_MODEL, 'prompt': prompt, 'stream': False},
            timeout=300
        )
        return r.json().get('response', 'AI agent unavailable').strip()
    except Exception as e:
        return f'AI agent unavailable: {e}'

# ── Send to Wazuh ─────────────────────────────────────────────
def send_to_wazuh(entry, explanation):
    log = {
        "hybrid_ids_event_id":        entry['event_id'],
        "hybrid_ids_timestamp":       entry['timestamp'],
        "hybrid_ids_level":           entry['level'],
        "hybrid_ids_confidence":      'HIGH' if entry['level'] == 'L4' else 'MEDIUM' if level == 'L3' else 'LOW',
        "hybrid_ids_category":        entry['category'],
        "hybrid_ids_proto":           entry['proto'],
        "hybrid_ids_src_ip":          entry['src'],
        "hybrid_ids_src_port":        entry['src_port'],
        "hybrid_ids_dst_ip":          entry['dst'],
        "hybrid_ids_dst_port":        entry['dst_port'],
        "hybrid_ids_ml_score":        entry['ml_score'],
        "hybrid_ids_s_alert":         entry['s_alert'],
        "hybrid_ids_s_sev":           entry['s_sev'],
        "hybrid_ids_s_sig":           entry['s_sig'],
        "hybrid_ids_fusion_tag":      entry['tag'],
        "hybrid_ids_mitre_source":    entry['mitre'].get('source', 'unknown'),
        "hybrid_ids_mitre_tactic":    entry['mitre']['tactic'],
        "hybrid_ids_mitre_technique": entry['mitre']['technique'],
        "hybrid_ids_ai_summary":      explanation[:10000]
    }
    try:
        with open(WAZUH_LOG, 'a') as f:
            f.write(json.dumps(log) + '\n')
    except Exception as e:
        print(f"    [!] Wazuh log error: {e}")

# ── Alert log ─────────────────────────────────────────────────
alert_log  = []
alert_lock = threading.Lock()

def log_alert(entry):
    with alert_lock:
        alert_log.append(entry)
        with open(ALERTS_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

# ── Start Suricata reader thread ──────────────────────────────
t = threading.Thread(target=suricata_reader, daemon=True)
t.start()

print("[*] Hybrid Detection Pipeline started")
print(f"    ML Model   : {type(model).__name__}")
print(f"    AI Model   : {AI_MODEL} (async)")
print(f"    Victim IP  : {VICTIM_IP}")
print(f"    Cooldown   : {ALERT_COOLDOWN}s per attack category")
print(f"    MITRE      : Suricata metadata > DB lookup > port fallback")
print(f"    Suricata   : {EVE_LOG}")
print(f"    Alert log  : {ALERTS_FILE}")
print("-" * 75)

streamer = NFStreamer(
    source='enp0s3',
    statistical_analysis=True,
    idle_timeout=10,
    active_timeout=30
)

try:
    for flow in streamer:
        try:
            src   = flow.src_ip
            dst   = flow.dst_ip
            proto = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(flow.protocol, '?')

            if flow.dst_port in WHITELIST_PORTS or flow.src_port in WHITELIST_PORTS or src in IDS_IP or src in VICTIM_IP:
                continue

            unique_ports = update_src_stats(src, flow.dst_port, flow.bidirectional_bytes)

            # ── 1. ML score ───────────────────────────────────
            ml_score = score_flow(flow)
            reason   = 'ML'

            # ── 2. Behavioral boost ───────────────────────────
            if dst == VICTIM_IP and src != IDS_IP:
                if unique_ports >= PORT_SCAN_THRESHOLD:
                    ml_score = max(ml_score, 0.85)
                    reason   = f'PORTSCAN({unique_ports} ports)'
                if src_stats[src]['flows'] > 50 and flow.dst_port in [22, 21, 3389, 23]:
                    ml_score = max(ml_score, 0.80)
                    reason   = f'BRUTEFORCE(port {flow.dst_port})'

            # ── 3. Suricata lookup (both src and dst ports) ───
            s_info  = get_suricata_alert(src, dst, flow.dst_port, flow.src_port)
            s_alert = s_info['alert']
            s_sev   = s_info['severity']
            s_sig   = s_info['signature']

            # ── 4. Fusion Layer ───────────────────────────────
            decision = fusion_layer(s_alert, s_sev, ml_score)
            level    = decision['level']

            if level in ('L0', 'L1'):
                continue

            # ── 5. Attack category + dedup ────────────────────
            category = get_attack_category(src, flow.dst_port, decision['tag'], s_sig)

            # Bypass cooldown if Suricata confirmed the alert
            if not s_alert and not should_alert(src, category):
                continue

            # ── 6. MITRE resolution ───────────────────────────
            mitre    = resolve_mitre(s_info, proto, flow.dst_port, decision['tag'], s_sig)
            event_id = hashlib.md5(
                f"{src}{dst}{category}{time.time()}".encode()
            ).hexdigest()[:6]
            ts   = time.strftime('%Y-%m-%d %H:%M:%S')
            conf = 'HIGH' if level == 'L4' else 'MEDIUM' if level == 'L3' else 'LOW'

            # ── 7. Build entry ────────────────────────────────
            entry = {
                'event_id':  event_id,
                'timestamp': ts,
                'level':     level,
                'category':  category,
                'proto':     proto,
                'src':       src,
                'src_port':  flow.src_port,
                'dst':       dst,
                'dst_port':  flow.dst_port,
                'ml_score':  ml_score,
                's_alert':   s_alert,
                's_sev':     s_sev,
                's_sig':     s_sig,
                'tag':       decision['tag'],
                'mitre':     mitre,
            }
            log_alert(entry)

            # ── 8. Print analyst format ───────────────────────
            print(f"\n[{ts}] EVENT_ID={event_id}  SRC={src}  DST={dst}  PROTO={proto}")
            print("-" * 75)
            print(f"CATEGORY: {category}")
            print(f"SURICATA:")
            print(f"  alert={s_alert}   severity={s_sev}   signature=\"{s_sig if s_sig else 'No match'}\"")
            print(f"ML ANOMALY:")
            print(f"  anomaly_score={ml_score}   m_alert={1 if ml_score >= 0.5 else 0}   model=\"{type(model).__name__}\"")
            print(f"FUSION ENGINE:")
            print(f"  decision={level}  confidence={conf}")
            print(f"  reason=\"{decision['tag']}\"")
            print(f"MITRE ATT&CK: [source={mitre.get('source','unknown')}]")
            print(f"  tactic=\"{mitre['tactic']}\"")
            print(f"  technique=\"{mitre['technique']}\"")
            print(f"  stage=\"{mitre['stage']}\"")
            print(f"ACTION: {decision['action']}")

            # ── 9. AI enrichment async (L3/L4 only) ──────────
            if level in ('L0','L1','L2','L3', 'L4'):
                def ai_task(e):
                    explanation = get_ai_explanation(e)
                    e['ai_summary'] = explanation
                    send_to_wazuh(e, explanation)
                    print(f"\n[AI AGENT] EVENT_ID={e['event_id']} CATEGORY={e['category']}")
                    print(f"  \"{explanation[:2000]}\"")
                    print(f"  [enriched log sent to Wazuh]\n")
                threading.Thread(
                    target=ai_task,
                    args=(entry.copy(),),
                    daemon=True
                ).start()
                print(f"AI AGENT: queued for async analysis...")

            print("-" * 75)

        except Exception as e:
            continue

except KeyboardInterrupt:
    print(f"\n[*] Pipeline stopped.")
    print(f"[*] Total alerts logged: {len(alert_log)}")
