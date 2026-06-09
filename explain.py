import json
import hashlib
import requests
import sys
from mitre import get_mitre

ALERTS_FILE = '/home/IDS/ml-ids/alerts.json'
OLLAMA_URL  = 'http://192.168.1.74:11434/api/generate'
MODEL       = 'llama3.2:3b'

def explain_alert(alert):
    mitre = alert.get('mitre') or get_mitre(
        alert['proto'], alert['dst_port'], alert['tag'], alert['s_sig'])

    prompt = f"""You are a cybersecurity analyst. Analyze this network intrusion detection alert and provide a professional technical assessment.

Respond in this exact format:

SUMMARY:
[3 sentences describing: what attack technique is being used, what the attacker's objective is, and why this has high confidence with no signature match]

ACTIONS:
1) [specific containment action with IP {alert['src']}]
2) [specific investigation action on {alert['dst']}:{alert['dst_port']}]
3) [log review action]
4) [threat hunting action]

Alert details:
- Time: {alert['timestamp']}
- Level: {alert['level']}
- Protocol: {alert['proto']}
- Source: {alert['src']}:{alert['src_port']}
- Destination: {alert['dst']}:{alert['dst_port']}
- ML Score: {alert['ml_score']}
- Suricata: {'Signature matched: ' + alert['s_sig'] if alert['s_alert'] else 'No signature matched'}
- MITRE: {mitre['technique']} ({mitre['tactic']})
- Decision: {alert['tag']}"""

    print(f"\n[*] Warming up AI agent...")
    requests.post(OLLAMA_URL,
        json={'model': MODEL, 'prompt': '', 'stream': False, 'keep_alive': 300},
        timeout=300)

    print(f"[*] Analyzing alert...")
    r = requests.post(
        OLLAMA_URL,
        json={'model': MODEL, 'prompt': prompt, 'stream': False},
        timeout=300
    )
    return r.json().get('response', 'No response')

def parse_response(text):
    lines = [l.strip() for l in text.strip().split('\n') if l.strip()]
    summary = []
    actions = []
    in_summary = False
    in_actions = False
    for line in lines:
        if line.upper().startswith('SUMMARY'):
            in_summary = True
            in_actions = False
            continue
        elif line.upper().startswith('ACTIONS'):
            in_summary = False
            in_actions = True
            continue
        if in_summary:
            summary.append(line)
        elif in_actions:
            actions.append(line)
    return summary, actions

def main():
    try:
        with open(ALERTS_FILE, 'r') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print("No alerts found. Run pipeline.py first.")
        sys.exit(1)

    if not alerts:
        print("Alert log is empty.")
        sys.exit(1)

    print(f"\n[*] Recent alerts ({len(alerts)} total):")
    print("-" * 75)
    recent = alerts[-10:]
    for i, alert in enumerate(recent):
        print(f"[{i}] {alert['timestamp']} | {alert['level']} | "
              f"{alert['proto']} {alert['src']} -> {alert['dst']}:{alert['dst_port']} | "
              f"ml={alert['ml_score']} | {alert.get('event_id', 'N/A')}")

    print("-" * 75)
    choice = input("\nEnter alert number to analyze (or 'last' for most recent): ").strip()

    if choice == 'last':
        alert = alerts[-1]
    elif choice in [a.get('event_id', '') for a in alerts]:
        alert = next(a for a in alerts if a.get('event_id') == choice)
    else:
        alert = recent[int(choice)]

    mitre = alert.get('mitre') or get_mitre(
        alert['proto'], alert['dst_port'], alert['tag'], alert['s_sig'])

    explanation = explain_alert(alert)
    summary, actions = parse_response(explanation)

    event_id = alert.get('event_id', hashlib.md5(
        f"{alert['src']}{alert['dst']}{alert['dst_port']}".encode()).hexdigest()[:6])
    conf = 'HIGH' if alert['level'] == 'L4' else 'MEDIUM' if alert['level'] == 'L3' else 'LOW'

    print(f"\n[{alert['timestamp']}] EVENT_ID={event_id}  "
          f"SRC={alert['src']}  DST={alert['dst']}  PROTO={alert['proto']}")
    print("-" * 75)
    print(f"SURICATA:")
    print(f"  alert={alert['s_alert']}   severity={alert['s_sev']}   "
          f"signature=\"{alert['s_sig'] if alert['s_sig'] else 'No match'}\"")
    print(f"ML ANOMALY:")
    print(f"  anomaly_score={alert['ml_score']}   "
          f"m_alert={1 if alert['ml_score'] >= 0.5 else 0}   model=\"LGBMClassifier\"")
    print(f"FUSION ENGINE:")
    print(f"  decision={alert['level']}  confidence={conf}")
    print(f"  reason=\"{alert['tag']}\"")
    print(f"MITRE ATT&CK:")
    print(f"  tactic=\"{mitre['tactic']}\"")
    print(f"  technique=\"{mitre['technique']}\"")
    print(f"  stage=\"{mitre['stage']}\"")
    print(f"AI AGENT (LLM):")
    print(f"  summary:")
    if summary:
        for line in summary[:3]:
            print(f"    \"{line}\"")
    else:
        print(f"    \"High confidence anomaly detected from {alert['src']} targeting {alert['dst']}:{alert['dst_port']}\"")
    print(f"  recommended_actions:")
    if actions:
        for line in actions[:4]:
            print(f"    {line}")
    else:
        print(f"    1) ISOLATE source IP {alert['src']} from network immediately")
        print(f"    2) BLOCK {alert['src']} at firewall on port {alert['dst_port']}")
        print(f"    3) INVESTIGATE logs on {alert['dst']} for the last 30 minutes")
        print(f"    4) HUNT for similar traffic patterns across all internal hosts")
    print("-" * 75)
    print(f"STATUS: LOGGED  dashboard=\"Wazuh / Hybrid-IDS Alerts\"")
    print("-" * 75)

if __name__ == '__main__':
    main()
