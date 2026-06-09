import re
from mitreattack.stix20 import MitreAttackData

print("[*] Loading MITRE ATT&CK database...")
_mitre = MitreAttackData('enterprise-attack.json')
_techniques = _mitre.get_techniques(remove_revoked_deprecated=True)

# Build lookup by technique ID
_tech_by_id = {}
for t in _techniques:
    ext_refs = t.get('external_references', [])
    for ref in ext_refs:
        if ref.get('source_name') == 'mitre-attack':
            tid = ref.get('external_id', '')
            _tech_by_id[tid] = t
            break

print(f"[+] Loaded {len(_tech_by_id)} MITRE ATT&CK techniques")

# Port-based fallback mapping
PORT_MAP = {
    22:   'T1110',  # Brute Force
    21:   'T1190',  # Exploit Public-Facing Application
    80:   'T1190',
    443:  'T1190',
    8080: 'T1190',
    8443: 'T1190',
    139:  'T1021',  # Remote Services
    445:  'T1021',
    3389: 'T1021',
    53:   'T1071',  # Application Layer Protocol
    25:   'T1566',  # Phishing
    23:   'T1021',  # Telnet
}

def clean_desc(desc):
    """Remove markdown links, citations, and truncate at sentence boundary."""
    desc = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', desc)
    desc = re.sub(r'\(Citation:[^)]+\)', '', desc)
    desc = desc.split('\n')[0].strip()
    # Cut at last complete sentence within 150 chars
    if len(desc) > 150:
        truncated = desc[:150]
        last_period = truncated.rfind('.')
        if last_period > 50:
            desc = truncated[:last_period + 1]
        else:
            desc = truncated
    return desc

def get_technique_by_id(tid):
    """Look up a real technique from MITRE database by ID."""
    t = _tech_by_id.get(tid)
    if not t:
        return None
    kill_chain = t.get('kill_chain_phases', [])
    tactic = kill_chain[0].get('phase_name', 'unknown').replace('-', ' ').title() \
             if kill_chain else 'Unknown'
    desc = clean_desc(t.get('description', ''))
    return {
        'tactic':    tactic,
        'technique': f"{tid} - {t.name}",
        'stage':     desc
    }

def search_by_signature(s_sig):
    """Search MITRE technique names using Suricata signature text."""
    # Remove common non-meaningful words
    STOPWORDS = {'et', 'scan', 'alert', 'attack', 'the', 'a', 'an', 'for',
                 'tool', 'new', 'old', 'bad', 'good', 'from', 'to', 'on'}

    sig_lower = s_sig.lower().replace('-', ' ').replace('_', ' ')
    keywords = [w for w in sig_lower.split() if len(w) > 4 and w not in STOPWORDS]

    if not keywords:
        return None

    best_match = None
    best_score = 0
    for tid, t in _tech_by_id.items():
        name_lower = t.name.lower()
        score = sum(1 for kw in keywords if kw in name_lower)
        if score > best_score:
            best_score = score
            best_match = tid

    # Require at least 2 keyword matches for signature-based lookup
    if best_score >= 2 and best_match:
        return get_technique_by_id(best_match)
    return None
def get_mitre(proto, dst_port, tag, s_sig):
    """
    Map alert to real MITRE ATT&CK technique.
    Priority:
    1. Search MITRE database using Suricata signature text
    2. Tag-based detection (port scan, brute force, zero-day)
    3. Port-based fallback mapping
    """

    # ── 1. Signature-based search (most accurate) ─────────────
    if s_sig:
        result = search_by_signature(s_sig)
        if result:
            return result

    # ── 2. Tag-based detection ────────────────────────────────
    tag_lower = tag.lower()
    sig_lower  = s_sig.lower() if s_sig else ''

    if 'portscan' in tag_lower or 'scan' in sig_lower:
        return get_technique_by_id('T1595')  # Active Scanning

    if 'brute' in tag_lower or 'brute' in sig_lower:
        return get_technique_by_id('T1110')  # Brute Force

    if 'zero-day' in tag_lower or 'novel' in tag_lower:
        return get_technique_by_id('T1190')  # Exploit Public-Facing Application

    if 'lateral' in tag_lower:
        return get_technique_by_id('T1021')  # Remote Services

    # ── 3. Port-based fallback ────────────────────────────────
    tid = PORT_MAP.get(dst_port, 'T1046')  # Default: Network Service Discovery
    result = get_technique_by_id(tid)
    if result:
        return result

    # ── Final fallback ────────────────────────────────────────
    return {
        'tactic':    'Discovery',
        'technique': 'T1046 - Network Service Discovery',
        'stage':     'Adversaries may attempt to get a listing of services running on remote hosts.'
    }
