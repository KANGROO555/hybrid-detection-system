def fusion_layer(s_alert, s_sev, anomaly_score):
    """
    Fusion Layer — R1-R12 rule-based decision logic.

    Inputs:
        s_alert      : int   — 1 if Suricata fired, 0 otherwise
        s_sev        : str   — 'low', 'medium', 'high', 'critical'
        anomaly_score: float — ML anomaly score 0.0 to 1.0

    Output:
        dict with keys: level, tag, action
    """
    m_alert = 1 if anomaly_score >= 0.5 else 0
    sev     = s_sev.lower() if s_sev else 'low'

    # ── R1 ────────────────────────────────────────────────────
    if (s_alert == 1 and sev in ('high', 'critical') and
            (m_alert == 1 or anomaly_score >= 0.4)):
        return {'level': 'L4', 'tag': 'Confirmed known high-severity attack, ML supports', 'action': 'Immediate investigation'}

    # ── R2 ────────────────────────────────────────────────────
    if (s_alert == 1 and sev in ('high', 'critical') and
            m_alert == 0 and anomaly_score < 0.4):
        return {'level': 'L3', 'tag': 'Known high-severity signature, ML not triggered', 'action': 'Immediate investigation'}

    # ── R3 ────────────────────────────────────────────────────
    if s_alert == 1 and sev == 'medium' and m_alert == 1:
        return {'level': 'L3', 'tag': 'Medium signature + anomalous behavior', 'action': 'Immediate investigation'}

    # ── R4 ────────────────────────────────────────────────────
    if s_alert == 1 and sev == 'medium' and m_alert == 0 and anomaly_score < 0.4:
        return {'level': 'L2', 'tag': 'Medium signature only - needs analyst review', 'action': 'Manual analyst review'}

    # ── R5 ────────────────────────────────────────────────────
    if s_alert == 1 and sev == 'low' and anomaly_score >= 0.75:
        return {'level': 'L3', 'tag': 'Low signature + strong anomaly - possible stealth attack', 'action': 'Immediate investigation'}

    # ── R6 ────────────────────────────────────────────────────
    if s_alert == 1 and sev == 'low' and anomaly_score < 0.3:
        return {'level': 'L1', 'tag': 'Possible Suricata false positive - low priority', 'action': 'Log event for reference'}

    # ── R7 ────────────────────────────────────────────────────
    if s_alert == 1 and sev == 'low' and 0.3 <= anomaly_score < 0.75:
        return {'level': 'L2', 'tag': 'Weak signature + some anomaly - keep an eye on it', 'action': 'Manual analyst review'}

    # ── R8 ────────────────────────────────────────────────────
    if s_alert == 0 and anomaly_score >= 0.9:
        return {'level': 'L4', 'tag': 'Strong anomaly without signature - likely zero-day', 'action': 'Immediate investigation'}

    # ── R9 ────────────────────────────────────────────────────
    if s_alert == 0 and 0.75 <= anomaly_score < 0.9:
        return {'level': 'L3', 'tag': 'Strong anomaly - high priority unknown attack', 'action': 'Immediate investigation'}

    # ── R10 ───────────────────────────────────────────────────
    if s_alert == 0 and 0.6 <= anomaly_score < 0.75:
        return {'level': 'L2', 'tag': 'Anomalous but not extreme - suspicious', 'action': 'Manual analyst review'}

    # ── R11 ───────────────────────────────────────────────────
    if s_alert == 0 and 0.4 <= anomaly_score < 0.6:
        return {'level': 'L1', 'tag': 'Mild anomaly - log only unless repeated', 'action': 'Log event for reference'}

    # ── R12 ───────────────────────────────────────────────────
    return {'level': 'L0', 'tag': 'Normal / benign', 'action': 'No action required'}


LEVEL_INFO = {
    'L0': {'confidence': 'Benign',                'color': 'green'},
    'L1': {'confidence': 'Low confidence',         'color': 'blue'},
    'L2': {'confidence': 'Suspicious activity',    'color': 'yellow'},
    'L3': {'confidence': 'High confidence attack', 'color': 'orange'},
    'L4': {'confidence': 'Confirmed attack',       'color': 'red'},
}


if __name__ == '__main__':
    test_cases = [
        (1, 'high',     0.6,  'L4'),  # R1
        (1, 'critical', 0.2,  'L3'),  # R2
        (1, 'medium',   0.7,  'L3'),  # R3
        (1, 'medium',   0.2,  'L2'),  # R4
        (1, 'low',      0.8,  'L3'),  # R5
        (1, 'low',      0.1,  'L1'),  # R6
        (1, 'low',      0.5,  'L2'),  # R7
        (0, 'none',     0.95, 'L4'),  # R8
        (0, 'none',     0.80, 'L3'),  # R9
        (0, 'none',     0.65, 'L2'),  # R10
        (0, 'none',     0.45, 'L1'),  # R11
        (0, 'none',     0.2,  'L0'),  # R12
    ]

    print("Testing Fusion Layer (R1-R12)")
    print("-" * 60)
    all_passed = True
    for i, (s_alert, s_sev, score, expected) in enumerate(test_cases, 1):
        result = fusion_layer(s_alert, s_sev, score)
        status = '✓' if result['level'] == expected else '✗ FAIL'
        if result['level'] != expected:
            all_passed = False
        print(f"R{i:02d} [{status}] s_alert={s_alert} sev={s_sev:8s} "
              f"score={score:.2f} → {result['level']} | {result['tag']}")

    print("-" * 60)
    print(f"{'All tests passed ✓' if all_passed else 'Some tests failed ✗'}")
