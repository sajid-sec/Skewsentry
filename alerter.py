# alerter.py
from datetime import datetime


# ─── Thresholds ────────────────────────────────────────────────────────────────

THRESHOLDS = {
    'CRITICAL': 2.5,
    'WARNING':  1.5,
    'INFO':     1.0,
}

# Default cooldown: suppress re-alerts for this many consecutive windows
# after an alert fires. Prevents alert storms on sustained attacks.
DEFAULT_COOLDOWN = 5


# ─── Core classifier ───────────────────────────────────────────────────────────

def classify_skew(sk: float | None) -> dict | None:
    """
    Given a Pearson skewness value, returns severity + direction.
    Returns None if skew is below INFO threshold (no alert needed).

    Direction:
    - POSITIVE sk → right-skewed → traffic spike → BRUTE_FORCE / VOLUMETRIC_SPIKE
    - NEGATIVE sk → left-skewed  → traffic drop  → SLOW_EXFILTRATION / BEACONING
    """
    if sk is None:
        return None

    abs_sk = abs(sk)
    direction = 'POSITIVE' if sk > 0 else 'NEGATIVE'

    # Check from highest severity downward — first match wins
    for severity in ['CRITICAL', 'WARNING', 'INFO']:
        if abs_sk >= THRESHOLDS[severity]:
            return {'severity': severity, 'direction': direction}

    return None  # Below INFO threshold — normal traffic


def classify_attack_type(direction: str, severity: str) -> str:
    """
    Maps direction + severity to a human-readable attack type label.

    POSITIVE (spike):
    - CRITICAL/WARNING → BRUTE_FORCE (high-volume repeated attempts)
    - INFO             → VOLUMETRIC_SPIKE (notable but not confirmed attack)

    NEGATIVE (drop):
    - CRITICAL/WARNING → SLOW_EXFILTRATION (sustained low-rate data leak)
    - INFO             → BEACONING (low-level periodic callback)
    """
    if direction == 'POSITIVE':
        if severity in ('CRITICAL', 'WARNING'):
            return 'BRUTE_FORCE'
        return 'VOLUMETRIC_SPIKE'
    else:  # NEGATIVE
        if severity in ('CRITICAL', 'WARNING'):
            return 'SLOW_EXFILTRATION'
        return 'BEACONING'


# ─── Alert builder ─────────────────────────────────────────────────────────────

def build_alert(window_result: dict, attack_type: str, severity: str, sk: float) -> dict:
    """
    Constructs the full alert context dict from a window result.
    This is what gets written to JSON/CSV and displayed in the terminal.
    """
    return {
        'timestamp':    window_result.get('timestamp'),
        'window_start': window_result.get('window_start'),
        'window_end':   window_result.get('window_end'),
        'mean':         window_result.get('mean'),
        'median':       window_result.get('median'),
        'std':          window_result.get('std'),
        'skewness':     sk,
        'alert_type':   attack_type,
        'severity':     severity,
        'n':            window_result.get('n'),
    }


# ─── Main alerter with cooldown ────────────────────────────────────────────────

def process_alerts(
    window_results: list[dict],
    threshold: float = 1.5,
    cooldown: int = DEFAULT_COOLDOWN
) -> list[dict]:
    """
    Processes all window results and returns only actionable alerts.

    threshold: minimum |skewness| to trigger any alert (overrides THRESHOLDS['WARNING'])
    cooldown:  number of consecutive windows to suppress after an alert fires

    Cooldown logic:
    - When an alert fires, set cooldown_counter = cooldown
    - Each subsequent window decrements the counter
    - While counter > 0, suppress alerts even if skew is still elevated
    - Counter resets if skew drops below INFO threshold (attack ended)
    - This ensures one alert per attack event, not one per window

    Why this matters:
    - A brute force attack lasting 10 minutes would otherwise produce ~10 alerts
    - Cooldown collapses that into 1 alert at the START of the attack
    - Without cooldown, SOC analysts get alert-fatigued and start ignoring them
    """
    alerts = []
    cooldown_counter = 0

    # Apply custom threshold by adjusting WARNING level
    # (INFO and CRITICAL stay fixed; user-supplied threshold replaces WARNING)
    effective_thresholds = THRESHOLDS.copy()
    effective_thresholds['WARNING'] = threshold

    for result in window_results:
        sk = result.get('pearson_skew')

        classification = classify_skew_with_threshold(sk, effective_thresholds)

        if classification is None:
            # Below all thresholds — attack has ended, reset cooldown
            cooldown_counter = 0
            continue

        severity  = classification['severity']
        direction = classification['direction']

        # Cooldown suppression
        if cooldown_counter > 0:
            cooldown_counter -= 1
            continue

        # Alert fires
        attack_type = classify_attack_type(direction, severity)
        alert = build_alert(result, attack_type, severity, sk)
        alerts.append(alert)

        # Start cooldown
        cooldown_counter = cooldown

    return alerts


def classify_skew_with_threshold(sk: float | None, thresholds: dict) -> dict | None:
    """
    Same as classify_skew() but uses a custom thresholds dict.
    Separated so process_alerts() can override WARNING threshold at runtime.
    """
    if sk is None:
        return None

    abs_sk = abs(sk)
    direction = 'POSITIVE' if sk > 0 else 'NEGATIVE'

    for severity in ['CRITICAL', 'WARNING', 'INFO']:
        if abs_sk >= thresholds[severity]:
            return {'severity': severity, 'direction': direction}

    return None


# ─── Summary stats ─────────────────────────────────────────────────────────────

def summarize_alerts(alerts: list[dict]) -> dict:
    """
    Returns a summary dict for the reporter/terminal output.
    """
    if not alerts:
        return {
            'total': 0,
            'critical': 0,
            'warning': 0,
            'info': 0,
            'brute_force': 0,
            'slow_exfiltration': 0,
            'other': 0,
        }

    return {
        'total':            len(alerts),
        'critical':         sum(1 for a in alerts if a['severity'] == 'CRITICAL'),
        'warning':          sum(1 for a in alerts if a['severity'] == 'WARNING'),
        'info':             sum(1 for a in alerts if a['severity'] == 'INFO'),
        'brute_force':      sum(1 for a in alerts if a['alert_type'] == 'BRUTE_FORCE'),
        'slow_exfiltration':sum(1 for a in alerts if a['alert_type'] == 'SLOW_EXFILTRATION'),
        'other':            sum(1 for a in alerts if a['alert_type'] not in ('BRUTE_FORCE', 'SLOW_EXFILTRATION')),
    }
