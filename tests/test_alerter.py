# tests/test_alerter.py
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime
from alerter import (
    classify_skew, classify_attack_type, process_alerts,
    summarize_alerts, build_alert, THRESHOLDS
)


# ─── Helper ───────────────────────────────────────────────────────────────────

def make_window(sk: float, ts=None) -> dict:
    """Minimal window result dict for testing."""
    if ts is None:
        ts = datetime(2024, 1, 15, 14, 0, 0)
    return {
        'timestamp':    ts,
        'window_start': ts,
        'window_end':   ts,
        'mean':         10.0,
        'median':       10.0,
        'std':          2.0,
        'pearson_skew': sk,
        'fisher_skew':  sk,
        'n':            60,
        'counts':       [10] * 60,
    }


class TestClassifySkew:
    def test_none_input_returns_none(self):
        assert classify_skew(None) is None

    def test_below_info_returns_none(self):
        assert classify_skew(0.5) is None
        assert classify_skew(-0.5) is None
        assert classify_skew(0.0) is None

    def test_info_threshold(self):
        result = classify_skew(1.0)
        assert result is not None
        assert result['severity'] == 'INFO'

    def test_warning_threshold(self):
        result = classify_skew(1.5)
        assert result is not None
        assert result['severity'] == 'WARNING'

    def test_critical_threshold(self):
        result = classify_skew(2.5)
        assert result is not None
        assert result['severity'] == 'CRITICAL'

    def test_positive_direction(self):
        result = classify_skew(1.5)
        assert result['direction'] == 'POSITIVE'

    def test_negative_direction(self):
        result = classify_skew(-1.5)
        assert result['direction'] == 'NEGATIVE'

    def test_boundary_exactly_at_threshold(self):
        result = classify_skew(1.5)
        assert result['severity'] == 'WARNING'


class TestClassifyAttackType:
    def test_positive_critical_is_brute_force(self):
        assert classify_attack_type('POSITIVE', 'CRITICAL') == 'BRUTE_FORCE'

    def test_positive_warning_is_brute_force(self):
        assert classify_attack_type('POSITIVE', 'WARNING') == 'BRUTE_FORCE'

    def test_positive_info_is_volumetric_spike(self):
        assert classify_attack_type('POSITIVE', 'INFO') == 'VOLUMETRIC_SPIKE'

    def test_negative_critical_is_slow_exfil(self):
        assert classify_attack_type('NEGATIVE', 'CRITICAL') == 'SLOW_EXFILTRATION'

    def test_negative_info_is_beaconing(self):
        assert classify_attack_type('NEGATIVE', 'INFO') == 'BEACONING'


class TestProcessAlerts:
    def test_no_alerts_on_normal_traffic(self):
        windows = [make_window(0.3) for _ in range(20)]
        alerts = process_alerts(windows)
        assert alerts == []

    def test_single_spike_produces_one_alert(self):
        windows = [make_window(0.3)] * 5 + [make_window(2.0)] + [make_window(0.3)] * 5
        alerts = process_alerts(windows)
        assert len(alerts) == 1
        assert alerts[0]['severity'] == 'WARNING'  # 2.0 is between 1.5 and 2.5

    def test_cooldown_suppresses_consecutive_alerts(self):
        # 10 consecutive windows above threshold, cooldown=5
        # Window 0 fires, 1-5 suppressed, window 6 fires again = 2 alerts
        windows = [make_window(2.0)] * 10
        alerts = process_alerts(windows, cooldown=5)
        assert len(alerts) == 2

    def test_cooldown_resets_after_normal_traffic(self):
        # Spike → normal (longer than cooldown) → spike = 2 alerts
        spike  = [make_window(2.0)]
        normal = [make_window(0.3)] * 10
        windows = spike + normal + spike
        alerts = process_alerts(windows, cooldown=5)
        assert len(alerts) == 2

    def test_alert_has_required_keys(self):
        windows = [make_window(2.0)]
        alerts = process_alerts(windows)
        assert len(alerts) == 1
        for key in ['timestamp', 'window_start', 'window_end',
                    'mean', 'median', 'std', 'skewness',
                    'alert_type', 'severity', 'n']:
            assert key in alerts[0], f"Missing key: {key}"

    def test_custom_threshold_respected(self):
        # threshold=2.0 replaces WARNING, INFO (1.0) still active
        # skew of 0.8 is below INFO threshold → no alert
        windows = [make_window(0.8)]
        alerts = process_alerts(windows, threshold=2.0)
        assert len(alerts) == 0

    def test_negative_skew_produces_exfil_alert(self):
        windows = [make_window(-2.0)]
        alerts = process_alerts(windows)
        assert len(alerts) == 1
        assert alerts[0]['alert_type'] == 'SLOW_EXFILTRATION'


class TestSummarizeAlerts:
    def test_empty_alerts(self):
        summary = summarize_alerts([])
        assert summary['total'] == 0

    def test_counts_severities(self):
        alerts = [
            {'severity': 'CRITICAL', 'alert_type': 'BRUTE_FORCE'},
            {'severity': 'WARNING',  'alert_type': 'BRUTE_FORCE'},
            {'severity': 'INFO',     'alert_type': 'BEACONING'},
        ]
        summary = summarize_alerts(alerts)
        assert summary['total'] == 3
        assert summary['critical'] == 1
        assert summary['warning'] == 1
        assert summary['info'] == 1
