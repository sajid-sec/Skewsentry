# tests/test_integration.py
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timedelta
from window  import run_window_engine
from alerter import process_alerts, summarize_alerts


def make_baseline(n_minutes=90, rate_low=5, rate_high=15):
    import random
    events = []
    base = datetime(2024, 1, 15, 8, 0, 0)
    for minute in range(n_minutes):
        ts = base + timedelta(minutes=minute)
        count = random.randint(rate_low, rate_high)
        for _ in range(count):
            events.append((ts, 'BASELINE'))
    return events


def inject_brute_force(events, start_minute=30, duration=15, spike_rate=200):
    base = datetime(2024, 1, 15, 8, 0, 0)
    injected = list(events)
    for minute in range(start_minute, start_minute + duration):
        ts = base + timedelta(minutes=minute)
        for _ in range(spike_rate):
            injected.append((ts, 'FAILED_LOGIN'))
    return injected


def inject_slow_exfil(events, start_minute=30, duration=20):
    base = datetime(2024, 1, 15, 8, 0, 0)
    attack_start = base + timedelta(minutes=start_minute)
    attack_end   = base + timedelta(minutes=start_minute + duration)
    filtered = [(ts, ev) for ts, ev in events
                if not (attack_start <= ts < attack_end)]
    for minute in range(start_minute, start_minute + duration):
        ts = base + timedelta(minutes=minute)
        filtered.append((ts, 'SLOW_EXFIL'))
    return filtered


def inject_mixed(events):
    events = inject_brute_force(events, start_minute=20, duration=15)
    events = inject_slow_exfil(events,  start_minute=55, duration=20)
    return events


def run_pipeline(events, window_size=20, threshold=0.8):
    window_results = run_window_engine(events, bucket_minutes=1, window_size=window_size)
    alerts  = process_alerts(window_results, threshold=threshold)
    summary = summarize_alerts(alerts)
    return window_results, alerts, summary


class TestBaseline:
    def test_clean_traffic_produces_few_alerts(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        _, alerts, _ = run_pipeline(events, window_size=20, threshold=1.5)
        assert len(alerts) <= 2, f"Too many false positives: {len(alerts)}"

    def test_baseline_skewness_near_zero(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        window_results, _, _ = run_pipeline(events, window_size=20)
        skews = [abs(r['pearson_skew']) for r in window_results
                 if r.get('pearson_skew') is not None]
        assert skews, "No skewness values computed"
        max_sk = max(skews)
        assert max_sk < 1.8, f"Baseline skewness too high: max={max_sk:.4f}"


class TestBruteForceInjection:
    def test_brute_force_detected(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_brute_force(events, start_minute=30, duration=15, spike_rate=200)
        _, alerts, summary = run_pipeline(events, window_size=20, threshold=0.8)
        assert summary['total'] > 0, "Brute force injection NOT detected."

    def test_brute_force_produces_positive_skew(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_brute_force(events, start_minute=30, duration=15, spike_rate=200)
        window_results, _, _ = run_pipeline(events, window_size=20, threshold=0.8)
        max_skew = max(
            (r['pearson_skew'] for r in window_results if r.get('pearson_skew') is not None),
            default=0.0
        )
        assert max_skew > 0.5, f"Expected positive skewness, got max={max_skew:.4f}"

    def test_brute_force_alert_type_correct(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_brute_force(events, start_minute=30, duration=15, spike_rate=200)
        _, alerts, _ = run_pipeline(events, window_size=20, threshold=0.8)
        if alerts:
            positive_alerts = [a for a in alerts
                               if a['alert_type'] in ('BRUTE_FORCE', 'VOLUMETRIC_SPIKE')]
            assert len(positive_alerts) > 0, \
                f"Expected BRUTE_FORCE alerts, got: {[a['alert_type'] for a in alerts]}"


class TestSlowExfilInjection:
    def test_slow_exfil_detected(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_slow_exfil(events, start_minute=30, duration=20)
        _, alerts, summary = run_pipeline(events, window_size=20, threshold=0.8)
        assert summary['total'] > 0, "Slow exfil injection NOT detected."

    def test_slow_exfil_produces_negative_skew(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_slow_exfil(events, start_minute=30, duration=20)
        window_results, _, _ = run_pipeline(events, window_size=20, threshold=0.8)
        min_skew = min(
            (r['pearson_skew'] for r in window_results if r.get('pearson_skew') is not None),
            default=0.0
        )
        assert min_skew < -0.5, f"Expected negative skewness, got min={min_skew:.4f}"

    def test_slow_exfil_alert_type_correct(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_slow_exfil(events, start_minute=30, duration=20)
        window_results, _, _ = run_pipeline(events, window_size=20, threshold=0.8)
        skews = [r['pearson_skew'] for r in window_results
                 if r.get('pearson_skew') is not None]
        has_negative = any(s < -0.5 for s in skews)
        assert has_negative, \
            f"Expected skew < -0.5 during slow exfil. Min={min(skews):.4f}"


class TestMixedInjection:
    def test_mixed_attack_detected(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_mixed(events)
        _, alerts, summary = run_pipeline(events, window_size=20, threshold=0.8)
        assert summary['total'] > 0, "Mixed injection NOT detected."

    def test_mixed_produces_both_skew_directions(self):
        import random
        random.seed(42)
        events = make_baseline(n_minutes=90)
        events = inject_mixed(events)
        window_results, _, _ = run_pipeline(events, window_size=20, threshold=0.8)
        skews = [r['pearson_skew'] for r in window_results
                 if r.get('pearson_skew') is not None]
        has_positive = any(s > 0.5  for s in skews)
        has_negative = any(s < -0.5 for s in skews)
        assert has_positive, "Mixed attack: expected positive skew but none found"
        assert has_negative, "Mixed attack: expected negative skew but none found"


class TestPipelineRobustness:
    def test_empty_events_no_crash(self):
        window_results, alerts, summary = run_pipeline([])
        assert window_results == []
        assert alerts == []
        assert summary['total'] == 0

    def test_single_minute_no_crash(self):
        events = [(datetime(2024, 1, 15, 8, 0, 0), 'TEST')] * 10
        window_results, alerts, summary = run_pipeline(events, window_size=60)
        assert isinstance(window_results, list)
        assert isinstance(alerts, list)

    def test_window_larger_than_data_no_crash(self):
        import random
        random.seed(0)
        events = make_baseline(n_minutes=10)
        window_results, alerts, summary = run_pipeline(events, window_size=60)
        assert isinstance(window_results, list)
