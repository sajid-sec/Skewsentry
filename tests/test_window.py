# tests/test_window.py
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timedelta
from window import bucket_events, sliding_window, run_window_engine


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_events(counts_per_minute: list[int], start_hour: int = 10) -> list:
    """
    Helper: given a list like [5, 3, 10, 2, ...],
    generates that many events per minute starting from start_hour:00.
    Returns list of (datetime, event_type) tuples.
    """
    events = []
    base = datetime(2024, 1, 15, start_hour, 0, 0)
    for minute_offset, count in enumerate(counts_per_minute):
        ts = base + timedelta(minutes=minute_offset)
        for _ in range(count):
            events.append((ts, 'TEST_EVENT'))
    return events


class TestBucketEvents:
    def test_empty_input_returns_empty(self):
        assert bucket_events([]) == []

    def test_correct_bucket_count(self):
        # 5 minutes of events → 5 buckets
        events = make_events([1, 2, 3, 4, 5])
        buckets = bucket_events(events)
        assert len(buckets) == 5

    def test_counts_match_input(self):
        counts_in = [3, 7, 2, 10, 1]
        events = make_events(counts_in)
        buckets = bucket_events(events)
        counts_out = [c for _, c in buckets]
        assert counts_out == counts_in

    def test_gap_filling(self):
        # Minute 0: 5 events, Minute 1: 0 events, Minute 2: 3 events
        base = datetime(2024, 1, 15, 10, 0, 0)
        events = []
        for _ in range(5):
            events.append((base, 'TEST'))
        for _ in range(3):
            events.append((base + timedelta(minutes=2), 'TEST'))
        buckets = bucket_events(events)
        # Should have 3 buckets: [5, 0, 3]
        assert len(buckets) == 3
        counts = [c for _, c in buckets]
        assert counts == [5, 0, 3]

    def test_sorted_by_time(self):
        events = make_events([1, 2, 3, 4, 5])
        buckets = bucket_events(events)
        times = [t for t, _ in buckets]
        assert times == sorted(times)


class TestSlidingWindow:
    def test_yields_correct_number_of_windows(self):
        # 10 buckets, window_size=5, step=1 → should yield 6 windows
        # (positions 0-4, 1-5, 2-6, 3-7, 4-8, 5-9)
        events = make_events([1]*10)
        buckets = bucket_events(events)
        results = list(sliding_window(buckets, window_size=5, step_size=1))
        assert len(results) == 6

    def test_result_has_required_keys(self):
        events = make_events([1]*10)
        buckets = bucket_events(events)
        results = list(sliding_window(buckets, window_size=5, step_size=1))
        required = ['timestamp', 'window_start', 'window_end',
                    'counts', 'mean', 'median', 'std', 'pearson_skew', 'n']
        for key in required:
            assert key in results[0], f"Missing key: {key}"

    def test_window_start_before_end(self):
        events = make_events([1]*10)
        buckets = bucket_events(events)
        results = list(sliding_window(buckets, window_size=5, step_size=1))
        for r in results:
            assert r['window_start'] < r['window_end']

    def test_insufficient_data_returns_empty(self):
        # Only 2 buckets, need at least 3
        events = make_events([5, 3])
        buckets = bucket_events(events)
        results = list(sliding_window(buckets, window_size=60, step_size=1))
        assert results == []

    def test_detects_spike_in_window(self):
        # 9 normal minutes + 1 spike minute
        counts = [10]*9 + [500]
        events = make_events(counts)
        buckets = bucket_events(events)
        results = list(sliding_window(buckets, window_size=10, step_size=1))
        # Last window should show positive skew
        last = results[-1]
        assert last['pearson_skew'] is not None
        assert last['pearson_skew'] > 0


class TestRunWindowEngine:
    def test_empty_events_returns_empty(self):
        assert run_window_engine([]) == []

    def test_returns_list_not_generator(self):
        events = make_events([1]*10)
        result = run_window_engine(events, window_size=5)
        assert isinstance(result, list)

    def test_pipeline_end_to_end(self):
        # Full pipeline: events → buckets → windows → stats
        counts = [5]*20 + [200]  # 20 normal + 1 spike
        events = make_events(counts)
        results = run_window_engine(events, window_size=10, step_size=1)
        assert len(results) > 0
        # The window containing the spike should show positive skew
        last = results[-1]
        assert last['pearson_skew'] is not None
        assert last['pearson_skew'] > 0
