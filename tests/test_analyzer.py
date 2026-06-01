# tests/test_analyzer.py
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analyzer import pearson_median_skew, fisher_skew, compute_stats


class TestEdgeCases:
    def test_insufficient_data_returns_none(self):
        assert pearson_median_skew([]) is None
        assert pearson_median_skew([1]) is None
        assert pearson_median_skew([1, 2]) is None

    def test_flat_data_returns_zero(self):
        assert pearson_median_skew([5, 5, 5, 5, 5]) == 0.0

    def test_identical_values_no_nan(self):
        result = pearson_median_skew([100] * 20)
        assert result == 0.0
        assert result is not None


class TestSkewnessDirection:
    def test_right_skew_positive(self):
        # One spike in flat baseline — confirms correct positive direction
        data = [10]*9 + [500]
        sk = pearson_median_skew(data)
        assert sk is not None
        assert sk > 0.5, f"Expected right skew > 0.5, got {sk}"

    def test_left_skew_negative(self):
        # One drop in high baseline — confirms correct negative direction
        data = [100]*9 + [1]
        sk = pearson_median_skew(data)
        assert sk is not None
        assert sk < -0.5, f"Expected left skew < -0.5, got {sk}"

    def test_symmetric_near_zero(self):
        data = list(range(1, 21))
        sk = pearson_median_skew(data)
        assert sk is not None
        assert abs(sk) < 0.5

    def test_skew_can_reach_alert_threshold(self):
        # Verifies formula CAN produce values near alert thresholds
        # n=5 with extreme outlier gets ~1.34 — documents formula's real range
        data = [1, 1, 1, 1, 1000]
        sk = pearson_median_skew(data)
        assert sk is not None
        assert sk > 1.0, f"Expected sk > 1.0 for extreme outlier, got {sk}"


class TestComputeStats:
    def test_returns_all_keys(self):
        result = compute_stats([1, 2, 3, 4, 5])
        for key in ['mean', 'median', 'std', 'pearson_skew', 'fisher_skew', 'n']:
            assert key in result

    def test_insufficient_window_returns_nones(self):
        result = compute_stats([1, 2])
        assert result['mean'] is None
