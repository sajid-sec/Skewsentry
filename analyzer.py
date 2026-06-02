# analyzer.py
import numpy as np
from scipy import stats


def pearson_median_skew(data: list) -> float | None:
    """
    Pearson's second skewness coefficient: 3*(mean - median) / std
    Uses sample std (ddof=1). Returns None if insufficient data, 0.0 if flat.
    """
    if len(data) < 3:
        return None
    mean = np.mean(data)
    median = np.median(data)
    std = np.std(data, ddof=1)   # ddof=1 = sample std, NOT population std
    if std == 0:
        return 0.0               # Flat traffic — no skew, not NaN
    return 3 * (mean - median) / std


def pearson_mode_skew(data: list) -> float | None:
    """
    Pearson's first skewness coefficient: (mean - mode) / std
    Less reliable on continuous/noisy data — prefer median method.
    """
    if len(data) < 3:
        return None
    mean = np.mean(data)
    std = np.std(data, ddof=1)
    if std == 0:
        return 0.0
    # np has no mode — use scipy
    mode_result = stats.mode(data, keepdims=True)
    mode_val = mode_result.mode[0]
    return (mean - mode_val) / std


def fisher_skew(data: list) -> float | None:
    """
    Fisher's moment-based skewness (scipy.stats.skew).
    Different formula from Pearson — gives different numbers.
    Used for comparison only.
    """
    if len(data) < 3:
        return None

    if float(np.std(data, ddof=1)) ==0:
        return 0.0
    return float(stats.skew(data, bias=False))  # bias=False = sample correction


def compute_stats(data: list) -> dict:
    """
    Compute all statistics for a single window.
    Returns a dict with all values needed by alerter and visualizer.
    """
    if len(data) < 3:
        return {
            'mean': None, 'median': None, 'std': None,
            'pearson_skew': None, 'fisher_skew': None, 'n': len(data)
        }
    return {
        'mean':          float(np.mean(data)),
        'median':        float(np.median(data)),
        'std':           float(np.std(data, ddof=1)),
        'pearson_skew':  pearson_median_skew(data),
        'fisher_skew':   fisher_skew(data),
        'n':             len(data)
    }


