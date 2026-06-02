# window.py
from collections import deque, defaultdict
from datetime import datetime, timedelta
from analyzer import compute_stats


# ─── Step 1: Time-bucket aggregation ──────────────────────────────────────────

def bucket_events(
    events: list[tuple[datetime, str]],
    bucket_minutes: int = 1
) -> list[tuple[datetime, int]]:
    """
    Bins raw (datetime, event_type) events into fixed-size time buckets.
    Returns list of (bucket_start_time, event_count) sorted by time.

    Why bucketing first:
    - Raw events are irregular in time — one second may have 50 events, the next zero.
    - Skewness needs a numeric series of counts, not raw timestamps.
    - Bucketing converts irregular events → regular time series.

    bucket_minutes=1 means each bucket = 1 minute of activity.
    """
    if not events:
        return []

    # Count events per bucket
    bucket_counts: dict[datetime, int] = defaultdict(int)

    for ts, event_type in events:
        # Floor timestamp to nearest bucket boundary
        # e.g. 14:23:47 with bucket_minutes=1 → 14:23:00
        floored = ts.replace(
            second=0,
            microsecond=0,
            minute=(ts.minute // bucket_minutes) * bucket_minutes
        )
        bucket_counts[floored] += 1

    # Fill gaps: if no events in a minute, count = 0
    # This is critical — a sudden silence IS anomalous (slow exfil signature)
    sorted_times = sorted(bucket_counts.keys())
    start = sorted_times[0]
    end = sorted_times[-1]

    filled: list[tuple[datetime, int]] = []
    current = start
    delta = timedelta(minutes=bucket_minutes)

    while current <= end:
        filled.append((current, bucket_counts.get(current, 0)))
        current += delta

    return filled


# ─── Step 2: Sliding window over buckets ──────────────────────────────────────

def sliding_window(
    bucketed: list[tuple[datetime, int]],
    window_size: int = 60,
    step_size: int = 1
):
    """
    Slides a fixed-size window across the bucketed time series.
    Yields one result dict per window position.

    window_size: number of buckets per window (default 60 = 60 minutes of data)
    step_size:   how many buckets to advance per step (default 1 = slide one minute)

    Why deque(maxlen=window_size):
    - Memory efficient: old buckets are automatically dropped when window advances
    - No need to keep the entire log in RAM — only the current window lives in memory
    - Critical for large log files (GB+)

    Each yielded dict contains:
    - timestamp:    end time of this window
    - window_start: start time of this window
    - window_end:   end time of this window
    - counts:       raw list of event counts in this window
    - mean, median, std, pearson_skew, fisher_skew, n: from compute_stats()
    """
    if len(bucketed) < window_size:
        # Not enough data to fill even one window
        # Still process what we have — useful for short test logs
        window_size = len(bucketed)

    if window_size < 3:
        return  # compute_stats needs at least 3 points

    # deque automatically evicts oldest bucket when maxlen is reached
    window: deque = deque(maxlen=window_size)
    # Track corresponding timestamps
    time_window: deque = deque(maxlen=window_size)

    for i, (bucket_time, count) in enumerate(bucketed):
        window.append(count)
        time_window.append(bucket_time)

        # Only compute once window is full
        if len(window) < window_size:
            continue

        # Slide: only compute every step_size buckets
        if (i - window_size + 1) % step_size != 0:
            continue

        stats = compute_stats(list(window))
        stats['timestamp']    = bucket_time          # end of window
        stats['window_start'] = time_window[0]       # start of window
        stats['window_end']   = bucket_time          # same as timestamp
        stats['counts']       = list(window)         # raw counts (for visualizer)

        yield stats


# ─── Step 3: Main entry point ──────────────────────────────────────────────────

def run_window_engine(
    events: list[tuple[datetime, str]],
    bucket_minutes: int = 1,
    window_size: int = 60,
    step_size: int = 1
) -> list[dict]:
    """
    Full pipeline: raw events → bucketed series → sliding window results.
    Returns a list of window result dicts (not a generator) for easier downstream use.

    Call this from skewsentry.py with events from parse_log().
    """
    bucketed = bucket_events(events, bucket_minutes=bucket_minutes)

    if not bucketed:
        return []

    results = list(sliding_window(bucketed, window_size=window_size, step_size=step_size))
    return results
