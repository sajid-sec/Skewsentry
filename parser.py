# parser.py
import re
import csv
from datetime import datetime


# ─── Regex patterns ────────────────────────────────────────────────────────────

# Apache / Nginx combined log format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<bytes>\S+)'
)

# SSH auth.log (syslog format):
# Jun  1 14:23:01 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
SSH_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\S+) '
    r'\S+ sshd\[\d+\]: (?P<msg>.+)'
)

# ─── Timestamp parsers ─────────────────────────────────────────────────────────

def _parse_apache_time(raw: str) -> datetime | None:
    """
    Converts Apache time string to datetime.
    Input format: '10/Oct/2000:13:55:36 -0700'
    We strip the timezone offset — treat all as naive local time.
    """
    try:
        # Strip timezone offset before parsing
        raw_stripped = raw.split(' ')[0]  # '10/Oct/2000:13:55:36'
        return datetime.strptime(raw_stripped, '%d/%b/%Y:%H:%M:%S')
    except ValueError:
        return None


def _parse_ssh_time(month: str, day: str, time_str: str) -> datetime | None:
    """
    Converts SSH auth.log time fields to datetime.
    Assumes current year (syslog doesn't include year).
    Input: month='Jun', day='1', time_str='14:23:01'
    """
    try:
        current_year = datetime.now().year
        raw = f"{month} {day.zfill(2)} {time_str} {current_year}"
        return datetime.strptime(raw, '%b %d %H:%M:%S %Y')
    except ValueError:
        return None


# ─── Event type classifiers ────────────────────────────────────────────────────

def _classify_apache_event(method: str, status: str) -> str:
    """
    Returns a human-readable event type from Apache method + status code.
    """
    status_int = int(status)
    if status_int == 200 and method == 'GET':
        return 'GET_OK'
    elif status_int == 200 and method == 'POST':
        return 'POST_OK'
    elif status_int in (401, 403):
        return 'AUTH_FAIL'
    elif status_int == 404:
        return 'NOT_FOUND'
    elif status_int >= 500:
        return 'SERVER_ERROR'
    else:
        return f'{method}_{status}'


def _classify_ssh_event(msg: str) -> str:
    """
    Returns event type from SSH log message content.
    """
    msg_lower = msg.lower()
    if 'failed password' in msg_lower:
        return 'FAILED_LOGIN'
    elif 'accepted password' in msg_lower or 'accepted publickey' in msg_lower:
        return 'SUCCESSFUL_LOGIN'
    elif 'invalid user' in msg_lower:
        return 'INVALID_USER'
    elif 'connection closed' in msg_lower or 'disconnected' in msg_lower:
        return 'DISCONNECT'
    else:
        return 'SSH_OTHER'


# ─── Main parsers ──────────────────────────────────────────────────────────────

def parse_apache(filepath: str) -> list[tuple[datetime, str]]:
    """
    Parses Apache/Nginx combined log format.
    Returns list of (datetime, event_type) tuples.
    Skips malformed lines silently.
    """
    events = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = APACHE_RE.match(line.strip())
            if not match:
                continue
            ts = _parse_apache_time(match.group('time'))
            if ts is None:
                continue
            event_type = _classify_apache_event(
                match.group('method'),
                match.group('status')
            )
            events.append((ts, event_type))
    return events


def parse_ssh(filepath: str) -> list[tuple[datetime, str]]:
    """
    Parses SSH auth.log (syslog format).
    Only processes lines containing 'sshd' — skips cron, sudo, etc.
    Returns list of (datetime, event_type) tuples.
    """
    events = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = SSH_RE.match(line.strip())
            if not match:
                continue
            ts = _parse_ssh_time(
                match.group('month'),
                match.group('day'),
                match.group('time')
            )
            if ts is None:
                continue
            event_type = _classify_ssh_event(match.group('msg'))
            events.append((ts, event_type))
    return events


def parse_csv(filepath: str) -> list[tuple[datetime, str]]:
    """
    CSV fallback parser for synthetic/custom data.
    Expected columns: timestamp, event_count (or event_type)
    timestamp format: ISO 8601 — '2024-01-15 14:32:00' or '2024-01-15T14:32:00'
    If event_count column exists, repeats a 'CSV_EVENT' entry that many times.
    If event_type column exists, uses that directly.
    """
    events = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize column names to lowercase
            row = {k.lower().strip(): v.strip() for k, v in row.items()}

            # Parse timestamp
            ts_raw = row.get('timestamp') or row.get('time') or row.get('datetime')
            if ts_raw is None:
                continue
            ts = None
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M'):
                try:
                    ts = datetime.strptime(ts_raw, fmt)
                    break
                except ValueError:
                    continue
            if ts is None:
                continue

            # Get event type or count
            if 'event_type' in row:
                events.append((ts, row['event_type'].upper()))
            elif 'event_count' in row:
                try:
                    count = int(row['event_count'])
                    for _ in range(count):
                        events.append((ts, 'CSV_EVENT'))
                except ValueError:
                    continue
            else:
                # Just record the timestamp as a generic event
                events.append((ts, 'CSV_EVENT'))

    return events


# ─── Auto-detect format ────────────────────────────────────────────────────────

def auto_detect_format(filepath: str) -> str:
    """
    Reads first 5 non-empty lines and guesses the log format.
    Returns: 'apache', 'ssh', or 'csv'
    """
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [f.readline().strip() for _ in range(5)]

    for line in lines:
        if not line:
            continue
        if APACHE_RE.match(line):
            return 'apache'
        if SSH_RE.match(line):
            return 'ssh'
        if ',' in line:
            return 'csv'

    return 'csv'  # default fallback


def parse_log(filepath: str, fmt: str = 'auto') -> list[tuple[datetime, str]]:
    """
    Main entry point. Call this from skewsentry.py.
    fmt: 'apache', 'ssh', 'csv', or 'auto'
    Returns list of (datetime, event_type) tuples sorted by time.
    """
    if fmt == 'auto':
        fmt = auto_detect_format(filepath)

    if fmt == 'apache':
        events = parse_apache(filepath)
    elif fmt == 'ssh':
        events = parse_ssh(filepath)
    elif fmt == 'csv':
        events = parse_csv(filepath)
    else:
        raise ValueError(f"Unknown format: {fmt}. Use 'apache', 'ssh', or 'csv'.")

    # Always return sorted by timestamp
    return sorted(events, key=lambda x: x[0])
