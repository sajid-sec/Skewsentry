# tests/test_parser.py
import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from parser import parse_apache, parse_ssh, parse_csv, auto_detect_format, parse_log


# ─── Sample raw log lines ──────────────────────────────────────────────────────

APACHE_SAMPLE = """\
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
192.168.1.1 - - [10/Oct/2000:13:56:01 -0700] "POST /login HTTP/1.1" 401 512
10.0.0.1 - - [10/Oct/2000:13:56:45 -0700] "GET /secret HTTP/1.1" 403 128
this is a malformed line that should be skipped
"""

SSH_SAMPLE = """\
Jun  1 14:23:01 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
Jun  1 14:23:05 hostname sshd[1235]: Failed password for admin from 1.2.3.4 port 22 ssh2
Jun  1 14:24:10 hostname sshd[1236]: Accepted password for sajid from 5.6.7.8 port 22 ssh2
Jun  1 14:25:00 hostname sudo[999]: sajid ran a command
"""

CSV_SAMPLE = """\
timestamp,event_count
2024-01-15 14:00:00,5
2024-01-15 14:01:00,3
2024-01-15 14:02:00,10
"""

CSV_TYPED_SAMPLE = """\
timestamp,event_type
2024-01-15 14:00:00,FAILED_LOGIN
2024-01-15 14:01:00,GET_OK
"""


def _write_temp(content: str, suffix: str) -> str:
    """Write content to a temp file, return path."""
    f = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


class TestApacheParser:
    def test_parses_correct_count(self):
        path = _write_temp(APACHE_SAMPLE, '.log')
        events = parse_apache(path)
        assert len(events) == 3  # malformed line skipped

    def test_event_types_correct(self):
        path = _write_temp(APACHE_SAMPLE, '.log')
        events = parse_apache(path)
        types = [e[1] for e in events]
        assert 'GET_OK' in types
        assert 'AUTH_FAIL' in types

    def test_returns_sorted_by_time(self):
        path = _write_temp(APACHE_SAMPLE, '.log')
        events = parse_apache(path)
        times = [e[0] for e in events]
        assert times == sorted(times)


class TestSSHParser:
    def test_parses_sshd_lines_only(self):
        path = _write_temp(SSH_SAMPLE, '.log')
        events = parse_ssh(path)
        # sudo line should be excluded (no sshd match)
        assert len(events) == 3

    def test_failed_login_detected(self):
        path = _write_temp(SSH_SAMPLE, '.log')
        events = parse_ssh(path)
        types = [e[1] for e in events]
        assert types.count('FAILED_LOGIN') == 2

    def test_successful_login_detected(self):
        path = _write_temp(SSH_SAMPLE, '.log')
        events = parse_ssh(path)
        types = [e[1] for e in events]
        assert 'SUCCESSFUL_LOGIN' in types


class TestCSVParser:
    def test_event_count_expansion(self):
        path = _write_temp(CSV_SAMPLE, '.csv')
        events = parse_csv(path)
        # 5 + 3 + 10 = 18 events total
        assert len(events) == 18

    def test_event_type_column(self):
        path = _write_temp(CSV_TYPED_SAMPLE, '.csv')
        events = parse_csv(path)
        assert len(events) == 2
        assert events[0][1] == 'FAILED_LOGIN'


class TestAutoDetect:
    def test_detects_apache(self):
        path = _write_temp(APACHE_SAMPLE, '.log')
        assert auto_detect_format(path) == 'apache'

    def test_detects_ssh(self):
        path = _write_temp(SSH_SAMPLE, '.log')
        assert auto_detect_format(path) == 'ssh'

    def test_detects_csv(self):
        path = _write_temp(CSV_SAMPLE, '.csv')
        assert auto_detect_format(path) == 'csv'
