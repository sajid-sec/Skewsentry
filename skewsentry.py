#!/usr/bin/env python3
# skewsentry.py — main entry point
"""
SkewSentry: Statistical Log Anomaly Detector
Uses Pearson's skewness to detect brute-force attacks and slow exfiltration
in Apache/Nginx access logs and SSH auth.log files.

Usage examples:
  python3 skewsentry.py /var/log/auth.log --format ssh
  python3 skewsentry.py access.log --format apache --window 30 --threshold 1.5
  python3 skewsentry.py access.log --output json --outfile alerts.json
  python3 skewsentry.py --generate-sample --attack brute_force --outfile demo.csv
  python3 skewsentry.py demo.csv --format csv --plot --verbose
"""

import argparse
import sys
import os
import json
import csv as csv_module
import random
from datetime import datetime, timedelta

from parser  import parse_log
from window  import run_window_engine
from alerter import process_alerts, summarize_alerts


# ─── Sample log generator ─────────────────────────────────────────────────────

def generate_sample(attack_type: str, outfile: str, duration_minutes: int = 120):
    """
    Generates a synthetic CSV log file with realistic baseline + attack pattern.

    attack_type options:
    - brute_force:       sudden spike in failed logins (right skew)
    - slow_exfiltration: sustained drop in normal traffic (left skew)
    - normal:            clean baseline with no anomalies

    Output format: timestamp,event_count
    This is essential for demos, README, and testing without real log access.
    """
    rows = []
    base_time = datetime(2024, 1, 15, 8, 0, 0)

    for minute in range(duration_minutes):
        ts = base_time + timedelta(minutes=minute)
        # Baseline: 5-15 events per minute (normal web traffic)
        count = random.randint(5, 15)

        if attack_type == 'brute_force':
            # Attack window: minutes 60-75 — massive spike
            if 60 <= minute <= 75:
                count = random.randint(150, 300)

        elif attack_type == 'slow_exfiltration':
            # Attack window: minutes 60-90 — traffic drops to near zero
            if 60 <= minute <= 90:
                count = random.randint(0, 2)

        rows.append({'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'), 'event_count': count})

    with open(outfile, 'w', newline='') as f:
        writer = csv_module.DictWriter(f, fieldnames=['timestamp', 'event_count'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Generated {duration_minutes}-minute '{attack_type}' sample → {outfile}")
    print(f"    {duration_minutes} rows, attack window embedded in minutes 60-75/90")


# ─── Output writers ───────────────────────────────────────────────────────────

def write_json(alerts: list[dict], summary: dict, outfile: str):
    """Writes alerts + summary to a JSON file."""
    output = {
        'summary': summary,
        'alerts':  [
            {k: str(v) if isinstance(v, datetime) else v for k, v in a.items()}
            for a in alerts
        ]
    }
    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"[+] JSON output written to {outfile}")


def write_csv_output(alerts: list[dict], outfile: str):
    """Writes alerts to a CSV file."""
    if not alerts:
        print("[!] No alerts to write.")
        return
    with open(outfile, 'w', newline='') as f:
        writer = csv_module.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows([
            {k: str(v) if isinstance(v, datetime) else v for k, v in a.items()}
            for a in alerts
        ])
    print(f"[+] CSV output written to {outfile}")


def print_terminal(alerts: list[dict], summary: dict, verbose: bool, window_results: list[dict]):
    """
    Plain terminal output (no rich yet — that's Step 08).
    Verbose mode prints every window result, not just alerts.
    """
    print("\n" + "="*60)
    print("  SKEWSENTRY — ANOMALY DETECTION RESULTS")
    print("="*60)

    if verbose:
        print(f"\n[VERBOSE] Total windows analyzed: {len(window_results)}")
        for r in window_results:
            sk = r.get('pearson_skew')
            sk_str = f"{sk:.4f}" if sk is not None else "N/A"
            print(f"  {r['timestamp']}  sk={sk_str:>8}  mean={r['mean']:.1f}  n={r['n']}")

    print(f"\n[SUMMARY]")
    print(f"  Total alerts   : {summary['total']}")
    print(f"  Critical       : {summary['critical']}")
    print(f"  Warning        : {summary['warning']}")
    print(f"  Info           : {summary['info']}")
    print(f"  Brute Force    : {summary['brute_force']}")
    print(f"  Slow Exfil     : {summary['slow_exfiltration']}")

    if not alerts:
        print("\n[OK] No anomalies detected. Traffic appears normal.")
        return

    print(f"\n[ALERTS]")
    for a in alerts:
        ts  = a['timestamp']
        sev = a['severity']
        atype = a['alert_type']
        sk  = a['skewness']
        indicator = {'CRITICAL': '[!!!]', 'WARNING': '[!! ]', 'INFO': '[!  ]'}.get(sev, '[?]')
        print(f"  {indicator} {ts}  {sev:<8}  {atype:<20}  sk={sk:.4f}")

    print("="*60 + "\n")


# ─── Argument parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='skewsentry',
        description='Statistical log anomaly detector using Pearson skewness.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 skewsentry.py /var/log/auth.log --format ssh
  python3 skewsentry.py access.log --format apache --window 30 --threshold 1.5
  python3 skewsentry.py access.log --output json --outfile alerts.json --verbose
  python3 skewsentry.py access.log --plot
  python3 skewsentry.py --generate-sample --attack brute_force --outfile demo.csv
  python3 skewsentry.py demo.csv --format csv --plot
        """
    )

    # Positional — optional because --generate-sample doesn't need a logfile
    parser.add_argument(
        'logfile',
        nargs='?',
        help='Path to log file to analyze (Apache, Nginx, SSH auth.log, or CSV)'
    )

    # Format
    parser.add_argument(
        '--format', '-f',
        choices=['apache', 'ssh', 'csv', 'auto'],
        default='auto',
        help='Log format (default: auto-detect)'
    )

    # Window parameters
    parser.add_argument(
        '--window', '-w',
        type=int,
        default=60,
        metavar='INT',
        help='Sliding window size in minutes (default: 60)'
    )
    parser.add_argument(
        '--step',
        type=int,
        default=1,
        metavar='INT',
        help='Window step size in minutes (default: 1)'
    )

    # Alert threshold
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=1.5,
        metavar='FLOAT',
        help='Skewness threshold for WARNING alerts (default: 1.5)'
    )

    # Output format
    parser.add_argument(
        '--output', '-o',
        choices=['terminal', 'json', 'csv'],
        default='terminal',
        help='Output format (default: terminal)'
    )
    parser.add_argument(
        '--outfile',
        metavar='PATH',
        help='Output file path for --output json/csv, or sample file for --generate-sample'
    )

    # Flags
    parser.add_argument(
        '--plot',
        action='store_true',
        help='Show matplotlib chart of traffic and skewness over time (Step 09)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print every window result, not just alerts'
    )

    # Sample generator
    parser.add_argument(
        '--generate-sample',
        action='store_true',
        help='Generate a synthetic log file instead of analyzing one'
    )
    parser.add_argument(
        '--attack',
        choices=['brute_force', 'slow_exfiltration', 'normal'],
        default='brute_force',
        help='Attack type to embed in generated sample (default: brute_force)'
    )

    return parser


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── Mode 1: Generate sample log ──────────────────────────────────────────
    if args.generate_sample:
        outfile = args.outfile or f"sample_{args.attack}.csv"
        generate_sample(attack_type=args.attack, outfile=outfile)
        sys.exit(0)

    # ── Mode 2: Analyze log file ─────────────────────────────────────────────
    if not args.logfile:
        parser.error("logfile is required unless --generate-sample is used.")

    if not os.path.exists(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing: {args.logfile}  (format={args.format})")
    events = parse_log(args.logfile, fmt=args.format)

    if not events:
        print("[!] No events parsed. Check file format or use --format explicitly.")
        sys.exit(1)

    print(f"[*] Parsed {len(events)} events. Running window engine "
          f"(window={args.window}min, step={args.step}min)...")

    window_results = run_window_engine(
        events,
        bucket_minutes=1,
        window_size=args.window,
        step_size=args.step
    )

    if not window_results:
        print("[!] Not enough data to fill a single window. "
              f"Need at least {args.window} minutes of logs. "
              "Try --window with a smaller value.")
        sys.exit(1)

    print(f"[*] Analyzed {len(window_results)} windows. Running alert classifier "
          f"(threshold={args.threshold})...")

    alerts  = process_alerts(window_results, threshold=args.threshold)
    summary = summarize_alerts(alerts)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.output == 'json':
        outfile = args.outfile or 'alerts.json'
        write_json(alerts, summary, outfile)

    elif args.output == 'csv':
        outfile = args.outfile or 'alerts.csv'
        write_csv_output(alerts, outfile)

    else:  # terminal
        print_terminal(alerts, summary, args.verbose, window_results)

    # ── Plot (placeholder until Step 09) ─────────────────────────────────────
    if args.plot:
        print("[!] --plot requires Step 09 (visualizer.py). Coming soon.")

    return 0


if __name__ == '__main__':
    sys.exit(main())
