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

from parser   import parse_log
from window   import run_window_engine
from alerter  import process_alerts, summarize_alerts
from reporter import print_rich_terminal, make_progress, console


# ─── Sample log generator ─────────────────────────────────────────────────────

def generate_sample(attack_type: str, outfile: str, duration_minutes: int = 120):
    """
    Generates a synthetic CSV log file with realistic baseline + attack pattern.

    attack_type options:
    - brute_force:       sudden spike in failed logins (right skew)
    - slow_exfiltration: sustained drop in normal traffic (left skew)
    - normal:            clean baseline with no anomalies

    Output format: timestamp,event_count
    """
    rows = []
    base_time = datetime(2024, 1, 15, 8, 0, 0)

    for minute in range(duration_minutes):
        ts = base_time + timedelta(minutes=minute)
        count = random.randint(5, 15)

        if attack_type == 'brute_force':
            if 60 <= minute <= 75:
                count = random.randint(150, 300)

        elif attack_type == 'slow_exfiltration':
            if 60 <= minute <= 90:
                count = random.randint(0, 2)

        rows.append({'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'), 'event_count': count})

    with open(outfile, 'w', newline='') as f:
        writer = csv_module.DictWriter(f, fieldnames=['timestamp', 'event_count'])
        writer.writeheader()
        writer.writerows(rows)

    console.print(f"[bold green][+][/bold green] Generated {duration_minutes}-minute "
                  f"'[cyan]{attack_type}[/cyan]' sample → [cyan]{outfile}[/cyan]")
    console.print(f"    {duration_minutes} rows, attack window embedded in minutes 60-75/90")


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
    console.print(f"[bold green][+][/bold green] JSON output written to [cyan]{outfile}[/cyan]")


def write_csv_output(alerts: list[dict], outfile: str):
    """Writes alerts to a CSV file."""
    if not alerts:
        console.print("[bold yellow][!] No alerts to write.[/bold yellow]")
        return
    with open(outfile, 'w', newline='') as f:
        writer = csv_module.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows([
            {k: str(v) if isinstance(v, datetime) else v for k, v in a.items()}
            for a in alerts
        ])
    console.print(f"[bold green][+][/bold green] CSV output written to [cyan]{outfile}[/cyan]")


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

    parser.add_argument(
        'logfile',
        nargs='?',
        help='Path to log file to analyze (Apache, Nginx, SSH auth.log, or CSV)'
    )
    parser.add_argument(
        '--format', '-f',
        choices=['apache', 'ssh', 'csv', 'auto'],
        default='auto',
        help='Log format (default: auto-detect)'
    )
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
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=1.5,
        metavar='FLOAT',
        help='Skewness threshold for WARNING alerts (default: 1.5)'
    )
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
        console.print(f"[bold red][ERROR] File not found: {args.logfile}[/bold red]")
        sys.exit(1)

    console.print(f"[bold blue][*][/bold blue] Parsing: [cyan]{args.logfile}[/cyan]  "
                  f"(format={args.format})")

    events = parse_log(args.logfile, fmt=args.format)

    if not events:
        console.print("[bold red][!] No events parsed. Check file format or "
                      "use --format explicitly.[/bold red]")
        sys.exit(1)

    console.print(f"[bold blue][*][/bold blue] Parsed [bold]{len(events)}[/bold] events.")

    with make_progress() as progress:
        task = progress.add_task(
            f"Running window engine (size={args.window}min, step={args.step}min)...",
            total=None
        )
        window_results = run_window_engine(
            events,
            bucket_minutes=1,
            window_size=args.window,
            step_size=args.step
        )
        progress.advance(task)

    if not window_results:
        console.print(
            f"[bold red][!] Not enough data for a single window. "
            f"Need at least {args.window} minutes of logs. "
            f"Try --window with a smaller value.[/bold red]"
        )
        sys.exit(1)

    console.print(
        f"[bold blue][*][/bold blue] Analyzed [bold]{len(window_results)}[/bold] windows. "
        f"Running alert classifier (threshold={args.threshold})..."
    )

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
        print_rich_terminal(alerts, summary, window_results, verbose=args.verbose)

    # ── Plot ─────────────────────────────────────────────────────────────────
    if args.plot:
        from visualizer import generate_chart
        chart_out = args.outfile if args.outfile and args.outfile.endswith('.png') else None
        generate_chart(
            window_results=window_results,
            alerts=alerts,
            outfile=chart_out,
            show=False
        )
        if chart_out:
            console.print(f"[bold green][+][/bold green] Chart saved to [cyan]{chart_out}[/cyan]")
        else:
            console.print(f"[bold green][+][/bold green] Chart saved to [cyan]skewsentry_chart.png[/cyan]")

    return 0


if __name__ == '__main__':
    sys.exit(main())
