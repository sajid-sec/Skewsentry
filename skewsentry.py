#!/usr/bin/env python3
# skewsentry.py — main entry point
import argparse
import sys
import os
import json
import csv as csv_module
import random
import time as time_module
from datetime import datetime, timedelta

from parser   import parse_log
from window   import run_window_engine
from alerter  import process_alerts, summarize_alerts
from reporter import print_rich_terminal, make_progress, console


def generate_sample(attack_type: str, outfile: str, duration_minutes: int = 120):
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


def write_json(alerts, summary, outfile, window_results=None, duration_seconds=0.0):
    max_skewness = 0.0
    if window_results:
        skews = [abs(r['pearson_skew']) for r in window_results
                 if r.get('pearson_skew') is not None]
        max_skewness = max(skews, default=0.0)

    output = {
        'schema_version': '1.0',
        'summary': {
            'total_windows_analyzed':    len(window_results) if window_results else 0,
            'total_alerts':              summary['total'],
            'critical':                  summary['critical'],
            'warning':                   summary['warning'],
            'info':                      summary['info'],
            'brute_force':               summary['brute_force'],
            'slow_exfiltration':         summary['slow_exfiltration'],
            'max_skewness':              round(max_skewness, 6),
            'analysis_duration_seconds': round(duration_seconds, 3),
        },
        'alerts': [
            {
                'timestamp':    a['timestamp'].isoformat() if isinstance(a['timestamp'], datetime) else str(a['timestamp']),
                'window_start': a['window_start'].isoformat() if isinstance(a.get('window_start'), datetime) else str(a.get('window_start', '')),
                'window_end':   a['window_end'].isoformat()   if isinstance(a.get('window_end'),   datetime) else str(a.get('window_end',   '')),
                'severity':     a.get('severity', ''),
                'alert_type':   a.get('alert_type', ''),
                'skewness':     round(a.get('skewness', 0.0), 6),
                'mean':         round(a.get('mean',     0.0), 4),
                'median':       round(a.get('median',   0.0), 4),
                'std':          round(a.get('std',      0.0), 4),
                'n':            a.get('n', 0),
            }
            for a in alerts
        ]
    }
    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2)
    console.print(f"[bold green][+][/bold green] JSON output written to [cyan]{outfile}[/cyan]")


def write_csv_output(alerts, outfile, window_results=None, duration_seconds=0.0):
    if not alerts:
        console.print("[bold yellow][!] No alerts to write.[/bold yellow]")
        return
    fieldnames = [
        'timestamp', 'window_start', 'window_end',
        'severity', 'alert_type',
        'skewness', 'mean', 'median', 'std', 'n'
    ]
    with open(outfile, 'w', newline='') as f:
        writer = csv_module.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for a in alerts:
            writer.writerow({
                'timestamp':    a['timestamp'].isoformat() if isinstance(a['timestamp'], datetime) else str(a['timestamp']),
                'window_start': a['window_start'].isoformat() if isinstance(a.get('window_start'), datetime) else str(a.get('window_start', '')),
                'window_end':   a['window_end'].isoformat()   if isinstance(a.get('window_end'),   datetime) else str(a.get('window_end',   '')),
                'severity':     a.get('severity', ''),
                'alert_type':   a.get('alert_type', ''),
                'skewness':     round(a.get('skewness', 0.0), 6),
                'mean':         round(a.get('mean',     0.0), 4),
                'median':       round(a.get('median',   0.0), 4),
                'std':          round(a.get('std',      0.0), 4),
                'n':            a.get('n', 0),
            })
    console.print(f"[bold green][+][/bold green] CSV output written to [cyan]{outfile}[/cyan]")


def build_parser():
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
    parser.add_argument('logfile', nargs='?',
                        help='Path to log file (Apache, Nginx, SSH auth.log, or CSV)')
    parser.add_argument('--format', '-f',
                        choices=['apache', 'ssh', 'csv', 'auto'], default='auto',
                        help='Log format (default: auto-detect)')
    parser.add_argument('--window', '-w', type=int, default=60, metavar='INT',
                        help='Sliding window size in minutes (default: 60)')
    parser.add_argument('--step', type=int, default=1, metavar='INT',
                        help='Window step size in minutes (default: 1)')
    parser.add_argument('--threshold', '-t', type=float, default=1.5, metavar='FLOAT',
                        help='Skewness threshold for WARNING alerts (default: 1.5)')
    parser.add_argument('--output', '-o', choices=['terminal', 'json', 'csv'],
                        default='terminal', help='Output format (default: terminal)')
    parser.add_argument('--outfile', metavar='PATH',
                        help='Output file path for --output json/csv or --generate-sample')
    parser.add_argument('--plot', action='store_true',
                        help='Save matplotlib chart as PNG')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print every window result, not just alerts')
    parser.add_argument('--generate-sample', action='store_true',
                        help='Generate a synthetic log file instead of analyzing one')
    parser.add_argument('--attack',
                        choices=['brute_force', 'slow_exfiltration', 'normal'],
                        default='brute_force',
                        help='Attack type for --generate-sample (default: brute_force)')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── Mode 1: Generate sample log ───────────────────────────────────────────
    if args.generate_sample:
        outfile = args.outfile or f"sample_{args.attack}.csv"
        generate_sample(attack_type=args.attack, outfile=outfile)
        sys.exit(0)

    # ── Mode 2: Analyze log file ──────────────────────────────────────────────
    if not args.logfile:
        parser.error("logfile is required unless --generate-sample is used.")

    if not os.path.exists(args.logfile):
        console.print(f"[bold red][ERROR] File not found: {args.logfile}[/bold red]")
        sys.exit(1)

    _analysis_start = time_module.time()

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

    alerts   = process_alerts(window_results, threshold=args.threshold)
    summary  = summarize_alerts(alerts)
    duration = time_module.time() - _analysis_start

    # ── Output ────────────────────────────────────────────────────────────────
    if args.output == 'json':
        outfile = args.outfile or 'alerts.json'
        write_json(alerts, summary, outfile,
                   window_results=window_results,
                   duration_seconds=duration)

    elif args.output == 'csv':
        outfile = args.outfile or 'alerts.csv'
        write_csv_output(alerts, outfile,
                         window_results=window_results,
                         duration_seconds=duration)

    else:  # terminal
        print_rich_terminal(alerts, summary, window_results, verbose=args.verbose)

    # ── Plot ──────────────────────────────────────────────────────────────────
    if args.plot:
        from visualizer import generate_chart
        chart_out = args.outfile if args.outfile and args.outfile.endswith('.png') else None
        generate_chart(window_results=window_results, alerts=alerts, outfile=chart_out)
        if not chart_out:
            console.print(f"[bold green][+][/bold green] Chart saved to [cyan]skewsentry_chart.png[/cyan]")

    return 0


if __name__ == '__main__':
    sys.exit(main())
