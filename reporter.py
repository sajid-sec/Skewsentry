# reporter.py
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

console = Console()


# ─── Severity styling ──────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    'CRITICAL': 'bold red',
    'WARNING':  'bold yellow',
    'INFO':     'bold cyan',
    'NORMAL':   'dim green',
}

SEVERITY_ICON = {
    'CRITICAL': '[!!!]',
    'WARNING':  '[!! ]',
    'INFO':     '[!  ]',
    'NORMAL':   '[ ok]',
}


# ─── Progress bar ──────────────────────────────────────────────────────────────

def make_progress() -> Progress:
    """
    Returns a rich Progress bar for use during file parsing and window analysis.
    Used as a context manager in skewsentry.py.

    Usage:
        with make_progress() as progress:
            task = progress.add_task("Parsing...", total=total)
            for item in items:
                ...
                progress.advance(task)
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,   # clears the bar after completion — clean output
    )


# ─── Windows table ─────────────────────────────────────────────────────────────

def print_windows_table(window_results: list[dict], alerts: list[dict]):
    """
    Prints a rich table of ALL window results.
    Alert windows are color-highlighted; normal windows are dim.
    Called only in --verbose mode.
    """
    # Build a set of alert timestamps for fast lookup
    alert_times = {str(a['timestamp']) for a in alerts}

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style='bold white',
        title='[bold]Window Analysis[/bold]',
        title_style='white',
    )

    table.add_column('Timestamp',   style='dim',   min_width=20)
    table.add_column('Mean',        justify='right', min_width=7)
    table.add_column('Median',      justify='right', min_width=7)
    table.add_column('Std',         justify='right', min_width=7)
    table.add_column('Skewness',    justify='right', min_width=9)
    table.add_column('Status',      min_width=12)

    for r in window_results:
        sk   = r.get('pearson_skew')
        ts   = str(r.get('timestamp', ''))
        mean = r.get('mean')
        med  = r.get('median')
        std  = r.get('std')

        sk_str   = f"{sk:+.4f}" if sk is not None else "  N/A  "
        mean_str = f"{mean:.1f}" if mean is not None else "N/A"
        med_str  = f"{med:.1f}"  if med  is not None else "N/A"
        std_str  = f"{std:.1f}"  if std  is not None else "N/A"

        # Determine row style
        if ts in alert_times:
            # Find which alert this is
            matched = next((a for a in alerts if str(a['timestamp']) == ts), None)
            if matched:
                sev   = matched['severity']
                style = SEVERITY_STYLE[sev]
                icon  = SEVERITY_ICON[sev]
                status_text = Text(f"{icon} {sev}", style=style)
            else:
                style = ''
                status_text = Text('ALERT', style='bold red')
        else:
            style = 'dim'
            status_text = Text('normal', style='dim green')

        table.add_row(ts, mean_str, med_str, std_str, sk_str, status_text, style=style)

    console.print()
    console.print(table)


# ─── Alerts table ──────────────────────────────────────────────────────────────

def print_alerts_table(alerts: list[dict]):
    """
    Prints a compact rich table of ONLY the fired alerts.
    Always shown (not just verbose mode).
    """
    if not alerts:
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style='bold white',
        title='[bold red]⚠  Anomalies Detected[/bold red]',
    )

    table.add_column('Timestamp',   min_width=20)
    table.add_column('Severity',    min_width=10)
    table.add_column('Type',        min_width=20)
    table.add_column('Skewness',    justify='right', min_width=9)
    table.add_column('Mean',        justify='right', min_width=7)
    table.add_column('Median',      justify='right', min_width=7)

    for a in alerts:
        sev   = a.get('severity', '')
        style = SEVERITY_STYLE.get(sev, '')
        icon  = SEVERITY_ICON.get(sev, '')

        table.add_row(
            str(a.get('timestamp', '')),
            Text(f"{icon} {sev}", style=style),
            Text(a.get('alert_type', ''), style=style),
            f"{a.get('skewness', 0):+.4f}",
            f"{a.get('mean', 0):.1f}",
            f"{a.get('median', 0):.1f}",
        )

    console.print()
    console.print(table)


# ─── Summary panel ─────────────────────────────────────────────────────────────

def print_summary(summary: dict, window_results: list[dict], alerts: list[dict]):
    """
    Prints a rich Panel with key stats at the end of output.
    Includes: total windows, alert counts, max skewness, top 3 anomalous timestamps.
    """
    # Max skewness observed across ALL windows
    all_skews = [
        r['pearson_skew'] for r in window_results
        if r.get('pearson_skew') is not None
    ]
    max_skew = max((abs(s) for s in all_skews), default=0.0)

    # Top 3 most anomalous windows by |skewness|
    top3 = sorted(
        [r for r in window_results if r.get('pearson_skew') is not None],
        key=lambda r: abs(r['pearson_skew']),
        reverse=True
    )[:3]

    # Build panel content
    lines = []
    lines.append(f"[bold white]Windows analyzed :[/bold white] {len(window_results)}")
    lines.append(f"[bold white]Total alerts     :[/bold white] {summary['total']}")
    lines.append(
        f"  [bold red]Critical[/bold red]   : {summary['critical']}   "
        f"[bold yellow]Warning[/bold yellow] : {summary['warning']}   "
        f"[bold cyan]Info[/bold cyan] : {summary['info']}"
    )
    lines.append(
        f"  [bold red]Brute Force[/bold red] : {summary['brute_force']}   "
        f"[bold yellow]Slow Exfil[/bold yellow] : {summary['slow_exfiltration']}   "
        f"Other : {summary['other']}"
    )
    lines.append(f"[bold white]Max |skewness|   :[/bold white] {max_skew:.4f}")

    if top3:
        lines.append("")
        lines.append("[bold white]Top 3 anomalous windows:[/bold white]")
        for i, r in enumerate(top3, 1):
            sk = r['pearson_skew']
            direction = "▲ spike" if sk > 0 else "▼ drop"
            lines.append(
                f"  {i}. {r['timestamp']}  sk={sk:+.4f}  {direction}"
            )

    if summary['total'] == 0:
        status_line = "\n[bold green]✓ No anomalies detected. Traffic appears normal.[/bold green]"
    else:
        status_line = f"\n[bold red]⚠  {summary['total']} anomal{'y' if summary['total']==1 else 'ies'} detected.[/bold red]"

    lines.append(status_line)

    panel = Panel(
        "\n".join(lines),
        title="[bold]SkewSentry Summary[/bold]",
        border_style="blue",
        padding=(1, 2),
    )

    console.print()
    console.print(panel)
    console.print()


# ─── Main entry point ──────────────────────────────────────────────────────────

def print_rich_terminal(
    alerts: list[dict],
    summary: dict,
    window_results: list[dict],
    verbose: bool = False,
):
    """
    Main reporter function called from skewsentry.py.
    Replaces the old print_terminal().
    """
    if verbose:
        print_windows_table(window_results, alerts)

    if alerts:
        print_alerts_table(alerts)
    else:
        console.print("\n[bold green]✓ No anomalies detected. Traffic appears normal.[/bold green]")

    print_summary(summary, window_results, alerts)
