# visualizer.py
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


def extract_series(window_results):
    times = []
    counts_mean = []
    skewness_values = []

    for r in window_results:
        ts = r.get('timestamp')
        if ts is None:
            continue
        times.append(ts)
        counts_mean.append(r.get('mean', 0.0) or 0.0)
        sk = r.get('pearson_skew')
        skewness_values.append(sk if sk is not None else 0.0)

    if not times:
        return [], [], [], 0.0, 0.0

    overall_mean = sum(counts_mean) / len(counts_mean)
    sorted_counts = sorted(counts_mean)
    n = len(sorted_counts)
    if n % 2 == 0:
        overall_median = (sorted_counts[n//2 - 1] + sorted_counts[n//2]) / 2
    else:
        overall_median = sorted_counts[n//2]

    return times, counts_mean, skewness_values, overall_mean, overall_median


def generate_chart(window_results, alerts, outfile=None, show=False, title='SkewSentry — Log Anomaly Detection'):
    times, counts_mean, skewness_values, overall_mean, overall_median = extract_series(window_results)

    if not times:
        print("[!] No data to plot.")
        return

    alert_times = [a.get('timestamp') for a in alerts if a.get('timestamp')]
    alert_colors = {'CRITICAL': 'red', 'WARNING': 'orange', 'INFO': 'steelblue'}

    fig, (ax1, ax2) = plt.subplots(
        2, 1,
        figsize=(12, 6),
        sharex=True,
        gridspec_kw={'height_ratios': [2, 1]}
    )

    fig.suptitle(title, fontsize=13, fontweight='bold')

    # ── Top panel: event counts ───────────────────────────────────────────────
    ax1.plot(times, counts_mean, color='steelblue', linewidth=1.2,
             alpha=0.85, label='Events/min (window mean)')
    ax1.axhline(overall_mean,   color='orange', linewidth=1.0, linestyle='--',
                alpha=0.8, label=f'Overall mean ({overall_mean:.1f})')
    ax1.axhline(overall_median, color='green',  linewidth=1.0, linestyle='--',
                alpha=0.8, label=f'Overall median ({overall_median:.1f})')
    ax1.set_ylabel('Events / minute', fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Alert markers on top panel
    seen = set()
    for alert in alerts:
        ts  = alert.get('timestamp')
        sev = alert.get('severity', 'INFO')
        if ts is None:
            continue
        color = alert_colors.get(sev, 'steelblue')
        label = f'{sev} alert' if sev not in seen else None
        seen.add(sev)
        ax1.axvline(ts, color=color, linewidth=1.2, linestyle='--', alpha=0.7, label=label)

    ax1.legend(loc='upper left', fontsize=7)

    # ── Bottom panel: skewness ────────────────────────────────────────────────
    ax2.plot(times, skewness_values, color='purple', linewidth=1.2,
             alpha=0.9, label='Pearson skewness')
    ax2.axhline(0,    color='grey',   linewidth=0.5, alpha=0.5)
    ax2.axhline( 1.5, color='orange', linewidth=1.0, linestyle=':', alpha=0.8, label='WARNING ±1.5')
    ax2.axhline(-1.5, color='orange', linewidth=1.0, linestyle=':', alpha=0.8)
    ax2.axhline( 2.5, color='red',    linewidth=1.0, linestyle=':', alpha=0.8, label='CRITICAL ±2.5')
    ax2.axhline(-2.5, color='red',    linewidth=1.0, linestyle=':', alpha=0.8)

    ax2.fill_between(times,  1.5,  3.2, alpha=0.05, color='orange')
    ax2.fill_between(times, -3.2, -1.5, alpha=0.05, color='orange')
    ax2.fill_between(times,  2.5,  3.2, alpha=0.08, color='red')
    ax2.fill_between(times, -3.2, -2.5, alpha=0.08, color='red')

    # Alert markers on bottom panel
    for alert in alerts:
        ts  = alert.get('timestamp')
        sev = alert.get('severity', 'INFO')
        if ts is None:
            continue
        ax2.axvline(ts, color=alert_colors.get(sev, 'steelblue'),
                    linewidth=1.2, linestyle='--', alpha=0.7)

    ax2.set_ylabel('Skewness', fontsize=9)
    ax2.set_xlabel('Time', fontsize=9)
    ax2.set_ylim(-3.2, 3.2)
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc='upper left', fontsize=7)

    ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    ax2.xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.setp(ax2.xaxis.get_majorticklabels(), rotation=30, ha='right')

    plt.tight_layout()

    out = outfile or 'skewsentry_chart.png'
    plt.savefig(out, dpi=100, format='png', bbox_inches='tight')
    plt.close(fig)
    print(f"[+] Chart saved to {out}")
