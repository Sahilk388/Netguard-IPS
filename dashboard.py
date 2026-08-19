#!/usr/bin/env python3
"""
====================================================================
  Network Protection Dashboard
  Run alongside netguard_ips.py (separate terminal, no sudo needed)
  Open in browser: http://127.0.0.1:5000
====================================================================
"""

import os
import csv
from flask import Flask, render_template_string

app = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.csv")

PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Protection</title>
    <meta http-equiv="refresh" content="3">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f4f7fb;
            color: #1f2937;
            margin: 0;
            padding: 28px;
        }
        h1 { font-size: 24px; color: #1f2937; margin: 0 0 4px 0; }
        .subtitle { color: #6b7280; font-size: 14px; margin-bottom: 24px; }

        .status-banner {
            display: flex;
            align-items: center;
            gap: 12px;
            background: #e8f7ee;
            border: 1px solid #b7e4c7;
            color: #1e6b3c;
            padding: 14px 18px;
            border-radius: 12px;
            font-size: 15px;
            margin-bottom: 24px;
        }
        .status-banner.alert { background: #fdecec; border-color: #f5b8b8; color: #a12b2b; }
        .dot { width: 10px; height: 10px; border-radius: 50%; background: #2fa860; flex-shrink: 0; }
        .status-banner.alert .dot { background: #d94b4b; }

        .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
        .card {
            background: #ffffff;
            border: 1px solid #e5e9f0;
            border-radius: 14px;
            padding: 18px 22px;
            flex: 1;
            min-width: 140px;
        }
        .card .num { font-size: 28px; font-weight: bold; color: #2b6cb0; }
        .card .label { font-size: 13px; color: #6b7280; margin-top: 4px; }
        .card.danger .num { color: #d94b4b; }
        .card.warn .num { color: #d99a2b; }

        .section-title { font-size: 16px; margin: 28px 0 12px 0; color: #1f2937; }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border-radius: 14px;
            overflow: hidden;
            border: 1px solid #e5e9f0;
        }
        th, td { padding: 12px 14px; text-align: left; font-size: 13px; }
        th { background: #f0f4f9; color: #4b5563; font-weight: 600; }
        tr:not(:last-child) td { border-bottom: 1px solid #eef1f5; }
        tr:hover td { background: #f7faff; }

        .tag { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
        .tag.arp { background: #fdecec; color: #a12b2b; }
        .tag.dns { background: #fff4e0; color: #966017; }
        .tag.other { background: #eef1f5; color: #4b5563; }

        .empty {
            text-align: center;
            padding: 40px 20px;
            color: #6b7280;
            background: #ffffff;
            border-radius: 14px;
            border: 1px dashed #d7dde5;
        }
        .empty .big { font-size: 32px; margin-bottom: 8px; }
    </style>
</head>
<body>
    <h1>Network Protection</h1>
    <div class="subtitle">This page shows what your network guard has caught, updated automatically.</div>

    {% if total > 0 %}
    <div class="status-banner alert">
        <div class="dot"></div>
        <div>Something suspicious was caught. Check the list below.</div>
    </div>
    {% else %}
    <div class="status-banner">
        <div class="dot"></div>
        <div>All clear. No suspicious activity found yet.</div>
    </div>
    {% endif %}

    <div class="stats">
        <div class="card"><div class="num">{{ total }}</div><div class="label">Total alerts</div></div>
        <div class="card danger"><div class="num">{{ arp_count }}</div><div class="label">Fake router attempts</div></div>
        <div class="card warn"><div class="num">{{ dns_count }}</div><div class="label">Fake website redirects</div></div>
        <div class="card"><div class="num">{{ blocked }}</div><div class="label">Devices blocked</div></div>
    </div>

    <div class="section-title">Recent activity</div>
    {% if rows %}
    <table>
        <tr><th>Time</th><th>What happened</th><th>Where from</th><th>Details</th><th>What we did</th></tr>
        {% for row in rows %}
        <tr>
            <td>{{ row.timestamp }}</td>
            <td>
                {% if 'ARP' in row.attack_type %}
                <span class="tag arp">Fake router</span>
                {% elif 'DNS' in row.attack_type %}
                <span class="tag dns">Fake website</span>
                {% else %}
                <span class="tag other">{{ row.attack_type }}</span>
                {% endif %}
            </td>
            <td>{{ row.source_ip }}</td>
            <td>{{ row.detail }}</td>
            <td>{{ row.action_taken }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="empty">
        <div class="big">&#128737;</div>
        Nothing to show yet. This page updates by itself when something happens.
    </div>
    {% endif %}
</body>
</html>
"""


def read_alerts():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, newline="") as f:
        return list(csv.DictReader(f))


@app.route("/")
def index():
    rows = read_alerts()
    rows.reverse()  # newest first
    arp_count = sum(1 for r in rows if "ARP" in r["attack_type"])
    dns_count = sum(1 for r in rows if "DNS" in r["attack_type"])
    blocked = len({r["source_ip"] for r in rows if "blocked" in r["action_taken"].lower()})
    return render_template_string(
        PAGE, rows=rows, total=len(rows), arp_count=arp_count, dns_count=dns_count, blocked=blocked
    )


if __name__ == "__main__":
    print("[*] Dashboard running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
