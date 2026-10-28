"""CSV and PDF report builders (F11)."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from app.db.models import Alert
from app.services.analytics import format_bytes

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CSV_COLUMNS = [
    "id",
    "first_seen",
    "last_seen",
    "attack_class",
    "severity",
    "risk_score",
    "flows",
    "src_ip",
    "dst_ip",
    "status",
    "analyst_label",
]


def _cell(value: Any) -> str:
    """Neutralise spreadsheet formula injection: analyst labels are free text."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


TRAFFIC_COLUMNS = ["ip", "sent_bytes", "received_bytes", "total_bytes", "flows", "last_seen"]

# The data-volume report as tables. Every table says what the host sent and what it received, in
# bytes as the network carried them (IP header included).
TRAFFIC_SECTIONS: dict[str, list[str]] = {
    "hosts": TRAFFIC_COLUMNS,
    "peers": ["host", "peer", "sent_bytes", "received_bytes", "total_bytes", "flows"],
    "services": [
        "host",
        "service",
        "protocol",
        "sent_bytes",
        "received_bytes",
        "total_bytes",
        "flows",
    ],
    "timeline": ["host", "time", "sent_bytes", "received_bytes", "flows"],
}


def _table_csv(columns: list[str], rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(c)) for c in columns])
    return buf.getvalue()


def traffic_csv(hosts: list[dict[str, Any]]) -> str:
    """Data volume per monitored host (bytes as the network carried them, IP header included)."""
    return _table_csv(TRAFFIC_COLUMNS, hosts)


def traffic_section_rows(section: str, details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten per-host details (``analytics.host_detail``) into the rows of one report table."""
    rows: list[dict[str, Any]] = []
    for d in details:
        host = d["ip"]
        if section == "peers":
            rows += [
                {
                    "host": host,
                    "peer": p["ip"],
                    "sent_bytes": p["sent_bytes"],
                    "received_bytes": p["received_bytes"],
                    "total_bytes": p["bytes"],
                    "flows": p["flows"],
                }
                for p in d["peers"]
            ]
        elif section == "services":
            rows += [
                {
                    "host": host,
                    "service": s["service"],
                    "protocol": s["protocol"],
                    "sent_bytes": s["sent_bytes"],
                    "received_bytes": s["received_bytes"],
                    "total_bytes": s["bytes"],
                    "flows": s["flows"],
                }
                for s in d["services"]
            ]
        elif section == "timeline":
            rows += [
                {
                    "host": host,
                    "time": p["t"],
                    "sent_bytes": p["sent"],
                    "received_bytes": p["received"],
                    "flows": p["flows"],
                }
                for p in d["points"]
            ]
    return rows


def traffic_section_csv(section: str, rows: list[dict[str, Any]]) -> str:
    return _table_csv(TRAFFIC_SECTIONS[section], rows)


def alerts_csv(alerts: list[Alert]) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for a in alerts:
        writer.writerow(
            [
                _cell(v)
                for v in (
                    a.id,
                    a.first_seen.isoformat(),
                    a.last_seen.isoformat(),
                    a.attack_class,
                    a.severity,
                    round(a.risk_score, 1),
                    a.count,
                    a.src_ip,
                    a.dst_ip,
                    a.status,
                    a.analyst_label,
                )
            ]
        )
    return buf.getvalue()


def summary_pdf(data: dict[str, Any]) -> bytes:
    """``data``: org_name, generated_at, risk{score,severity}, open_by_severity, flows_24h,
    model_version, alerts[{severity, attack_class, src_ip, dst_ip, count, risk, actions}], and
    optionally traffic{total_bytes, monitored_sent_bytes, monitored_received_bytes, hosts[...]}."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    out = io.BytesIO()
    doc = SimpleDocTemplate(
        out,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="SentinelBI security summary",
    )

    def p(text: str, style: str = "BodyText") -> Paragraph:
        return Paragraph(escape(text), styles[style])

    gen: datetime = data["generated_at"]
    story: list[Any] = [
        p("SentinelBI security summary", "Title"),
        p(f"{data['org_name']}   |   generated {gen:%Y-%m-%d %H:%M} UTC"),
        Spacer(1, 6 * mm),
        p("Overview", "Heading2"),
    ]
    sev = data["open_by_severity"]
    kpis = [
        ["Organisation risk", f"{data['risk']['score']:.1f} / 100 ({data['risk']['severity']})"],
        [
            "Open alerts",
            ", ".join(f"{k}: {sev.get(k, 0)}" for k in ("Critical", "High", "Medium", "Low")),
        ],
        ["Flows in the last 24 h", f"{data['flows_24h']:,}"],
    ]
    traffic = data.get("traffic")
    if traffic:
        kpis.append(
            [
                "Data transferred, last 24 h",
                f"{format_bytes(traffic['total_bytes'])} in total; monitored hosts sent "
                f"{format_bytes(traffic['monitored_sent_bytes'])} and received "
                f"{format_bytes(traffic['monitored_received_bytes'])}",
            ]
        )
    table = Table(kpis, colWidths=[55 * mm, 110 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
            ]
        )
    )
    story += [table, Spacer(1, 6 * mm)]
    if traffic:
        story.append(p("Data volume by monitored host (last 24 h)", "Heading2"))
        if not traffic["hosts"]:
            story.append(p("No monitored host has sent or received traffic yet."))
        else:
            host_rows = [["Host", "Sent", "Received", "Total", "Flows"]] + [
                [
                    h["ip"],
                    format_bytes(h["sent_bytes"]),
                    format_bytes(h["received_bytes"]),
                    format_bytes(h["total_bytes"]),
                    f"{h['flows']:,}",
                ]
                for h in traffic["hosts"]
            ]
            ht = Table(
                host_rows, repeatRows=1, colWidths=[44 * mm, 30 * mm, 30 * mm, 30 * mm, 24 * mm]
            )
            ht.setStyle(
                TableStyle(
                    [
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                    ]
                )
            )
            story.append(ht)
        story.append(Spacer(1, 6 * mm))
    story.append(p("Open alerts (highest risk first)", "Heading2"))

    if not data["alerts"]:
        story.append(p("No open alerts."))
    else:
        rows = [["Severity", "Attack", "Source", "Target", "Flows", "Risk"]] + [
            [
                a["severity"],
                a["attack_class"],
                a["src_ip"] or "-",
                a["dst_ip"] or "multiple",
                str(a["count"]),
                f"{a['risk']:.1f}",
            ]
            for a in data["alerts"]
        ]
        t = Table(
            rows, repeatRows=1, colWidths=[22 * mm, 32 * mm, 36 * mm, 36 * mm, 16 * mm, 16 * mm]
        )
        t.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ]
            )
        )
        story += [t, Spacer(1, 6 * mm), p("Recommended actions", "Heading2")]
        for a in data["alerts"][:5]:
            story.append(
                p(
                    f"{a['attack_class']} from {a['src_ip'] or 'unknown source'} ({a['severity']})",
                    "Heading4",
                )
            )
            for act in a["actions"]:
                story.append(p(f"- {act}"))

    story += [
        Spacer(1, 8 * mm),
        p(
            f"Generated by SentinelBI, a research prototype. Detections come from model "
            f"'{data['model_version']}'; see its model card for measured performance and "
            "limitations. "
            "Recommendations are guidance to be reviewed by a person; compliance notes are "
            "not legal advice.",
            "Italic",
        ),
    ]
    doc.build(story)
    return out.getvalue()
