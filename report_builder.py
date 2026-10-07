"""
Network-wide report: uptime per device, incidents, bandwidth top
consumers, and plain-language recommendations, exported as a PDF.

Kept separate from ui.py so the numbers can be computed (and tested)
without any Tk code. ui.py only has to:
    data = report_builder.gather_report_data(engine, hours)
    report_builder.build_network_report_pdf(path, data)
Both are safe to call from a background thread.

HOW UPTIME IS COMPUTED
engine.py only logs a status_history entry when a device CHANGES into
Unstable / Idle / Offline, or recovers to Online. That is a complete
timeline of transitions, so the time spent in each state can be rebuilt
from it:
    Uptime %   = time NOT Offline   (Idle/Unstable still count as "up":
                                      the device was present, just slow)
    Healthy %  = time fully Online
The report only covers the period monitoring was actually running
(see "tracked since" below) — time the app was closed is not tracked, so
it is never counted as 100% uptime.
"""

from datetime import datetime, timedelta

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import history_store

_TS_FMT = "%Y-%m-%d %H:%M:%S"
_PROBLEM_STATES = ("Unstable", "Idle", "Offline")
_KNOWN_STATES = ("Online", "Unstable", "Idle", "Offline")

# Recommendation thresholds
_LOW_UPTIME_PCT = 95.0
_MANY_INCIDENTS = 5
_HOG_SHARE = 0.50
_WIDESPREAD_SHARE = 0.40


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _parse_ts(value):
    try:
        return datetime.strptime(str(value), _TS_FMT)
    except (TypeError, ValueError):
        return None


def format_duration(seconds):
    seconds = int(max(0, seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d {h:02d}h"
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def compute_availability(entries, window_start, now, current_status="Online"):
    """Rebuilds how long a device spent in each state between
    `window_start` and `now` from its status_history `entries`
    (dicts with "ts" and "status"). Returns a dict with uptime_pct,
    healthy_pct, incidents, outages, downtime_seconds, longest_outage_seconds
    and last_incident (timestamp string or None)."""
    parsed = []
    for e in entries or []:
        ts = _parse_ts(e.get("ts"))
        st = e.get("status")
        if ts is not None and st in _KNOWN_STATES:
            parsed.append((ts, st))
    parsed.sort(key=lambda x: x[0])

    # State at the start of the window: the last transition BEFORE it.
    # With no history at all, trust the live status; with history that
    # only begins inside the window, the device was fine before it.
    if not parsed:
        state = current_status if current_status in _KNOWN_STATES else "Online"
    else:
        state = "Online"
        for ts, st in parsed:
            if ts <= window_start:
                state = st
            else:
                break

    in_window = [(ts, st) for ts, st in parsed if window_start < ts <= now]

    seconds = {s: 0.0 for s in _KNOWN_STATES}
    longest_outage = 0.0
    cursor = window_start
    outage_run = 0.0

    def _close_segment(upto):
        nonlocal cursor, outage_run
        dur = max(0.0, (upto - cursor).total_seconds())
        seconds[state] += dur
        if state == "Offline":
            outage_run += dur
        cursor = upto

    for ts, st in in_window:
        _close_segment(ts)
        if state == "Offline" and st != "Offline":
            longest_outage = max(longest_outage, outage_run)
            outage_run = 0.0
        state = st
    _close_segment(now)
    if state == "Offline":
        longest_outage = max(longest_outage, outage_run)

    total = max(1.0, (now - window_start).total_seconds())
    down = seconds["Offline"]
    incidents = [(ts, st) for ts, st in in_window if st in _PROBLEM_STATES]
    return {
        "uptime_pct": round(100.0 * (total - down) / total, 2),
        "healthy_pct": round(100.0 * seconds["Online"] / total, 2),
        "incidents": len(incidents),
        "outages": sum(1 for _, st in incidents if st == "Offline"),
        "downtime_seconds": down,
        "longest_outage_seconds": longest_outage,
        "last_incident": incidents[-1][0].strftime(_TS_FMT) if incidents else None,
    }


def _network_key(engine):
    """The key history_store saves under. A group engine may not carry its
    own network_key, so fall back to the network it belongs to."""
    key = getattr(engine, "network_key", None)
    if key:
        return key
    for attr in ("parent", "parent_engine", "network", "net"):
        owner = getattr(engine, attr, None)
        key = getattr(owner, "network_key", None)
        if key:
            return key
    return None


def _device_entries(engine, device):
    """Full saved history for one device (history_store), falling back to
    the in-memory copy if the store has nothing."""
    entries = []
    try:
        entries = list(history_store.load_for_mac(_network_key(engine), device.mac) or [])
    except Exception:
        entries = []
    if not entries:
        entries = list(getattr(device, "status_history", []) or [])
    return entries


def build_recommendations(devices, bandwidth_rows, estimated_total, window_hours):
    """Plain-language findings, most important first."""
    recs = []
    online_count = len(devices)

    offline_now = [d for d in devices if d["status"] == "Offline"]
    if offline_now:
        names = ", ".join(d["name"] for d in offline_now[:5])
        more = f" and {len(offline_now) - 5} more" if len(offline_now) > 5 else ""
        recs.append(("critical",
                     f"{len(offline_now)} device(s) are Offline right now: {names}{more}. "
                     "Check power, cable and Wi-Fi connection for each."))

    degraded_now = [d for d in devices if d["status"] in ("Unstable", "Idle")]
    if online_count >= 3 and len(degraded_now) / online_count >= _WIDESPREAD_SHARE:
        recs.append(("warning",
                     f"{len(degraded_now)} of {online_count} devices are slow or unstable at the "
                     "same time. This usually points to the router, the ISP uplink or a congested "
                     "Wi-Fi channel rather than the individual devices."))

    if window_hours >= 1:
        for d in sorted(devices, key=lambda x: x["uptime_pct"]):
            if d["uptime_pct"] < _LOW_UPTIME_PCT:
                recs.append(("warning",
                             f"{d['name']} ({d['ip']}) had only {d['uptime_pct']:.1f}% uptime "
                             f"(longest outage {format_duration(d['longest_outage_seconds'])}). "
                             "Check its power, cable or Wi-Fi signal strength."))
        for d in devices:
            if d["incidents"] >= _MANY_INCIDENTS and d["uptime_pct"] >= _LOW_UPTIME_PCT:
                recs.append(("info",
                             f"{d['name']} ({d['ip']}) was unstable {d['incidents']} times in this "
                             "period. Possible weak signal, interference or a failing cable."))

    if estimated_total > 0 and bandwidth_rows:
        top = bandwidth_rows[0]
        share = top["estimated_bytes"] / estimated_total
        if share >= _HOG_SHARE:
            recs.append(("warning",
                         f"{top['name']} accounts for about {share * 100:.0f}% of the network's "
                         "estimated usage. Check for large downloads, streaming or backups; "
                         "consider scheduling them off-peak or limiting that device."))

    if not recs:
        recs.append(("ok", "No significant problems were found in this period."))
    return recs


# --------------------------------------------------------------------------
# data gathering
# --------------------------------------------------------------------------
def gather_report_data(engine, hours):
    now = datetime.now()
    requested_start = now - timedelta(hours=hours)

    with engine.lock:
        devices = list(engine.devices)
        session_start = getattr(engine, "_bw_session_start", None)
        meta = [(d, d.name, d.ip, d.mac, d.status) for d in devices]

    try:
        snapshot = engine.get_bandwidth_snapshot()
    except Exception:
        snapshot = {"devices": [], "network_total_available": False}
    bw_by_mac = {r.get("mac"): r for r in snapshot.get("devices", []) if not r.get("is_host")}

    histories = {mac: _device_entries(engine, d) for d, _n, _i, mac, _s in meta}

    # Only claim uptime for the period monitoring really covered.
    earliest = []
    if session_start is not None:
        earliest.append(session_start)
    for entries in histories.values():
        for e in entries:
            ts = _parse_ts(e.get("ts"))
            if ts:
                earliest.append(ts)
    tracked_since = min(earliest) if earliest else now
    window_start = max(requested_start, tracked_since)
    if window_start >= now:
        window_start = now - timedelta(seconds=1)

    rows = []
    for d, name, ip, mac, status in meta:
        avail = compute_availability(histories.get(mac, []), window_start, now, status)
        bw = bw_by_mac.get(mac, {})
        rows.append({
            "name": name, "ip": ip, "mac": mac, "status": status,
            "estimated_bytes": float(bw.get("estimated_bytes", 0.0)),
            "formatted_usage": bw.get("formatted_estimate", "--"),
            **avail,
        })
    rows.sort(key=lambda r: r["uptime_pct"])

    # The computer running the app is intentionally left out of the report.
    bandwidth_rows = sorted(
        (r for r in snapshot.get("devices", []) if not r.get("is_host")),
        key=lambda r: r.get("estimated_bytes", 0.0), reverse=True)
    estimated_total = float(snapshot.get("estimated_total_bytes", 0.0))

    counts = {s: 0 for s in _KNOWN_STATES}
    for r in rows:
        if r["status"] in counts:
            counts[r["status"]] += 1

    avg_uptime = round(sum(r["uptime_pct"] for r in rows) / len(rows), 2) if rows else 0.0

    return {
        "network_label": getattr(engine, "label", "Network"),
        "is_group": bool(getattr(engine, "is_group", False)),
        "generated": now,
        "requested_hours": hours,
        "window_start": window_start,
        "window_end": now,
        "device_count": len(rows),
        "status_counts": counts,
        "average_uptime_pct": avg_uptime,
        "total_incidents": sum(r["incidents"] for r in rows),
        "devices": rows,
        "top_consumers": bandwidth_rows[:5],
        "real_total_available": bool(snapshot.get("network_total_available")),
        "real_total": snapshot.get("formatted_total", "--"),
        "real_sent": snapshot.get("formatted_sent", "--"),
        "real_recv": snapshot.get("formatted_recv", "--"),
        "network_estimated_total": snapshot.get("formatted_network_estimated_total", "--"),
        "recommendations": build_recommendations(
            rows, bandwidth_rows, estimated_total, hours),
    }


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------
_STATUS_COLOR = {
    "Online": "#1B8A3A", "Unstable": "#B36B00",
    "Idle": "#2255AA", "Offline": "#CC0000",
}
_REC_COLOR = {
    "critical": "#CC0000", "warning": "#B36B00",
    "info": "#2255AA", "ok": "#1B8A3A",
}


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _table_style(header_color="#222222"):
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])


def build_network_report_pdf(path, data):
    styles = getSampleStyleSheet()
    title = ParagraphStyle("RTitle", parent=styles["Title"], fontSize=19, spaceAfter=4)
    sub = ParagraphStyle("RSub", parent=styles["Normal"], fontSize=10,
                         textColor=colors.HexColor("#555555"), spaceAfter=10)
    section = ParagraphStyle("RSection", parent=styles["Heading2"], fontSize=13,
                             spaceBefore=14, spaceAfter=6)
    cell = ParagraphStyle("RCell", parent=styles["Normal"], fontSize=8.5, leading=10.5)

    story = []
    story.append(Paragraph("Group Report" if data.get("is_group") else "Network Report", title))
    ws, we = data["window_start"], data["window_end"]
    story.append(Paragraph(
        f"{_esc(data['network_label'])}"
        f"<br/>Period covered: {ws.strftime('%Y-%m-%d %H:%M')} to {we.strftime('%Y-%m-%d %H:%M')} "
        f"({format_duration((we - ws).total_seconds())})"
        f"<br/>Generated {data['generated'].strftime(_TS_FMT)}", sub))

    # --- Summary -----------------------------------------------------------
    c = data["status_counts"]
    summary = [
        ["Devices tracked", str(data["device_count"]),
         "Average uptime", f"{data['average_uptime_pct']:.1f}%"],
        ["Online / Unstable", f"{c['Online']} / {c['Unstable']}",
         "Idle / Offline", f"{c['Idle']} / {c['Offline']}"],
        ["Incidents in period", str(data["total_incidents"]),
         "Estimated network usage", _esc(data["network_estimated_total"])],
    ]
    t = Table(summary, colWidths=[1.7 * inch, 1.5 * inch, 1.9 * inch, 1.9 * inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F7F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)

    # --- Findings ----------------------------------------------------------
    story.append(Paragraph("Findings and Recommendations", section))
    for level, text in data["recommendations"]:
        st = ParagraphStyle("Rec", parent=styles["Normal"], fontSize=10, leading=13,
                            textColor=colors.HexColor(_REC_COLOR.get(level, "#333333")),
                            leftIndent=10, spaceAfter=5)
        story.append(Paragraph(f"&bull; {_esc(text)}", st))

    # --- Device availability ----------------------------------------------
    story.append(Paragraph("Device Availability (lowest uptime first)", section))
    head = ["Device", "IP", "Status", "Uptime", "Healthy", "Incidents", "Max outage", "Est. usage"]
    rows = [head]
    for d in data["devices"]:
        col = _STATUS_COLOR.get(d["status"], "#333333")
        rows.append([
            Paragraph(_esc(d["name"]), cell),
            Paragraph(_esc(d["ip"]), cell),
            Paragraph(f'<font color="{col}"><b>{_esc(d["status"])}</b></font>', cell),
            f'{d["uptime_pct"]:.1f}%',
            f'{d["healthy_pct"]:.1f}%',
            str(d["incidents"]),
            format_duration(d["longest_outage_seconds"]) if d["outages"] else "--",
            _esc(d["formatted_usage"]),
        ])
    if len(rows) == 1:
        rows.append(["No devices tracked", "", "", "", "", "", "", ""])
    dt = Table(rows, repeatRows=1, colWidths=[
        1.55 * inch, 0.95 * inch, 0.7 * inch, 0.6 * inch, 0.65 * inch,
        0.65 * inch, 0.85 * inch, 0.85 * inch])
    dt.setStyle(_table_style())
    story.append(dt)

    # --- Top consumers -----------------------------------------------------
    story.append(Paragraph("Top Bandwidth Consumers", section))
    top = [["#", "Device", "IP", "Usage"]]
    for i, r in enumerate(data["top_consumers"], start=1):
        top.append([
            str(i), Paragraph(_esc(r.get("name", "")), cell), _esc(r.get("ip", "")),
            _esc(r.get("formatted_estimate", "--")),
        ])
    if len(top) == 1:
        top.append(["--", "No usage recorded yet", "", ""])
    tt = Table(top, repeatRows=1, colWidths=[0.35 * inch, 2.9 * inch, 1.5 * inch, 1.6 * inch])
    tt.setStyle(_table_style("#007AFF"))
    story.append(tt)

    doc = SimpleDocTemplate(
        path, pagesize=letter,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        title=f"{'Group' if data.get('is_group') else 'Network'} Report - {data['network_label']}",
    )
    doc.build(story)