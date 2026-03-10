#!/usr/bin/env python3
import sys
import json
import subprocess
import os
import shutil
import requests
import threading
import time
from collections import Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import hashlib

# --- Configuration ---
# Internal MerIT staff — receives ALL alerts including maintenance/platform events
INTERNAL_RECIPIENTS = [
    "kbrummitt@merit-group.us",
    "jhenderson@merit-group.us",
    "chris.sparks@merit-group.us",
]

# All recipients — client-visible security alerts only
ALL_RECIPIENTS = [
    "kbrummitt@merit-group.us",
    "jhenderson@merit-group.us",
    "chris.sparks@merit-group.us",
    "franklin-FCS-MerIT-VAI-ALERTS@merit-cloud.com",
    "laurie.baggett@fcstn.net",
    "hal.hill@fcstn.net",
    "shawn.oneal@fcstn.net",
]

SENDER_EMAIL = "franklin-FCS-MerIT-VAI-ALERTS@merit-cloud.com"
SENDER_NAME = "MerIT Vision AI"
MIN_ALERT_LEVEL = 11
ALERTS_JSON_FILE = "/var/ossec/logs/alerts/alerts.json"
SENDMAIL_PATH = shutil.which("sendmail") or "/usr/sbin/sendmail"
LOGO_URL = "https://merit-group.us/wp-content/uploads/2025/12/logo-2.png"

# --- Weekly Digest Storage ---
WEEKLY_DIGEST_FILE      = "/var/ossec/logs/vision_weekly_digest.json"
WEEKLY_DIGEST_SENT_FILE = "/var/ossec/logs/vision_digest_sent.txt"
digest_lock = threading.Lock()

# --- Enable / Disable / Queue ---
DISABLE_FLAG_FILE = "/var/ossec/logs/vision_mailer_disabled"
ALERT_QUEUE_FILE  = "/var/ossec/logs/vision_alert_queue.json"
PID_FILE          = "/var/ossec/logs/vision_mailer.pid"
QUEUE_MAX_ENTRIES = 200

# --- Maintenance Alert Filter ---
# Wazuh platform/operational events that expose internal hygiene.
# These are routed to MerIT staff ONLY — never forwarded to clients.
MAINTENANCE_GROUPS = {
    'ossec', 'agent_disconnected', 'agent_restarting', 'wazuh_agent_buffer',
    'agent_flooding', 'wazuh_reporting', 'wazuh_integrity_check_ok',
    'ossec_internal',
}

# Wazuh core rule IDs covering agent lifecycle and platform health
MAINTENANCE_RULE_IDS = {
    '501', '502', '503', '504', '505', '506', '507', '508', '509',
    '510', '511', '512', '520', '521', '522', '523', '524',
    '530', '531', '532', '533', '534', '535', '536', '537', '538', '539',
    '580', '581', '582', '583', '601', '750', '751', '752',
}

MAINTENANCE_KEYWORDS = [
    'agent buffer', 'buffer overflow', 'agent started', 'agent stopped',
    'agent disconnected', 'agent reconnected', 'agent timeout',
    'remote syslog', 'ossec started', 'ossec stopped', 'wazuh agent',
    'flood protection', 'agent connection', 'integrity checking',
    'rootcheck', 'policy monitoring',
]

# --- AI Configuration ---
OLLAMA_URL = "http://10.43.18.31:11434/api/generate"
OLLAMA_MODEL = "llama3.2"

AI_PROMPT_TEMPLATE = """
You are a Senior SOC Analyst generating a notification for a client using the "MerIT Vision AI" monitoring platform.
Summarize the following security log.

**GUIDELINES:**
1. The client knows this system as "MerIT Vision AI". Please use that name in your report. Do not use the vendor name "Wazuh".
2. Write a professional, reassuring notification.
3. Use HTML formatting (<b>, <br>, <ul>, <li>).

**Output Format (HTML Only):**
<p><b>Executive Summary:</b> [One clear sentence explaining the event]</p>
<p><b>Alert Details:</b>
<ul>
    <li><b>Source:</b> MerIT Vision AI</li>
    <li><b>Device:</b> [Agent Name]</li>
    <li><b>User:</b> [User Name or "System"]</li>
    <li><b>Event:</b> [Brief description]</li>
</ul>
</p>
<p><b>Analyst Recommendations:</b><br>
[Specific, actionable advice for the client's IT contact]
</p>

**LOG DATA:**
{log_data}
"""

WEEKLY_DIGEST_AI_PROMPT = """
You are a Senior SOC Analyst preparing a weekly security digest for a client using the "MerIT Vision AI" monitoring platform.
Review the following weekly alert statistics and generate a professional narrative summary.

**GUIDELINES:**
1. Address this as "MerIT Vision AI Weekly Digest". Do NOT use the word "Wazuh".
2. Write in a professional, reassuring tone appropriate for business leadership.
3. Use HTML formatting (<b>, <br>, <ul>, <li>, <p>).
4. Highlight any trends, persistent threats, or areas of concern.
5. Provide 3-5 specific, actionable recommendations based on the week's data.

**Output Format (HTML Only):**
<p><b>Weekly Overview:</b> [2-3 sentences summarizing the week's security posture]</p>
<p><b>Key Findings:</b>
<ul>
    [List the most significant patterns or events]
</ul>
</p>
<p><b>Analyst Recommendations:</b>
<ul>
    [3-5 specific, actionable items]
</ul>
</p>

**WEEKLY STATISTICS:**
{stats_data}
"""

# --- Duplicate Detection Cache ---
alert_cache = {}
DUPLICATE_WINDOW = 300
NOTIFY_DUPLICATE_COUNTS = {1, 3, 5, 10, 25, 50}

def sanitize_text(text):
    """Replaces 'Wazuh' with 'MerIT Vision AI' in any string."""
    if not text: return ""
    return text.replace("Wazuh", "MerIT Vision AI").replace("wazuh", "MerIT Vision AI")

def get_alert_hash(alert_data):
    rule = alert_data.get('rule', {})
    agent = alert_data.get('agent', {})
    unique_str = f"{rule.get('id')}|{agent.get('name')}|{alert_data.get('srcip', 'N/A')}|{alert_data.get('dstip', 'N/A')}"
    return hashlib.md5(unique_str.encode()).hexdigest()

def is_duplicate_alert(alert_data):
    alert_hash = get_alert_hash(alert_data)
    now = datetime.now()
    entry = alert_cache.get(alert_hash)

    if not entry:
        alert_cache[alert_hash] = (now, 1)
        return True, 1
    first_seen, count = entry
    if (now - first_seen).total_seconds() > DUPLICATE_WINDOW:
        alert_cache[alert_hash] = (now, 1)
        return True, 1
    count += 1
    alert_cache[alert_hash] = (first_seen, count)
    return (count in NOTIFY_DUPLICATE_COUNTS), count

def cleanup_cache():
    now = datetime.now()
    expired = [k for k, (ts, _) in alert_cache.items() if (now - ts).total_seconds() > DUPLICATE_WINDOW]
    for k in expired: alert_cache.pop(k, None)

def is_mailer_enabled():
    """Returns True when the mailer is active. Disabled by presence of DISABLE_FLAG_FILE."""
    return not os.path.exists(DISABLE_FLAG_FILE)

def load_queue():
    """Load the alert queue list from disk."""
    try:
        if os.path.exists(ALERT_QUEUE_FILE):
            with open(ALERT_QUEUE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def record_to_queue(alert_data, status, routed_to="ALL"):
    """Append an alert entry to the rolling queue (capped at QUEUE_MAX_ENTRIES)."""
    rule  = alert_data.get('rule', {})
    agent = alert_data.get('agent', {})
    entry = {
        "timestamp":  alert_data.get('timestamp', datetime.now().isoformat())[:19].replace('T', ' '),
        "rule_id":    str(rule.get('id', 'N/A')),
        "rule_desc":  sanitize_text(rule.get('description', 'N/A'))[:60],
        "agent":      sanitize_text(agent.get('name', 'Unknown')),
        "level":      rule.get('level', 0),
        "status":     status,
        "routed_to":  routed_to,
    }
    try:
        queue = load_queue()
        queue.append(entry)
        if len(queue) > QUEUE_MAX_ENTRIES:
            queue = queue[-QUEUE_MAX_ENTRIES:]
        with open(ALERT_QUEUE_FILE, 'w') as f:
            json.dump(queue, f)
    except Exception as e:
        print(f"Warning: Could not update queue: {e}", file=sys.stderr)

def should_alert(alert_data):
    rule = alert_data.get('rule', {})
    alert_level = rule.get('level', 0)
    if alert_level < MIN_ALERT_LEVEL: return False, f"Level {alert_level} < {MIN_ALERT_LEVEL}"
    return True, f"Level {alert_level} >= {MIN_ALERT_LEVEL}"

def is_maintenance_alert(alert_data):
    """
    Returns True if the alert is a Wazuh platform/operational event (e.g. agent
    buffer overflow, agent connect/disconnect).  These are 'dirty laundry' —
    they are routed to internal MerIT staff only and never forwarded to clients.
    """
    rule = alert_data.get('rule', {})
    rule_id = str(rule.get('id', ''))
    rule_desc = rule.get('description', '').lower()
    rule_groups = set(rule.get('groups', []))

    if rule_id in MAINTENANCE_RULE_IDS:
        return True
    if rule_groups & MAINTENANCE_GROUPS:
        return True
    for keyword in MAINTENANCE_KEYWORDS:
        if keyword in rule_desc:
            return True
    return False


# --- Weekly Digest Functions ---

def load_digest_data():
    """Load the current week's digest data from disk, or return a fresh structure."""
    try:
        if os.path.exists(WEEKLY_DIGEST_FILE):
            with open(WEEKLY_DIGEST_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load digest file: {e}", file=sys.stderr)
    week_start = (datetime.now() - timedelta(days=datetime.now().weekday())).strftime('%Y-%m-%d')
    return {"week_start": week_start, "alerts": []}


def save_digest_data(data):
    """Persist digest data to disk."""
    try:
        with open(WEEKLY_DIGEST_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"Warning: Could not save digest file: {e}", file=sys.stderr)


def record_alert_for_digest(alert_data):
    """Records a client-visible alert for inclusion in the Friday weekly digest."""
    rule = alert_data.get('rule', {})
    agent = alert_data.get('agent', {})
    entry = {
        "timestamp": alert_data.get('timestamp', datetime.now().isoformat()),
        "rule_id": str(rule.get('id', 'N/A')),
        "rule_desc": sanitize_text(rule.get('description', 'N/A')),
        "agent": sanitize_text(agent.get('name', 'Unknown')),
        "level": rule.get('level', 0),
        "groups": rule.get('groups', []),
    }
    with digest_lock:
        data = load_digest_data()
        week_start = (datetime.now() - timedelta(days=datetime.now().weekday())).strftime('%Y-%m-%d')
        if data.get('week_start') != week_start:
            data = {"week_start": week_start, "alerts": []}
        data['alerts'].append(entry)
        save_digest_data(data)


def build_digest_stats(alerts):
    """Convert raw alert list into summary statistics for the digest email."""
    total = len(alerts)
    critical = sum(1 for a in alerts if a['level'] >= 15)
    high     = sum(1 for a in alerts if 13 <= a['level'] < 15)
    medium   = sum(1 for a in alerts if 11 <= a['level'] < 13)
    agent_counts = Counter(a['agent'] for a in alerts)
    rule_counts  = Counter(f"{a['rule_id']} - {a['rule_desc']}" for a in alerts)
    day_counts   = Counter()
    for a in alerts:
        try:
            day_counts[a['timestamp'][:10]] += 1
        except Exception:
            pass
    return {
        'total':      total,
        'critical':   critical,
        'high':       high,
        'medium':     medium,
        'top_agents': agent_counts.most_common(5),
        'top_rules':  rule_counts.most_common(10),
        'by_day':     sorted(day_counts.items()),
    }


def create_weekly_digest_html(stats, ai_content, week_start, week_end):
    """Builds the Vision-branded weekly digest HTML email."""
    agent_rows = ""
    for i, (agent, count) in enumerate(stats['top_agents'], 1):
        bg = "#ffffff" if i % 2 == 0 else "#f8f9ff"
        agent_rows += (
            f"<tr style='background-color:{bg}'>"
            f"<td>{i}</td><td>{agent}</td><td><b>{count}</b></td></tr>"
        )

    rule_rows = ""
    for i, (rule, count) in enumerate(stats['top_rules'], 1):
        bg = "#ffffff" if i % 2 == 0 else "#f8f9ff"
        rule_rows += (
            f"<tr style='background-color:{bg}'>"
            f"<td>{count}</td><td>{rule}</td></tr>"
        )

    day_rows = ""
    max_day = max((c for _, c in stats['by_day']), default=1)
    for day, count in stats['by_day']:
        bar_width = max(4, int((count / max_day) * 200))
        day_rows += (
            f"<tr>"
            f"<td style='padding:4px 8px;font-size:13px;white-space:nowrap;'>{day}</td>"
            f"<td style='padding:4px 8px;'>"
            f"<div style='background-color:#1565c0;height:16px;width:{bar_width}px;"
            f"border-radius:3px;display:inline-block;'></div>"
            f"<span style='margin-left:6px;font-size:13px;'>{count}</span>"
            f"</td></tr>"
        )

    ai_section = ""
    if ai_content:
        ai_section = (
            "<div style='background-color:#e8f0fe;border-left:4px solid #1565c0;"
            "padding:16px;border-radius:4px;margin:20px 24px;'>"
            "<h2 style='color:#1565c0;margin-top:0;'>&#129302; AI Security Narrative</h2>"
            f"<div style='font-size:14px;line-height:1.7;color:#333;'>{ai_content}</div>"
            "</div>"
        )

    day_section = ""
    if day_rows:
        day_section = (
            "<div class='section'><h2>&#128197; Daily Activity</h2>"
            "<table class='data-table' style='border:none;'>"
            + day_rows + "</table></div>"
        )

    no_agent_row = "<tr><td colspan='3' style='text-align:center;color:#888;'>No data this week</td></tr>"
    no_rule_row  = "<tr><td colspan='2' style='text-align:center;color:#888;'>No data this week</td></tr>"

    return f"""<html>
<head>
  <style>
    body {{font-family:Arial,sans-serif;margin:0;padding:0;background-color:#eef1f7;}}
    .wrap {{width:100%;max-width:680px;margin:20px auto;}}
    .card {{background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #d0d7e8;margin-bottom:16px;}}
    .header {{background:linear-gradient(135deg,#003d80 0%,#0064cc 100%);padding:28px 24px;text-align:center;}}
    .header h1 {{color:#fff;margin:0;font-size:22px;letter-spacing:1px;}}
    .header p {{color:#b8d0f0;margin:6px 0 0;font-size:13px;}}
    .digest-banner {{background-color:#1565c0;color:#fff;padding:10px 20px;text-align:center;font-size:15px;font-weight:bold;letter-spacing:0.5px;}}
    .section {{padding:20px 24px;}}
    .section h2 {{color:#003d80;font-size:16px;border-bottom:2px solid #e0e7f3;padding-bottom:8px;margin-top:0;}}
    .stat-grid {{display:table;width:100%;border-collapse:separate;border-spacing:10px;}}
    .stat-box {{display:table-cell;text-align:center;background:#f0f4ff;border-radius:8px;padding:16px 8px;border:1px solid #c8d8f5;}}
    .stat-num {{font-size:28px;font-weight:bold;color:#003d80;}}
    .stat-label {{font-size:12px;color:#555;margin-top:4px;}}
    .data-table {{width:100%;border-collapse:collapse;font-size:13px;}}
    .data-table th {{background-color:#003d80;color:#ffffff;padding:8px 10px;text-align:left;}}
    .data-table td {{padding:7px 10px;border-bottom:1px solid #e8ecf5;}}
    .footer {{background-color:#002f6c;color:#8aadd4;text-align:center;padding:14px;font-size:12px;}}
  </style>
</head>
<body><div class="wrap"><div class="card">
  <div class="header">
    <img src="{LOGO_URL}" alt="MerIT Logo" width="220"
         style="display:block;margin:0 auto 12px auto;border:0;">
    <div style="width:80%;height:1px;background:rgba(255,255,255,0.3);margin:0 auto 12px auto;"></div>
    <h1>Weekly Security Digest</h1>
    <p>Week of {week_start} &mdash; {week_end}</p>
  </div>
  <div class="digest-banner">
    &#128196; MerIT Vision AI &nbsp;|&nbsp; Powered by Intelligent Threat Analysis
  </div>
  <div class="section">
    <h2>&#128200; Weekly Alert Summary</h2>
    <div class="stat-grid">
      <div class="stat-box">
        <div class="stat-num">{stats['total']}</div>
        <div class="stat-label">Total Alerts</div>
      </div>
      <div class="stat-box" style="background:#fff0f0;border-color:#f5c8c8;">
        <div class="stat-num" style="color:#c62828;">{stats['critical']}</div>
        <div class="stat-label">Critical (L15+)</div>
      </div>
      <div class="stat-box" style="background:#fff4e5;border-color:#f5deb3;">
        <div class="stat-num" style="color:#e65100;">{stats['high']}</div>
        <div class="stat-label">High (L13-14)</div>
      </div>
      <div class="stat-box" style="background:#fffde7;border-color:#f5e8a0;">
        <div class="stat-num" style="color:#f57c00;">{stats['medium']}</div>
        <div class="stat-label">Medium (L11-12)</div>
      </div>
    </div>
  </div>
  {day_section}
  <div class="section">
    <h2>&#128421;&#65039; Top Affected Devices</h2>
    <table class="data-table">
      <tr><th>#</th><th>Agent / Device</th><th>Alerts</th></tr>
      {agent_rows if agent_rows else no_agent_row}
    </table>
  </div>
  <div class="section">
    <h2>&#128204; Top Alert Types</h2>
    <table class="data-table">
      <tr><th>Count</th><th>Alert Type</th></tr>
      {rule_rows if rule_rows else no_rule_row}
    </table>
  </div>
  {ai_section}
  <div class="footer">
    This weekly digest was automatically generated by MerIT Vision AI &mdash;
    your intelligent security platform.<br>
    Week ending {week_end} &nbsp;|&nbsp; MerIT Group &nbsp;|&nbsp; merit-group.us
  </div>
</div></div>
</body></html>"""


def generate_weekly_digest():
    """Generates and sends the Friday weekly digest to all recipients."""
    print(f"[{datetime.now().isoformat()}] \U0001f4ca Generating weekly security digest...", flush=True)

    with digest_lock:
        data = load_digest_data()

    alerts     = data.get('alerts', [])
    stats      = build_digest_stats(alerts)
    now        = datetime.now()
    week_end   = now.strftime('%Y-%m-%d')
    week_start = data.get('week_start', (now - timedelta(days=6)).strftime('%Y-%m-%d'))

    stats_text = (
        f"Week: {week_start} to {week_end}\n"
        f"Total Alerts: {stats['total']}\n"
        f"Critical (Level 15+): {stats['critical']}\n"
        f"High (Level 13-14): {stats['high']}\n"
        f"Medium (Level 11-12): {stats['medium']}\n\n"
        "Top 5 Most Affected Agents:\n"
        + "\n".join(f"  {i+1}. {a} ({c} alerts)" for i, (a, c) in enumerate(stats['top_agents']))
        + "\n\nTop 10 Alert Types:\n"
        + "\n".join(f"  - {r}: {c} occurrences" for r, c in stats['top_rules'])
        + "\n\nDaily Activity:\n"
        + "\n".join(f"  {d}: {c} alerts" for d, c in stats['by_day'])
    )

    ai_content = None
    try:
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": WEEKLY_DIGEST_AI_PROMPT.format(stats_data=stats_text),
            "stream": False,
        }
        response = requests.post(OLLAMA_URL, json=payload, timeout=600)
        response.raise_for_status()
        ai_content = response.json().get('response', None)
    except Exception as e:
        print(f"\u26a0\ufe0f Weekly digest AI failed (sending without narrative): {e}", file=sys.stderr)

    html = create_weekly_digest_html(stats, ai_content, week_start, week_end)

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"[Vision AI] Weekly Security Digest \u2014 Week of {week_start}"
    msg['From']    = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg['To']      = ", ".join(ALL_RECIPIENTS)
    msg.attach(MIMEText(html, 'html'))

    if not SENDMAIL_PATH or not os.path.exists(SENDMAIL_PATH):
        print("Error: sendmail not found, cannot send weekly digest.", file=sys.stderr)
        return

    try:
        subprocess.run(
            [SENDMAIL_PATH, '-t', '-oi'],
            input=msg.as_bytes(),
            check=True,
            timeout=15,
        )
        print(f"[{datetime.now().isoformat()}] \U0001f4ca Weekly digest sent successfully.", flush=True)
        with open(WEEKLY_DIGEST_SENT_FILE, 'w') as f:
            f.write(now.strftime('%Y-%m-%d'))
        # Reset digest data so next week starts fresh
        with digest_lock:
            new_week = (now - timedelta(days=now.weekday())).strftime('%Y-%m-%d')
            save_digest_data({"week_start": new_week, "alerts": []})
    except subprocess.CalledProcessError as exc:
        print(f"Error sending weekly digest: sendmail exited {exc.returncode}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("Error sending weekly digest: sendmail timed out", file=sys.stderr)
    except Exception as e:
        print(f"Error sending weekly digest: {e}", file=sys.stderr)


def weekly_digest_scheduler():
    """
    Background daemon thread.  Wakes every 30 minutes; on Fridays at or after
    08:00 sends the weekly digest if it hasn't been sent yet today.
    """
    while True:
        try:
            now = datetime.now()
            if now.weekday() == 4 and now.hour >= 8:   # 4 = Friday
                today_str = now.strftime('%Y-%m-%d')
                last_sent = ""
                if os.path.exists(WEEKLY_DIGEST_SENT_FILE):
                    with open(WEEKLY_DIGEST_SENT_FILE, 'r') as f:
                        last_sent = f.read().strip()
                if last_sent != today_str:
                    generate_weekly_digest()
        except Exception as e:
            print(f"[{datetime.now().isoformat()}] Weekly digest scheduler error: {e}", file=sys.stderr)
        time.sleep(1800)   # check every 30 minutes


def get_ai_analysis(alert_data):
    """
    Returns AI summary if successful.
    Returns NONE if failed, so we can hide the section in the email.
    """
    try:
        # Truncate to 2000 chars to prevent AI timeout
        log_json = json.dumps(alert_data)
        if len(log_json) > 2000:
            log_json = log_json[:2000] + "... [Log Truncated for Analysis]"

        payload = {"model": OLLAMA_MODEL, "prompt": AI_PROMPT_TEMPLATE.format(log_data=log_json), "stream": False}
        
        # Timeout 600s
        response = requests.post(OLLAMA_URL, json=payload, timeout=600)
        response.raise_for_status()
        result = response.json()
        
        # Return the AI text
        return result.get('response', None)
        
    except Exception as e:
        # Log error to system backend (journalctl), but return None to emailer
        print(f"⚠️ AI Generation Failed (Hiding from email): {e}", file=sys.stderr)
        return None

def create_html_email(alert_data, ai_content, duplicate_count=None, is_internal=False):
    """Creates a branded HTML email from an alert dictionary."""

    rule = alert_data.get('rule', {})
    agent = alert_data.get('agent', {})
    alert_level = rule.get('level', 0)

    # Sanitize inputs for display
    agent_name = sanitize_text(agent.get('name', 'N/A'))
    rule_desc = sanitize_text(rule.get('description', 'N/A'))

    if "active-response" in rule.get('groups', []):
        title = "🚨 Active Response Executed"
        main_info = f"An automated response was taken on agent <strong>{agent_name}</strong>."
        alert_color = "#d32f2f"
    elif is_internal:
        title = "🔧 Maintenance Alert (Internal)"
        main_info = (
            f"An operational/maintenance event was detected on <strong>{agent_name}</strong>. "
            "<em>This alert is routed to MerIT staff only and has not been forwarded to the client.</em>"
        )
        alert_color = "#f57c00"
    else:
        title = "⚠️ Security Alert"
        main_info = f"An alert was generated on agent <strong>{agent_name}</strong>."
        alert_color = "#f57c00"

    # Color code based on level
    if alert_level >= 15:
        alert_color = "#c62828"  # Dark red for critical
    elif alert_level >= 13:
        alert_color = "#d32f2f"  # Red for high
    else:
        alert_color = "#f57c00"  # Orange for medium

    duplicate_notice = ""
    if duplicate_count and duplicate_count > 1:
        duplicate_notice = f"<div style='background-color: #fff3cd; padding: 10px; margin: 10px 0; border-left: 4px solid #ff9800;'><strong>⚠️ Duplicate Alert:</strong> We've detected <strong>{duplicate_count}</strong> similar alerts in the last 5 minutes.</div>"

    internal_banner = ""
    if is_internal:
        internal_banner = (
            "<div style='background-color:#e8f5e9;padding:10px;margin:10px 0;"
            "border-left:4px solid #388e3c;font-size:13px;'>"
            "<strong>&#128274; Internal Only:</strong> This is a platform maintenance alert. "
            "It has <strong>not</strong> been forwarded to the client.</div>"
        )

    # Only create the "Executive Summary" HTML block if ai_content is not None.
    ai_section_html = ""
    if ai_content:
        ai_section_html = f"""
        <h2>Executive Summary</h2>
        <div class="ai-text">
            {ai_content}
        </div>
        """

    html_body = f"""
    <html>
    <head>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }}
        .container {{ width: 100%; max-width: 650px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; border: 1px solid #dddddd; }}
        .header {{ background-color: #004a99; color: #ffffff; padding: 20px; text-align: center; }}
        .alert-banner {{ background-color: {alert_color}; color: #ffffff; padding: 12px; text-align: center; font-weight: bold; font-size: 16px; }}
        .logo {{ max-width: 250px; height: auto; margin-bottom: 0; display: block; margin-left: auto; margin-right: auto; border: 0; outline: none; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 25px; }}
        .content h2 {{ color: #004a99; border-bottom: 2px solid #eeeeee; padding-bottom: 10px; }}
        .alert-details {{ width: 100%; border-collapse: collapse; }}
        .alert-details td {{ padding: 8px; border: 1px solid #dddddd; text-align: left; font-size: 14px; }}
        .alert-details tr td:first-child {{ background-color: #f2f2f2; font-weight: bold; width: 150px; }}
        .level-critical {{ background-color: #ffcdd2; font-weight: bold; color: #c62828; }}
        .level-high {{ background-color: #ffe0b2; font-weight: bold; color: #e65100; }}
        .footer {{ background-color: #f4f4f4; color: #888888; text-align: center; padding: 15px; font-size: 12px; }}
        .ai-text {{ font-size: 14px; line-height: 1.6; color: #333; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <img src="{LOGO_URL}" alt="MerIT Logo" class="logo" width="250">
          <div style="width: 90%; height: 2px; background-color: #ffffff; margin: 15px auto 0 auto;"></div>
        </div>
        <div class="alert-banner">
          {title} - Level {alert_level}
        </div>
        <div class="content">
          {internal_banner}
          {duplicate_notice}
          <p>{main_info}</p>
          <table class="alert-details">
            <tr>
              <td>Alert Level</td>
              <td class="{'level-critical' if alert_level >= 14 else 'level-high'}">{alert_level}</td>
            </tr>
            <tr><td>Rule ID</td><td>{rule.get('id', 'N/A')}</td></tr>
            <tr><td>Rule Description</td><td>{rule_desc}</td></tr>
            <tr><td>Agent Name</td><td>{agent_name}</td></tr>
            <tr><td>Agent IP</td><td>{agent.get('ip', 'N/A')}</td></tr>
            <tr><td>Timestamp</td><td>{alert_data.get('timestamp', 'N/A')}</td></tr>
            <tr><td>Rule Groups</td><td>{', '.join(rule.get('groups', []))}</td></tr>
          </table>
          
          {ai_section_html}
          
        </div>
        <div class="footer">
          This is an automated notification from your MerIT Vision AI security platform.
        </div>
      </div>
    </body>
    </html>
    """
    return html_body

def send_email(html_content, alert_data, duplicate_count=None, recipients=None):
    if recipients is None:
        recipients = ALL_RECIPIENTS

    msg = MIMEMultipart('alternative')
    rule = alert_data.get('rule', {})
    alert_level = rule.get('level', 0)

    agent_name = sanitize_text(alert_data.get('agent', {}).get('name', 'Unknown'))
    alert_description = sanitize_text(rule.get('description', 'Security Event'))

    dup_suffix = f" (x{duplicate_count})" if duplicate_count and duplicate_count > 1 else ""
    msg['Subject'] = f"[ALERT L{alert_level}] {agent_name} - {alert_description}{dup_suffix}"
    msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg['To'] = ", ".join(recipients)
    msg.attach(MIMEText(html_content, 'html'))

    if not SENDMAIL_PATH or not os.path.exists(SENDMAIL_PATH):
        print(f"Error sending email: sendmail not found at {SENDMAIL_PATH}", file=sys.stderr)
        return

    try:
        subprocess.run(
            [SENDMAIL_PATH, '-t', '-oi'],
            input=msg.as_bytes(),
            check=True,
            timeout=15,
        )
        print("📨 Email sent successfully.", flush=True)
    except subprocess.CalledProcessError as exc:
        print(f"Error sending email: sendmail exited {exc.returncode}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("Error sending email: sendmail timed out", file=sys.stderr)
    except Exception as e:
        print(f"Error sending email: {e}", file=sys.stderr)

def main():
    # Write PID so the CLI control panel can check daemon status
    try:
        with open(PID_FILE, 'w') as _pf:
            _pf.write(str(os.getpid()))
    except Exception as _pe:
        print(f"Warning: could not write PID file: {_pe}", file=sys.stderr)

    # Start the Friday weekly digest scheduler as a background daemon thread
    digest_thread = threading.Thread(target=weekly_digest_scheduler, daemon=True)
    digest_thread.start()
    print(f"[{datetime.now().isoformat()}] \U0001f4c5 Weekly digest scheduler started (fires Fridays at 08:00+).", flush=True)

    try:
        command = ['/usr/bin/stdbuf', '-oL', '/usr/bin/tail', '-F', '-n', '0', ALERTS_JSON_FILE]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[{datetime.now().isoformat()}] MerIT Vision AI notification script started.", flush=True)

        json_buffer = ""
        for line_fragment_bytes in iter(process.stdout.readline, b''):
            if not line_fragment_bytes:
                continue

            try:
                decoded_line = line_fragment_bytes.decode('utf-8')
                json_buffer += decoded_line

                if '\n' not in json_buffer:
                    continue

                lines = json_buffer.split('\n')
                json_buffer = lines.pop()

                for line in lines:
                    if not line:
                        continue

                    try:
                        alert = json.loads(line)
                        should_send, reason = should_alert(alert)

                        rule = alert.get('rule', {})
                        alert_level = rule.get('level', 0)
                        rule_id = rule.get('id', 'N/A')
                        agent_name = alert.get('agent', {}).get('name', 'Unknown')

                        if should_send:
                            # --- Enable / Disable gate ---
                            if not is_mailer_enabled():
                                print(f"[{datetime.now().isoformat()}] \u23f8\ufe0f  HELD (mailer disabled): Rule {rule_id} L{alert_level} {agent_name}", flush=True)
                                record_to_queue(alert, "HELD", routed_to="-")
                                continue

                            notify_now, dup_count = is_duplicate_alert(alert)

                            if notify_now:
                                maintenance   = is_maintenance_alert(alert)
                                recipients    = INTERNAL_RECIPIENTS if maintenance else ALL_RECIPIENTS
                                routing_tag   = "INTERNAL (maintenance)" if maintenance else "ALL RECIPIENTS"
                                route_label   = "INTERNAL" if maintenance else "ALL"

                                print(f"[{datetime.now().isoformat()}] Generating Executive Summary for Rule {rule_id}...", flush=True)
                                ai_analysis = get_ai_analysis(alert)

                                print(f"[{datetime.now().isoformat()}] \u2705 SENDING [{routing_tag}]: Rule {rule_id} L{alert_level} {agent_name} - {reason}", flush=True)
                                html_email = create_html_email(alert, ai_analysis, dup_count, is_internal=maintenance)
                                send_email(html_email, alert, dup_count, recipients=recipients)
                                record_to_queue(alert, "SENT", routed_to=route_label)

                                # Only log client-visible alerts for the weekly digest
                                if not maintenance:
                                    record_alert_for_digest(alert)
                            else:
                                record_to_queue(alert, "DUPLICATE", routed_to="-")
                                print(f"[{datetime.now().isoformat()}] \U0001f504 DUPLICATE #{dup_count}: Rule {rule_id} L{alert_level} {agent_name}", flush=True)
                        else:
                            print(f"[{datetime.now().isoformat()}] ⊘ SUPPRESSED: Rule {rule_id} L{alert_level} {agent_name} - {reason}", flush=True)

                    except json.JSONDecodeError:
                        print(f"Skipping corrupt JSON: {line[:100]}...", file=sys.stderr)
                        continue

                cleanup_cache()

            except Exception as e:
                print(f"[{datetime.now().isoformat()}] Error: {e}", file=sys.stderr)
                json_buffer = ""

    except KeyboardInterrupt:
        print(f"\n[{datetime.now().isoformat()}] Notification script stopped.")
    finally:
        if 'process' in locals() and process.poll() is None:
            process.terminate()

if __name__ == "__main__":
    main()
