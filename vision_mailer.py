#!/usr/bin/env python3
import sys
import json
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import hashlib

# --- Configuration ---
RECIPIENT_EMAIL = [
    "kbrummitt@merit-group.us"
]

SENDER_EMAIL = "cloud-alerts@merit-cloud.com"
MIN_ALERT_LEVEL = 12
ALERTS_JSON_FILE = "/var/ossec/logs/alerts/alerts.json"

HIGH_PRIORITY_GROUPS = {
    'attack',
    'mitre_attack',
    'security_event',
    'malware',
    'brute_force',
    'authentication_failed',
    'authentication_failures',
    'webshell',
    'pci_dss_11.4',
    'gdpr_IV_35.7.d',
    'vulnerability',
    'lateral_movement',
    'privilege_escalation',
    'active-response',
    'rootkit',
    'ransomware',
    'suspicious_login',
}

# NOISE groups to suppress
NOISE_GROUPS = {
    'syslog',
    'windows_update',
    'dhcp',
    'dns',
    'ntp',
    'snmp',
}

# Specific rule IDs to suppress
SUPPRESSED_RULE_IDS = {
    1002, 1007, 1008, 1016, 5105,
}

# --- Duplicate Detection Cache ---
alert_cache = {}  # {alert_hash: (timestamp, count)}
DUPLICATE_WINDOW = 300  # 5 minutes in seconds
MAX_DUPLICATES_BEFORE_ALERT = 10  # Alert if we see 10+ of the same alert

def get_alert_hash(alert_data):
    """Create a hash representing the alert's identity (ignoring timestamp)."""
    rule = alert_data.get('rule', {})
    agent = alert_data.get('agent', {})
    
    # Hash based on rule ID, agent, and source (not timestamp or full_log)
    unique_str = f"{rule.get('id')}|{agent.get('name')}|{alert_data.get('srcip', 'N/A')}|{alert_data.get('dstip', 'N/A')}"
    return hashlib.md5(unique_str.encode()).hexdigest()

def is_duplicate_alert(alert_data):
    """
    Check if this alert is a duplicate within the time window.
    Returns (is_duplicate: bool, count: int)
    """
    alert_hash = get_alert_hash(alert_data)
    now = datetime.now()
    
    if alert_hash in alert_cache:
        timestamp, count = alert_cache[alert_hash]
        age = (now - timestamp).total_seconds()
        
        # If still within window, increment count
        if age < DUPLICATE_WINDOW:
            alert_cache[alert_hash] = (timestamp, count + 1)
            return True, count + 1
        else:
            # Window expired, reset
            alert_cache[alert_hash] = (now, 1)
            return False, 1
    else:
        # First occurrence of this alert
        alert_cache[alert_hash] = (now, 1)
        return False, 1

def cleanup_cache():
    """Remove expired entries from cache."""
    now = datetime.now()
    expired = [k for k, (ts, _) in alert_cache.items() 
               if (now - ts).total_seconds() > DUPLICATE_WINDOW]
    for k in expired:
        del alert_cache[k]

def should_alert(alert_data):
    """
    Sophisticated logic to determine if an alert should be sent.
    Returns (should_alert: bool, reason: str)
    """
    rule = alert_data.get('rule', {})
    alert_level = rule.get('level', 0)
    rule_id = rule.get('id', 0)
    alert_groups = set(rule.get('groups', []))

    # Step 1: Check if rule is suppressed
    if rule_id in SUPPRESSED_RULE_IDS:
        return False, f"Rule {rule_id} suppressed (known noise)"

    # Step 2: Check noise groups
    if alert_groups.intersection(NOISE_GROUPS):
        return False, f"Noise group detected"

    # Step 3: Minimum alert level
    if alert_level < MIN_ALERT_LEVEL:
        return False, f"Level {alert_level} < {MIN_ALERT_LEVEL}"

    # Step 4: HIGH priority groups
    if HIGH_PRIORITY_GROUPS.intersection(alert_groups):
        return True, f"HIGH priority match"

    return False, f"No priority groups matched"

def create_html_email(alert_data, duplicate_count=None):
    """Creates a branded HTML email from an alert dictionary."""

    rule = alert_data.get('rule', {})
    agent = alert_data.get('agent', {})
    alert_level = rule.get('level', 0)

    log_content = alert_data.get('full_log')
    if not log_content or log_content.isspace():
        log_content = json.dumps(alert_data, indent=4)

    if "active-response" in rule.get('groups', []):
        title = "🚨 Active Response Executed"
        main_info = f"An automated response was taken on agent <strong>{agent.get('name', 'N/A')}</strong>."
        alert_color = "#d32f2f"
    else:
        title = "⚠️ Security Alert"
        main_info = f"An alert was generated on agent <strong>{agent.get('name', 'N/A')}</strong>."
        alert_color = "#f57c00"

    # Color code based on level
    if alert_level >= 15:
        alert_color = "#c62828"  # Dark red for critical
    elif alert_level >= 13:
        alert_color = "#d32f2f"  # Red for high
    else:
        alert_color = "#f57c00"  # Orange for medium

    logo_url = "https://merit-group.us/wp-content/uploads/2025/11/logo.png"

    duplicate_notice = ""
    if duplicate_count and duplicate_count > 1:
        duplicate_notice = f"<div style='background-color: #fff3cd; padding: 10px; margin: 10px 0; border-left: 4px solid #ff9800;'><strong>⚠️ Duplicate Alert:</strong> We've detected <strong>{duplicate_count}</strong> similar alerts in the last 5 minutes.</div>"

    html_body = f"""
    <html>
    <head>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }}
        .container {{ width: 100%; max-width: 650px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; border: 1px solid #dddddd; }}
        .header {{ background-color: #004a99; color: #ffffff; padding: 20px; text-align: center; }}
        .alert-banner {{ background-color: {alert_color}; color: #ffffff; padding: 12px; text-align: center; font-weight: bold; font-size: 16px; }}
        .logo {{ max-width: 250px; height: auto; margin-bottom: 0; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 25px; }}
        .content h2 {{ color: #004a99; border-bottom: 2px solid #eeeeee; padding-bottom: 10px; }}
        .alert-details {{ width: 100%; border-collapse: collapse; }}
        .alert-details td {{ padding: 8px; border: 1px solid #dddddd; text-align: left; font-size: 14px; }}
        .alert-details tr td:first-child {{ background-color: #f2f2f2; font-weight: bold; width: 150px; }}
        .level-critical {{ background-color: #ffcdd2; font-weight: bold; color: #c62828; }}
        .level-high {{ background-color: #ffe0b2; font-weight: bold; color: #e65100; }}
        .footer {{ background-color: #f4f4f4; color: #888888; text-align: center; padding: 15px; font-size: 12px; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <img src="{logo_url}" alt="MerIT Logo" class="logo">
          <div style="width: 90%; height: 2px; background-color: #ffffff; margin: 15px auto 0 auto;"></div>
        </div>
        <div class="alert-banner">
          {title} - Level {alert_level}
        </div>
        <div class="content">
          {duplicate_notice}
          <p>{main_info}</p>
          <table class="alert-details">
            <tr>
              <td>Alert Level</td>
              <td class="{'level-critical' if alert_level >= 14 else 'level-high'}">{alert_level}</td>
            </tr>
            <tr><td>Rule ID</td><td>{rule.get('id', 'N/A')}</td></tr>
            <tr><td>Rule Description</td><td>{rule.get('description', 'N/A')}</td></tr>
            <tr><td>Agent Name</td><td>{agent.get('name', 'N/A')}</td></tr>
            <tr><td>Agent IP</td><td>{agent.get('ip', 'N/A')}</td></tr>
            <tr><td>Timestamp</td><td>{alert_data.get('timestamp', 'N/A')}</td></tr>
            <tr><td>Rule Groups</td><td>{', '.join(rule.get('groups', []))}</td></tr>
          </table>
          <h2>Full Log Details</h2>
          <table class="alert-details" style="table-layout: fixed; width: 100%;">
            <tr>
              <td style="width: 100%;">
                <pre style="white-space: pre-wrap; word-break: break-all; word-wrap: break-word; font-size: 12px;">{log_content}</pre>
              </td>
            </tr>
          </table>
        </div>
        <div class="footer">
          This is an automated notification from your MerIT Vision AI security platform.
        </div>
      </div>
    </body>
    </html>
    """
    return html_body

def send_email(html_content, alert_data, duplicate_count=None):
    """Sends the email using the system's sendmail command."""
    msg = MIMEMultipart('alternative')
    
    rule = alert_data.get('rule', {})
    alert_level = rule.get('level', 0)
    alert_description = rule.get('description', 'Security Event')
    agent_name = alert_data.get('agent', {}).get('name', 'Unknown')
    
    dup_suffix = f" (x{duplicate_count})" if duplicate_count and duplicate_count > 1 else ""
    msg['Subject'] = f"[ALERT L{alert_level}] {agent_name} - {alert_description}{dup_suffix}"
    
    msg['From'] = SENDER_EMAIL
    msg['To'] = ", ".join(RECIPIENT_EMAIL)
    msg.attach(MIMEText(html_content, 'html'))

    try:
        p = subprocess.Popen(['/usr/sbin/sendmail', '-t', '-oi'], stdin=subprocess.PIPE)
        p.communicate(msg.as_bytes())
    except Exception as e:
        print(f"Error sending email: {e}", file=sys.stderr)

def main():
    """Tails the alerts.json file and processes new alerts."""
    try:
        command = ['/usr/bin/stdbuf', '-oL', '/usr/bin/tail', '-F', '-n', '0', ALERTS_JSON_FILE]
        
        process = subprocess.Popen(command, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
        
        print(f"[{datetime.now().isoformat()}] Wazuh notification script started.", flush=True)
        
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
                            is_dup, dup_count = is_duplicate_alert(alert)
                            
                            if is_dup and dup_count <= MAX_DUPLICATES_BEFORE_ALERT:
                                print(f"[{datetime.now().isoformat()}] 🔄 DUPLICATE #{dup_count}: Rule {rule_id} L{alert_level} {agent_name}", flush=True)
                            else:
                                # Send email for first occurrence or after threshold
                                print(f"[{datetime.now().isoformat()}] ✅ SENDING: Rule {rule_id} L{alert_level} {agent_name} - {reason}", flush=True)
                                html_email = create_html_email(alert, dup_count)
                                send_email(html_email, alert, dup_count)
                        else:
                            print(f"[{datetime.now().isoformat()}] ⊘ SUPPRESSED: Rule {rule_id} L{alert_level} {agent_name} - {reason}", flush=True)

                    except json.JSONDecodeError:
                        print(f"Skipping corrupt JSON: {line[:100]}...", file=sys.stderr)
                        continue
                
                # Periodically clean up old cache entries
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
