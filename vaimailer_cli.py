#!/usr/bin/env python3
"""
MerIT Vision AI — Mailer Control Panel
=======================================
Usage:
    vaimailer            Launch the interactive TUI
    vaimailer --install  Install /usr/local/bin/vaimailer symlink (requires sudo)
"""

import curses
import os
import sys
import json
import subprocess
import threading
import time
import shutil
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Locate and import the main mailer module ──────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

# Auto-detect which mailer is installed on this server.
# On a Franklin server: vision_ai_mailer_franklin.py
# On a Trousdale server: vision_ai_mailer_trousdale.py
# Fallback (legacy): vision_ai_mailer.py
_MAILER_CANDIDATES = [
    "vision_ai_mailer_franklin",
    "vision_ai_mailer_trousdale",
    "vision_ai_mailer",
]

_m = None
for _mod_name in _MAILER_CANDIDATES:
    try:
        import importlib as _il
        _m = _il.import_module(_mod_name)
        _ACTIVE_MAILER = _mod_name
        break
    except ImportError:
        pass

if _m is None:
    print(f"ERROR: Could not find a Vision AI mailer module in {_SCRIPT_DIR}")
    print(f"       Expected one of: {', '.join(_MAILER_CANDIDATES)}")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION        = "1.1"
TEST_RECIPIENT = "kbrummitt@merit-group.us"

# Service names to try when checking daemon via systemctl
SERVICE_NAMES = ["vision-ai-mailer", "vision_ai_mailer", "vaimailer"]

# Mock alert used for test email
TEST_ALERT_DATA = {
    "timestamp": "",   # filled at send time
    "rule": {
        "level": 12,
        "id":    "1002",
        "description": "TEST: Suspicious login attempt detected — Vision AI test event.",
        "groups": ["syslog", "authentication_failed"],
    },
    "agent": {"id": "000", "name": "test-agent-prod-01", "ip": "10.43.18.50"},
    "data":  {"srcuser": "testuser", "dstuser": "N/A"},
    "srcip": "203.0.113.42",
    "dstip": "10.43.18.50",
}

# ── Colour pair IDs ───────────────────────────────────────────────────────────
_C_HEADER   = 1   # white on deep blue
_C_ENABLED  = 2   # white on green
_C_DISABLED = 3   # white on red
_C_SELECTED = 4   # black on cyan
_C_WARN     = 5   # bright yellow on black
_C_DIM      = 6   # grey on black
_C_TITLE    = 7   # bold white on dark blue
_C_NORMAL   = 8   # white on black

_SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']


# ── Small utilities ───────────────────────────────────────────────────────────

def _safe(win, y, x, text, attr=0):
    """addstr that never raises on window overflow or narrow terms."""
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h - 1 or x < 0 or x >= w:
            return
        avail = w - x - 1
        if avail <= 0:
            return
        win.addstr(y, x, text[:avail], attr)
    except curses.error:
        pass


def _get_daemon_status():
    """Return 'RUNNING', 'STOPPED', or 'UNKNOWN'."""
    for svc in SERVICE_NAMES:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=3,
            )
            s = r.stdout.strip()
            if s == "active":
                return "RUNNING"
            if s in ("inactive", "failed", "dead"):
                return "STOPPED"
        except Exception:
            pass
    # Fallback: PID file
    if os.path.exists(_m.PID_FILE):
        try:
            with open(_m.PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return "RUNNING"
        except (ValueError, OSError):
            pass
    return "UNKNOWN"


def _queue_count():
    try:
        return len(_m.load_queue())
    except Exception:
        return 0


def _build_synthetic_digest_alerts():
    """Synthetic sample data for the test digest when no real data exists."""
    samples = [
        (12, "1002",  "Unknown problem detected in the system",       "fw-primary"),
        (13, "5501",  "User login failed",                            "dc01"),
        (11, "31101", "Web attack: SQL injection attempt",            "web-server-01"),
        (14, "5501",  "Multiple authentication failures",             "dc01"),
        (12, "1002",  "Kernel error detected",                        "app-server-02"),
        (13, "31101", "XSS attack attempt detected",                  "web-server-01"),
        (11, "5501",  "User login failed",                            "workstation-07"),
        (15, "40101", "Ransomware-like behavior pattern detected",     "fileserver-01"),
        (12, "1002",  "Service crashed and restarted",                "app-server-02"),
        (11, "31101", "Port scan detected from external source",      "fw-primary"),
    ]
    base = datetime.now()
    return [
        {
            "timestamp": (base - timedelta(days=i % 7, hours=i * 2)).isoformat(),
            "rule_id":   rule_id,
            "rule_desc": desc,
            "agent":     agent,
            "level":     level,
            "groups":    [],
        }
        for i, (level, rule_id, desc, agent) in enumerate(samples)
    ]


# ══════════════════════════════════════════════════════════════════════════════
# Main UI Class
# ══════════════════════════════════════════════════════════════════════════════

class VisionAIMailerUI:

    def __init__(self, stdscr):
        self.scr = stdscr
        curses.start_color()
        curses.use_default_colors()
        curses.curs_set(0)
        curses.set_escdelay(50)
        self.scr.keypad(True)
        self._init_colors()

    def _init_colors(self):
        curses.init_pair(_C_HEADER,   curses.COLOR_WHITE,  curses.COLOR_BLUE)
        curses.init_pair(_C_ENABLED,  curses.COLOR_WHITE,  curses.COLOR_GREEN)
        curses.init_pair(_C_DISABLED, curses.COLOR_WHITE,  curses.COLOR_RED)
        curses.init_pair(_C_SELECTED, curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(_C_WARN,     curses.COLOR_YELLOW, -1)
        # Color 8 (dark grey) only exists on 256-colour terminals; fall back to
        # default foreground (-1) on 8-colour terminals like some SSH sessions.
        _dim_fg = 8 if curses.COLORS > 8 else -1
        curses.init_pair(_C_DIM,      _dim_fg,             -1)
        curses.init_pair(_C_TITLE,    curses.COLOR_WHITE,  curses.COLOR_BLUE)
        curses.init_pair(_C_NORMAL,   curses.COLOR_WHITE,  -1)

    # ── Layout helpers ────────────────────────────────────────────────────────

    def _h(self): return self.scr.getmaxyx()[0]
    def _w(self): return self.scr.getmaxyx()[1]

    def _draw_header(self, subtitle=""):
        w = self._w()
        title = "  MerIT Vision AI  —  Mailer Control Panel  "
        hattr = curses.color_pair(_C_HEADER) | curses.A_BOLD
        self.scr.attron(hattr)
        try:
            self.scr.addstr(0, 0, " " * (w - 1))
        except curses.error:
            pass
        _safe(self.scr, 0, max(0, (w - len(title)) // 2), title, hattr)
        self.scr.attroff(hattr)
        if subtitle:
            dattr = curses.color_pair(_C_DIM)
            try:
                self.scr.attron(dattr)
                self.scr.addstr(1, 0, " " * (w - 1))
                self.scr.attroff(dattr)
            except curses.error:
                pass
            _safe(self.scr, 1, max(0, (w - len(subtitle)) // 2), subtitle, dattr)

    def _draw_status_bar(self, row=2):
        w = self._w()
        enabled = _m.is_mailer_enabled()
        daemon  = _get_daemon_status()
        qcount  = _queue_count()
        ts      = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

        dim  = curses.color_pair(_C_DIM)
        try:
            self.scr.addstr(row,     0, "─" * (w - 1), dim)
            self.scr.addstr(row + 2, 0, "─" * (w - 1), dim)
        except curses.error:
            pass

        col = 2
        _safe(self.scr, row + 1, col, "Mailer: ", curses.color_pair(_C_NORMAL))
        col += 8

        en_label = "  ENABLED  " if enabled else " DISABLED "
        en_attr  = (curses.color_pair(_C_ENABLED) | curses.A_BOLD) if enabled \
                   else (curses.color_pair(_C_DISABLED) | curses.A_BOLD)
        _safe(self.scr, row + 1, col, en_label, en_attr)
        col += len(en_label) + 2

        dm_sym  = "●" if daemon == "RUNNING" else "○"
        dm_attr = (curses.color_pair(_C_ENABLED) | curses.A_BOLD) if daemon == "RUNNING" \
                  else curses.color_pair(_C_WARN)
        _safe(self.scr, row + 1, col, f" {dm_sym} Daemon: {daemon}  ", dm_attr)
        col += 18

        _safe(self.scr, row + 1, col, f" Queue: {qcount} entries  ",
              curses.color_pair(_C_NORMAL))

        ts_str = f"  {ts}  "
        _safe(self.scr, row + 1, w - len(ts_str) - 1, ts_str, curses.color_pair(_C_DIM))

    def _draw_footer(self, text="  Arrow keys / number to select   [Q] Quit  "):
        h, w = self.scr.getmaxyx()
        fattr = curses.color_pair(_C_HEADER)
        try:
            self.scr.attron(fattr)
            self.scr.addstr(h - 1, 0, " " * (w - 1))
            self.scr.attroff(fattr)
        except curses.error:
            pass
        _safe(self.scr, h - 1, 2, text, fattr)

    # ── Main menu ─────────────────────────────────────────────────────────────

    def run(self):
        sel = 0
        while True:
            self.scr.erase()
            enabled = _m.is_mailer_enabled()

            menu = [
                ("1", "Live Monitor",              "  Tail the live service log"),
                ("2", "Send Test Alert Email",      f"  →  {TEST_RECIPIENT}"),
                ("3", "Send Test Weekly Digest",    f"  →  {TEST_RECIPIENT}"),
                ("4",
                 "Disable Mailer" if enabled else "Enable Mailer",
                 "  Halt outbound email delivery" if enabled else "  Resume email delivery"),
                ("5", "View Alert Queue",           f"  ({_queue_count()} entries)"),
                ("6", "Exit",                       ""),
            ]

            self._draw_header()
            self._draw_status_bar(row=2)
            self._draw_footer()

            menu_top = 6
            for i, (num, label, hint) in enumerate(menu):
                attr   = (curses.color_pair(_C_SELECTED) | curses.A_BOLD) if i == sel \
                         else curses.color_pair(_C_NORMAL)
                prefix = "  ▶  " if i == sel else "     "
                line   = f"{prefix}[{num}]  {label}{hint}"
                _, w   = self.scr.getmaxyx()
                _safe(self.scr, menu_top + i * 2, 2, " " * min(w - 4, 74), attr)
                _safe(self.scr, menu_top + i * 2, 2, line, attr)

            ver_str = f"v{VERSION}"
            _safe(self.scr, self._h() - 2, self._w() - len(ver_str) - 2, ver_str,
                  curses.color_pair(_C_DIM))
            self.scr.refresh()

            ch = self.scr.getch()
            action = None

            if ch == curses.KEY_UP:
                sel = (sel - 1) % len(menu)
            elif ch == curses.KEY_DOWN:
                sel = (sel + 1) % len(menu)
            elif ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                action = sel
            elif ord('1') <= ch <= ord('6'):
                action = ch - ord('1')
            elif ch in (ord('q'), ord('Q')):
                break

            if action is None:
                continue
            if action == 0: self._live_monitor()
            elif action == 1: self._test_alert_email()
            elif action == 2: self._test_weekly_digest()
            elif action == 3: self._toggle_enable_disable()
            elif action == 4: self._view_queue()
            elif action == 5: break

    # ── Live Monitor ──────────────────────────────────────────────────────────

    def _live_monitor(self):
        """Drop out of curses, stream live logs, re-enter curses on Ctrl+C."""
        curses.endwin()
        print("\033[1;34m")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║        MerIT Vision AI  —  Live Daemon Monitor              ║")
        print("║        Press  Ctrl+C  to return to the menu                 ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print("\033[0m", flush=True)

        cmd = None
        for svc in SERVICE_NAMES:
            try:
                probe = subprocess.run(
                    ["journalctl", "-u", svc, "-n", "1", "--no-pager"],
                    capture_output=True, timeout=3,
                )
                if probe.returncode == 0:
                    cmd = ["journalctl", "-u", svc, "-f", "-n", "80", "--no-pager",
                           "--output=short-precise"]
                    break
            except Exception:
                pass

        if cmd is None:
            for candidate in ["/var/ossec/logs/vision_mailer.log",
                               "/var/ossec/logs/alerts/alerts.json"]:
                if os.path.exists(candidate):
                    cmd = ["tail", "-F", "-n", "80", candidate]
                    break

        if cmd is None:
            print("No log source found. Install the service or check paths.")
            input("\nPress Enter to return to the menu...")
        else:
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                pass

        # Re-initialise curses
        self.scr = curses.initscr()
        curses.start_color()
        self._init_colors()
        curses.curs_set(0)
        self.scr.keypad(True)

    # ── Spinner helper ────────────────────────────────────────────────────────

    def _run_with_spinner(self, label, fn, *args, **kwargs):
        """
        Run fn in a background thread while displaying an animated spinner.
        Returns (ok: bool, message: str, return_value: any).
        """
        self.scr.erase()
        self._draw_header(subtitle=label)
        _safe(self.scr, 5, 4, "Initialising…", curses.color_pair(_C_WARN) | curses.A_BOLD)
        self.scr.refresh()

        result = [None, None, None]   # [ok, msg, rv]

        def _worker():
            try:
                rv = fn(*args, **kwargs)
                result[:] = [True, "Done.", rv]
            except Exception as ex:
                result[:] = [False, str(ex), None]

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

        si = 0
        while t.is_alive():
            f = _SPINNER[si % len(_SPINNER)]
            _safe(self.scr, 7, 4,
                  f" {f}  {label} — please wait (AI may take up to 60 s)…",
                  curses.color_pair(_C_WARN))
            self.scr.refresh()
            si += 1
            time.sleep(0.1)

        t.join()
        return result[0], result[1], result[2]

    # ── Test Alert Email ──────────────────────────────────────────────────────

    def _test_alert_email(self):
        self.scr.erase()
        self._draw_header(subtitle="Send Test Alert Email")
        self._draw_footer("  [ENTER] Confirm   [Q] Cancel  ")

        _safe(self.scr, 5, 4,
              f"Send a realistic test alert email to:  {TEST_RECIPIENT}",
              curses.color_pair(_C_NORMAL) | curses.A_BOLD)

        for row, line in enumerate([
            "  • A mock Level-12 authentication-failure alert will be built",
            "  • Ollama AI will generate a real Executive Summary narrative",
            "  • Sent via sendmail to you only — client list is NOT touched",
            "  • This does NOT affect the live queue or digest counters",
        ], start=7):
            _safe(self.scr, row, 4, line, curses.color_pair(_C_DIM))

        _safe(self.scr, 12, 4, "Press ENTER to proceed or Q to cancel.",
              curses.color_pair(_C_WARN))
        self.scr.refresh()

        while True:
            ch = self.scr.getch()
            if ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                break
            if ch in (ord('q'), ord('Q')):
                return

        alert           = dict(TEST_ALERT_DATA)
        alert['timestamp'] = datetime.now().isoformat()

        def _do():
            ai   = _m.get_ai_analysis(alert)
            html = _m.create_html_email(alert, ai, duplicate_count=None, is_internal=False)
            msg  = MIMEMultipart('alternative')
            msg['Subject'] = "[TEST] Vision AI Alert — Level 12 — test-agent-prod-01"
            msg['From']    = f"{_m.SENDER_NAME} <{_m.SENDER_EMAIL}>"
            msg['To']      = TEST_RECIPIENT
            msg.attach(MIMEText(html, 'html'))
            if not _m.SENDMAIL_PATH or not os.path.exists(_m.SENDMAIL_PATH):
                raise RuntimeError(f"sendmail not found at {_m.SENDMAIL_PATH}")
            subprocess.run([_m.SENDMAIL_PATH, '-t', '-oi'],
                           input=msg.as_bytes(), check=True, timeout=15)

        ok, msg_txt, _ = self._run_with_spinner("Sending test alert email", _do)
        self._show_result(
            ok,
            f"Test alert email delivered to {TEST_RECIPIENT}" if ok else msg_txt,
        )

    # ── Test Weekly Digest ────────────────────────────────────────────────────

    def _test_weekly_digest(self):
        self.scr.erase()
        self._draw_header(subtitle="Send Test Weekly Digest")
        self._draw_footer("  [ENTER] Confirm   [Q] Cancel  ")

        _safe(self.scr, 5, 4,
              f"Send a test weekly digest to:  {TEST_RECIPIENT}",
              curses.color_pair(_C_NORMAL) | curses.A_BOLD)

        for row, line in enumerate([
            "  • Uses real recorded alert data if available, else synthetic samples",
            "  • Ollama AI will generate a real weekly security narrative",
            "  • Sent ONLY to you — client distribution list is NOT touched",
            "  • Does NOT reset the production weekly digest counter",
        ], start=7):
            _safe(self.scr, row, 4, line, curses.color_pair(_C_DIM))

        _safe(self.scr, 12, 4, "Press ENTER to proceed or Q to cancel.",
              curses.color_pair(_C_WARN))
        self.scr.refresh()

        while True:
            ch = self.scr.getch()
            if ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                break
            if ch in (ord('q'), ord('Q')):
                return

        def _do():
            import requests as _rq

            with _m.digest_lock:
                data = _m.load_digest_data()
            alerts = data.get('alerts', []) or _build_synthetic_digest_alerts()

            stats      = _m.build_digest_stats(alerts)
            now        = datetime.now()
            week_end   = now.strftime('%Y-%m-%d')
            week_start = data.get('week_start',
                                  (now - timedelta(days=6)).strftime('%Y-%m-%d'))

            stats_text = (
                f"Week: {week_start} to {week_end}\n"
                f"Total Alerts: {stats['total']}\n"
                f"Critical (Level 15+): {stats['critical']}\n"
                f"High (Level 13-14): {stats['high']}\n"
                f"Medium (Level 11-12): {stats['medium']}\n\n"
                "Top 5 Most Affected Agents:\n"
                + "\n".join(f"  {i+1}. {a} ({c} alerts)"
                             for i, (a, c) in enumerate(stats['top_agents']))
                + "\n\nTop 10 Alert Types:\n"
                + "\n".join(f"  - {r}: {c} occurrences"
                             for r, c in stats['top_rules'])
                + "\n\nDaily Activity:\n"
                + "\n".join(f"  {d}: {c} alerts" for d, c in stats['by_day'])
                + "\n\n[NOTE: This is a TEST digest sent from the vaimailer control panel.]"
            )

            ai_content = None
            try:
                payload = {
                    "model":  _m.OLLAMA_MODEL,
                    "prompt": _m.WEEKLY_DIGEST_AI_PROMPT.format(stats_data=stats_text),
                    "stream": False,
                }
                r = _rq.post(_m.OLLAMA_URL, json=payload, timeout=600)
                r.raise_for_status()
                ai_content = r.json().get('response')
            except Exception as ex:
                ai_content = f"<p><em>(AI narrative unavailable during test: {ex})</em></p>"

            html = _m.create_weekly_digest_html(stats, ai_content, week_start, week_end)
            msg  = MIMEMultipart('alternative')
            msg['Subject'] = f"[TEST] Vision AI Weekly Digest — Week of {week_start}"
            msg['From']    = f"{_m.SENDER_NAME} <{_m.SENDER_EMAIL}>"
            msg['To']      = TEST_RECIPIENT
            msg.attach(MIMEText(html, 'html'))

            if not _m.SENDMAIL_PATH or not os.path.exists(_m.SENDMAIL_PATH):
                raise RuntimeError(f"sendmail not found at {_m.SENDMAIL_PATH}")
            subprocess.run([_m.SENDMAIL_PATH, '-t', '-oi'],
                           input=msg.as_bytes(), check=True, timeout=15)

        ok, msg_txt, _ = self._run_with_spinner(
            "Generating and sending test weekly digest", _do
        )
        self._show_result(
            ok,
            f"Test weekly digest delivered to {TEST_RECIPIENT}" if ok else msg_txt,
        )

    # ── Enable / Disable ──────────────────────────────────────────────────────

    def _toggle_enable_disable(self):
        enabled = _m.is_mailer_enabled()
        action  = "DISABLE" if enabled else "ENABLE"
        verb    = "disable" if enabled else "re-enable"
        color   = (curses.color_pair(_C_DISABLED) if enabled
                   else curses.color_pair(_C_ENABLED))

        self.scr.erase()
        self._draw_header(subtitle=f"{action} Mailer")
        self._draw_footer("  [ENTER] Confirm   [Q] Cancel  ")

        _safe(self.scr, 5, 4,
              f"Are you sure you want to {verb} the Vision AI mailer?",
              color | curses.A_BOLD)

        if enabled:
            notes = [
                "  While DISABLED:",
                "    • Incoming alerts will be marked HELD in the queue (not emailed)",
                "    • The Friday weekly digest scheduler continues to run",
                "    • Re-enable instantly from this menu at any time",
            ]
        else:
            notes = [
                "  Re-enabling will resume normal alert email delivery immediately.",
                "  Any HELD queue entries will NOT be re-sent (they are logged only).",
            ]

        for row, line in enumerate(notes, start=7):
            _safe(self.scr, row, 4, line, curses.color_pair(_C_DIM))

        _safe(self.scr, 12, 4, f"Press ENTER to {action} or Q to cancel.",
              curses.color_pair(_C_WARN))
        self.scr.refresh()

        while True:
            ch = self.scr.getch()
            if ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                break
            if ch in (ord('q'), ord('Q')):
                return

        try:
            if enabled:
                with open(_m.DISABLE_FLAG_FILE, 'w') as f:
                    f.write(datetime.now().isoformat())
                self._show_result(True, "Mailer DISABLED. Alerts will be held in the queue.")
            else:
                os.remove(_m.DISABLE_FLAG_FILE)
                self._show_result(True, "Mailer ENABLED. Alert emails will resume immediately.")
        except Exception as ex:
            self._show_result(False, f"Could not toggle mailer state: {ex}")

    # ── View Alert Queue ──────────────────────────────────────────────────────

    def _view_queue(self):
        try:
            raw_queue = _m.load_queue()
        except Exception as ex:
            self._show_result(False, f"Could not load queue: {ex}")
            return

        # Newest first
        queue  = list(reversed(raw_queue))
        total  = len(queue)
        offset = 0

        _STATUS_ATTR = {
            "SENT":       curses.color_pair(_C_ENABLED)  | curses.A_BOLD,
            "HELD":       curses.color_pair(_C_DISABLED) | curses.A_BOLD,
            "DUPLICATE":  curses.color_pair(_C_DIM),
            "SUPPRESSED": curses.color_pair(_C_DIM),
        }

        while True:
            self.scr.erase()
            h, w = self.scr.getmaxyx()
            PAGE = max(1, h - 13)

            self._draw_header(subtitle="Alert Queue")
            self._draw_footer(
                "  [↑/↓] Scroll   [PgUp/PgDn] Page   [C] Clear queue   [Q] Back  "
            )

            # Column positions
            C_TS, C_LV, C_AG, C_DE, C_ST, C_RT = 2, 22, 27, 47, 66, 75

            hattr = curses.color_pair(_C_TITLE) | curses.A_BOLD
            _safe(self.scr, 5, C_TS, f"{'TIMESTAMP':<19}", hattr)
            _safe(self.scr, 5, C_LV, f"{'LV':<4}",         hattr)
            _safe(self.scr, 5, C_AG, f"{'AGENT':<19}",      hattr)
            _safe(self.scr, 5, C_DE, f"{'DESCRIPTION':<18}", hattr)
            _safe(self.scr, 5, C_ST, f"{'STATUS':<9}",      hattr)
            _safe(self.scr, 5, C_RT, f"{'ROUTE':<6}",       hattr)
            _safe(self.scr, 6, 2, "─" * min(w - 4, 82), curses.color_pair(_C_DIM))

            page_items = queue[offset: offset + PAGE]
            for ri, entry in enumerate(page_items):
                y      = 7 + ri
                status = entry.get('status', '?')
                attr   = _STATUS_ATTR.get(status, curses.color_pair(_C_NORMAL))
                ts     = entry.get('timestamp', '')[:19]
                lv     = str(entry.get('level', '?'))
                ag     = entry.get('agent', 'Unknown')[:18]
                de     = entry.get('rule_desc', '')[:17]
                rt     = entry.get('routed_to', '-')[:5]

                _safe(self.scr, y, C_TS, f"{ts:<20}", curses.color_pair(_C_NORMAL))
                _safe(self.scr, y, C_LV, f"L{lv:<3}",   curses.color_pair(_C_WARN))
                _safe(self.scr, y, C_AG, f"{ag:<19}",   curses.color_pair(_C_NORMAL))
                _safe(self.scr, y, C_DE, f"{de:<18}",   curses.color_pair(_C_DIM))
                _safe(self.scr, y, C_ST, f"{status:<9}", attr)
                _safe(self.scr, y, C_RT, f"{rt:<6}",    curses.color_pair(_C_DIM))

            total_pages = max(1, (total + PAGE - 1) // PAGE)
            page_num    = offset // PAGE + 1
            _safe(self.scr, h - 3, 2,
                  f"  {offset+1}–{min(offset+PAGE, total)} of {total} entries  "
                  f"(Page {page_num}/{total_pages})  ",
                  curses.color_pair(_C_DIM))
            self.scr.refresh()

            ch = self.scr.getch()
            if ch in (ord('q'), ord('Q')):
                break
            elif ch == curses.KEY_UP and offset > 0:
                offset -= 1
            elif ch == curses.KEY_DOWN and offset + PAGE < total:
                offset += 1
            elif ch == curses.KEY_PPAGE:
                offset = max(0, offset - PAGE)
            elif ch == curses.KEY_NPAGE:
                offset = min(max(0, total - PAGE), offset + PAGE)
            elif ch in (ord('c'), ord('C')):
                self._clear_queue_confirm()
                try:
                    raw_queue = _m.load_queue()
                    queue  = list(reversed(raw_queue))
                    total  = len(queue)
                    offset = 0
                except Exception:
                    pass

    def _clear_queue_confirm(self):
        self.scr.erase()
        self._draw_header(subtitle="Clear Queue")
        self._draw_footer("  [ENTER] Confirm   [Q] Cancel  ")
        _safe(self.scr, 5, 4, "Clear ALL queue entries? This cannot be undone.",
              curses.color_pair(_C_DISABLED) | curses.A_BOLD)
        _safe(self.scr, 7, 4, "Press ENTER to confirm or Q to cancel.",
              curses.color_pair(_C_WARN))
        self.scr.refresh()

        while True:
            ch = self.scr.getch()
            if ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                try:
                    with open(_m.ALERT_QUEUE_FILE, 'w') as f:
                        json.dump([], f)
                    self._show_result(True, "Alert queue cleared successfully.")
                except Exception as ex:
                    self._show_result(False, str(ex))
                return
            if ch in (ord('q'), ord('Q')):
                return

    # ── Result screen ─────────────────────────────────────────────────────────

    def _show_result(self, success, message):
        self.scr.erase()
        self._draw_header()
        self._draw_footer("  Press any key to return to menu  ")
        color = (curses.color_pair(_C_ENABLED)  | curses.A_BOLD) if success \
                else (curses.color_pair(_C_DISABLED) | curses.A_BOLD)
        icon  = "  ✔  SUCCESS" if success else "  ✖  ERROR"
        _safe(self.scr, 5, 4, icon,    color)
        _safe(self.scr, 7, 4, message, curses.color_pair(_C_NORMAL))
        _safe(self.scr, 9, 4, "Press any key to return to the menu.",
              curses.color_pair(_C_DIM))
        self.scr.refresh()
        self.scr.getch()


# ── Install helper ────────────────────────────────────────────────────────────

def _install():
    script = os.path.abspath(__file__)
    link   = "/usr/local/bin/vaimailer"
    try:
        # Write a plain shell wrapper — always LF, immune to CRLF in the .py file.
        # This is more reliable than a symlink because the shell reads the shebang
        # of the target file directly when following a symlink, which breaks if the
        # .py file was transferred from Windows with CRLF line endings.
        wrapper = f"#!/bin/sh\nexec python3 {script} \"$@\"\n"
        with open(link, 'w', newline='\n') as f:
            f.write(wrapper)
        os.chmod(link, 0o755)
        print("\033[32m")
        print("  \u2714  Installation successful!")
        print("\033[0m")
        print(f"  Command  :  vaimailer")
        print(f"  Points to:  {script}")
        print()
        print("  You can now run \033[1mvaimailer\033[0m from any terminal on this server.")
    except PermissionError:
        print("\033[31m  \u2716  Permission denied.\033[0m  Run with sudo:")
        print(f"     sudo python3 {script} --install")
    except Exception as ex:
        print(f"\033[31m  \u2716  Install failed: {ex}\033[0m")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if "--install" in sys.argv:
        _install()
        return
    curses.wrapper(lambda scr: VisionAIMailerUI(scr).run())


if __name__ == "__main__":
    main()
