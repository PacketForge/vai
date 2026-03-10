#!/usr/bin/env python3
"""
wazuh_log_retention.py — Wazuh Log Housekeeping Daemon

Two scheduled tasks — both run at startup, then every 24 hours:

  1. RETENTION (every 24 h)
       Delete compressed (.gz) alert and archive log files that are older
       than RETENTION_DAYS (default 90).  Empty year/month subdirectories
       are pruned automatically after each pass.

  2. LOW-LEVEL PURGE (every 24 h)
       Open every rotated (.json.gz) file that is NOT today's active log,
       strip out any JSON entry whose rule.level is below
       LOW_LEVEL_THRESHOLD (default 7), then rewrite the file atomically.
       This keeps archives lean without touching live data.

Usage:
  # Run as a long-lived daemon (loops every hour):
  python3 wazuh_log_retention.py

  # Single pass then exit — good for cron:
  python3 wazuh_log_retention.py --run-once

  # Preview what would change without touching any files:
  python3 wazuh_log_retention.py --dry-run --run-once
"""

import argparse
import gzip
import json
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path


# ─── Configuration ────────────────────────────────────────────────────────────

RETENTION_DAYS      = 90    # delete .gz files older than this many days
LOW_LEVEL_THRESHOLD = 7     # purge alert entries with rule.level strictly below this
CHECK_INTERVAL_SECS = 3600  # seconds between daemon passes (1 hour)

# Wazuh log directories (alerts and full archives)
ALERT_LOG_DIR   = Path("/var/ossec/logs/alerts")
ARCHIVE_LOG_DIR = Path("/var/ossec/logs/archives")

# Housekeeping state / PID files
PID_FILE        = Path("/var/ossec/logs/wazuh_retention.pid")
STATE_FILE      = Path("/var/ossec/logs/wazuh_retention_state.json")
DAEMON_LOG_FILE = Path("/var/ossec/logs/wazuh_retention.log")


# ─── Logging ──────────────────────────────────────────────────────────────────

def _setup_logging():
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in (
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(DAEMON_LOG_FILE, encoding="utf-8"),
    ):
        handler.setFormatter(fmt)
        root.addHandler(handler)


log = logging.getLogger("wazuh_retention")


# ─── State helpers ────────────────────────────────────────────────────────────

def _load_state():
    try:
        if STATE_FILE.exists():
            with STATE_FILE.open() as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_state(state):
    """Write state file atomically so a partial write never corrupts it."""
    try:
        fd, tmp = tempfile.mkstemp(dir=STATE_FILE.parent, prefix=".wrl_state_")
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        shutil.move(tmp, str(STATE_FILE))
    except Exception as e:
        log.warning("Could not save state: %s", e)


def _should_run(state, key):
    """Return True if 24 h have elapsed since the last successful run of `key`."""
    last = state.get(key)
    if not last:
        return True
    try:
        return (datetime.now() - datetime.fromisoformat(last)) >= timedelta(hours=24)
    except Exception:
        return True


# ─── 90-day Retention ─────────────────────────────────────────────────────────

def run_retention(dry_run=False):
    """
    Walk alert and archive directories.  Any compressed log file whose
    modification time is older than RETENTION_DAYS is deleted.
    """
    cutoff        = datetime.now() - timedelta(days=RETENTION_DAYS)
    deleted_count = 0
    deleted_bytes = 0

    for log_dir in (ALERT_LOG_DIR, ARCHIVE_LOG_DIR):
        if not log_dir.exists():
            log.debug("Directory not found, skipping: %s", log_dir)
            continue

        for path in log_dir.rglob("*"):
            if not path.is_file():
                continue
            # Only touch rotated / compressed files — never the live .json or .log
            if path.suffix not in (".gz", ".zip"):
                continue

            try:
                stat     = path.stat()
                mtime    = datetime.fromtimestamp(stat.st_mtime)
                size     = stat.st_size
                age_days = (datetime.now() - mtime).days

                if mtime >= cutoff:
                    continue

                if dry_run:
                    log.info(
                        "[DRY-RUN] Would delete (%d days old, %.1f KB): %s",
                        age_days, size / 1024, path,
                    )
                else:
                    path.unlink()
                    log.info(
                        "DELETED (%d days old, %.1f KB): %s",
                        age_days, size / 1024, path,
                    )

                deleted_count += 1
                deleted_bytes += size

            except Exception as e:
                log.warning("Could not process %s: %s", path, e)

        # Remove leftover empty year/month subdirectories
        if not dry_run:
            for path in sorted(log_dir.rglob("*"), reverse=True):
                if path.is_dir():
                    try:
                        path.rmdir()  # only succeeds when the directory is empty
                        log.info("REMOVED empty directory: %s", path)
                    except OSError:
                        pass  # not empty — that's fine

    log.info(
        "Retention pass complete — %d file(s) %s, %.2f MB %s.",
        deleted_count,
        "would be deleted" if dry_run else "deleted",
        deleted_bytes / (1024 * 1024),
        "would be freed"   if dry_run else "freed",
    )


# ─── 24-hour Low-level Entry Purge ────────────────────────────────────────────

def _is_todays_file(path):
    """
    Return True if the file's mtime is today — those files may still be
    actively written by Wazuh and must not be modified.
    """
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
        return mtime.date() == datetime.now().date()
    except Exception:
        return True  # if we can't stat it, assume it's active


def _purge_file(path, dry_run=False):
    """
    Read a .json.gz file line by line, discard any JSON entry whose
    rule.level < LOW_LEVEL_THRESHOLD, and write the filtered result back
    to the same path atomically.

    Returns (lines_kept, lines_removed).
    """
    kept    = []
    removed = 0

    try:
        with gzip.open(str(path), "rt", encoding="utf-8", errors="replace") as gz:
            for raw in gz:
                raw = raw.rstrip("\n")
                if not raw:
                    continue
                try:
                    obj   = json.loads(raw)
                    level = obj.get("rule", {}).get("level", 0)
                    if level >= LOW_LEVEL_THRESHOLD:
                        kept.append(raw)
                    else:
                        removed += 1
                except json.JSONDecodeError:
                    kept.append(raw)  # non-JSON line — preserve as-is
    except Exception as e:
        log.warning("Could not read %s: %s", path, e)
        return 0, 0

    if removed == 0:
        return len(kept), 0  # nothing to do

    if dry_run:
        log.info(
            "[DRY-RUN] Would remove %d low-level entries from %s (%d kept)",
            removed, path, len(kept),
        )
        return len(kept), removed

    # If every entry was below threshold, just delete the file entirely
    if not kept:
        try:
            path.unlink()
            log.info(
                "DELETED (all %d entries were below L%d): %s",
                removed, LOW_LEVEL_THRESHOLD, path,
            )
        except Exception as e:
            log.warning("Could not delete empty result file %s: %s", path, e)
        return 0, removed

    # Atomic rewrite: compress into a temp file, then replace the original
    fd, tmp_path = tempfile.mkstemp(suffix=".gz", dir=path.parent, prefix=".tmpret_")
    try:
        with os.fdopen(fd, "wb") as raw_fd:
            with gzip.GzipFile(fileobj=raw_fd, mode="wb") as gz_out:
                for line in kept:
                    gz_out.write((line + "\n").encode("utf-8"))
        shutil.move(tmp_path, str(path))
        log.info(
            "PURGED %d low-level entries from %s (%d entries kept)",
            removed, path, len(kept),
        )
    except Exception as e:
        log.warning("Could not rewrite %s: %s", path, e)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return 0, 0

    return len(kept), removed


def run_low_level_purge(dry_run=False):
    """
    Iterate over all rotated .json.gz alert and archive files.
    Skip any file last modified today (may still be active).
    Strip entries whose rule.level is below LOW_LEVEL_THRESHOLD.
    """
    total_removed = 0
    files_touched = 0

    for log_dir in (ALERT_LOG_DIR, ARCHIVE_LOG_DIR):
        if not log_dir.exists():
            continue
        for path in log_dir.rglob("*.json.gz"):
            if _is_todays_file(path):
                log.debug("SKIP (active today): %s", path)
                continue
            kept, removed = _purge_file(path, dry_run=dry_run)
            if removed > 0:
                files_touched += 1
                total_removed += removed

    log.info(
        "Low-level purge complete — %d %s from %d file(s).",
        total_removed,
        "entries would be removed" if dry_run else "entries removed",
        files_touched,
    )


# ─── PID management ───────────────────────────────────────────────────────────

def _write_pid():
    try:
        with PID_FILE.open("w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        log.warning("Could not write PID file: %s", e)


def _remove_pid():
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except Exception:
        pass


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Wazuh log retention and low-level purge daemon"
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run a single pass and exit (good for cron jobs)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would happen without modifying any files",
    )
    args = parser.parse_args()

    _setup_logging()
    _write_pid()
    signal.signal(signal.SIGTERM, lambda *_: (_remove_pid(), sys.exit(0)))

    log.info(
        "Wazuh log retention started  PID=%d  retention=%dd  "
        "low-level-threshold=L%d  dry_run=%s",
        os.getpid(), RETENTION_DAYS, LOW_LEVEL_THRESHOLD, args.dry_run,
    )

    try:
        while True:
            state = _load_state()

            if _should_run(state, "retention"):
                log.info("── 90-day retention pass ──────────────────────")
                run_retention(dry_run=args.dry_run)
                if not args.dry_run:
                    state["retention"] = datetime.now().isoformat()
                    _save_state(state)

            if _should_run(state, "low_level_purge"):
                log.info(
                    "── low-level purge (L < %d) ─────────────────────",
                    LOW_LEVEL_THRESHOLD,
                )
                run_low_level_purge(dry_run=args.dry_run)
                if not args.dry_run:
                    state["low_level_purge"] = datetime.now().isoformat()
                    _save_state(state)

            if args.run_once:
                log.info("--run-once complete, exiting.")
                break

            log.info("Sleeping %d s until next check...", CHECK_INTERVAL_SECS)
            time.sleep(CHECK_INTERVAL_SECS)

    except KeyboardInterrupt:
        log.info("Interrupted — stopping.")
    finally:
        _remove_pid()
        log.info("Wazuh log retention daemon stopped.")


if __name__ == "__main__":
    main()
