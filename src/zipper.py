#!/usr/local/bin/python3
"""Zipper job CLI skeleton for TrueNAS CORE.

Loads configuration, sets up logging, acquires a lock, and prepares to
perform snapshot-based processing. Implementation steps will follow.
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import sys
import re
import subprocess
import time
import shutil
import urllib.request
import urllib.error
import json as jsonlib
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl  # FreeBSD/Unix locking
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore


@dataclass
class GotifyConfig:
    url: str
    token: str
    priority: int = 5
    timeout_seconds: int = 10


@dataclass
class AppConfig:
    source_path: Path
    target_path: Path
    snapshot_prefix: str
    max_workers: int
    retries: int
    nice: int
    umask: str
    lockfile_path: Path
    tmp_dir: Path
    log_file: Path
    gotify: GotifyConfig

    @staticmethod
    def from_dict(data: dict) -> "AppConfig":
        required = [
            "source_path",
            "target_path",
            "snapshot_prefix",
            "max_workers",
            "retries",
            "nice",
            "umask",
            "lockfile_path",
            "tmp_dir",
            "log_file",
            "gotify",
        ]
        for key in required:
            if key not in data:
                raise ValueError(f"Missing required config key: {key}")
        gotify_data = data["gotify"]
        for k in ["url", "token"]:
            if k not in gotify_data:
                raise ValueError(f"Missing gotify config key: {k}")
        return AppConfig(
            source_path=Path(data["source_path"]).resolve(),
            target_path=Path(data["target_path"]).resolve(),
            snapshot_prefix=str(data["snapshot_prefix"]),
            max_workers=int(data["max_workers"]),
            retries=int(data["retries"]),
            nice=int(data["nice"]),
            umask=str(data["umask"]),
            lockfile_path=Path(data["lockfile_path"]).resolve(),
            tmp_dir=Path(data["tmp_dir"]).resolve(),
            log_file=Path(data["log_file"]).resolve(),
            gotify=GotifyConfig(
                url=str(gotify_data["url"]),
                token=str(gotify_data["token"]),
                priority=int(gotify_data.get("priority", 5)),
                timeout_seconds=int(gotify_data.get("timeout_seconds", 10)),
            ),
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ZFS zipper job")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--dry-run", action="store_true", help="Do not modify anything")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--send-gotify", metavar="MESSAGE", help="Send a test Gotify message and exit")
    parser.add_argument("--title", default="zipper debug", help="Title for --send-gotify")
    parser.add_argument("--priority", type=int, help="Priority override for --send-gotify")
    return parser.parse_args(argv)


def setup_logging(log_file: Path, verbosity: int) -> logging.Logger:
    log = logging.getLogger("zipper")
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    # File handler with fallback if unwritable
    file_handler = None
    try:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file), maxBytes=5 * 1024 * 1024, backupCount=3
        )
    except Exception:
        fallback = Path.cwd() / "zipper.log"
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                str(fallback), maxBytes=5 * 1024 * 1024, backupCount=3
            )
        except Exception:
            file_handler = None
    if file_handler is not None:
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        log.addHandler(file_handler)

    # Syslog handler (FreeBSD: /var/run/log; Linux: /dev/log). Only if root.
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            syslog_socket = None
            for candidate in ("/var/run/log", "/dev/log"):
                if Path(candidate).exists():
                    syslog_socket = candidate
                    break
            if syslog_socket is not None:
                syslog_handler = logging.handlers.SysLogHandler(address=syslog_socket)
                syslog_handler.setLevel(logging.INFO)
                syslog_handler.setFormatter(logging.Formatter("zipper: %(levelname)s %(message)s"))
                log.addHandler(syslog_handler)
    except Exception:
        # Fall back silently if syslog unavailable
        pass

    # STDERR based on verbosity
    if verbosity > 0:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.DEBUG if verbosity > 1 else logging.INFO)
        stderr_handler.setFormatter(fmt)
        log.addHandler(stderr_handler)

    return log


def load_config(path: Path) -> AppConfig:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return AppConfig.from_dict(data)


def set_umask_and_nice(umask_str: str, nice_value: int, log: logging.Logger) -> None:
    try:
        os.umask(int(umask_str, 8))
    except Exception as e:
        log.warning("Failed to set umask %s: %s", umask_str, e)
    try:
        os.nice(int(nice_value))
    except Exception as e:
        log.warning("Failed to set nice %s: %s", nice_value, e)


def acquire_lock(lockfile_path: Path, log: logging.Logger) -> int | None:
    try:
        lock_fd = os.open(str(lockfile_path), os.O_CREAT | os.O_RDWR, 0o644)
        if fcntl is None:
            log.warning("fcntl not available; skipping lock")
            return lock_fd
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(lock_fd, str(os.getpid()).encode("ascii"))
        return lock_fd
    except BlockingIOError:
        log.error("Another instance is running (lock held): %s", lockfile_path)
        return None
    except Exception as e:
        log.error("Failed to acquire lock %s: %s", lockfile_path, e)
        return None


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    config_path = Path(args.config)
    config = load_config(config_path)

    log = setup_logging(config.log_file, args.verbose)
    set_umask_and_nice(config.umask, config.nice, log)

    lock_fd = acquire_lock(config.lockfile_path, log)
    if lock_fd is None:
        return 2

    try:
        log.info("startup: dry_run=%s workers=%s", args.dry_run, config.max_workers)

        # Debug path: send Gotify and exit
        if args.send_gotify is not None:
            prio = args.priority if args.priority is not None else config.gotify.priority
            ok = _send_gotify(
                gotify=config.gotify,
                title=args.title,
                message=args.send_gotify,
                priority=prio,
                log=log,
            )
            return 0 if ok else 1

        zfs_available = shutil.which("zfs") is not None
        dataset = None
        snapshot_name = None
        prev_snapshot = None
        changed_paths: set[str] = set()

        if zfs_available:
            dataset = _find_dataset_for_path(config.source_path, log)
            if dataset is None:
                log.error("failed to resolve dataset for %s", config.source_path)
                return 1

            mountpoint = _get_dataset_mountpoint(dataset, log)
            if mountpoint is None:
                log.error("failed to resolve mountpoint for %s", dataset)
                return 1

            snapshot_name = _create_snapshot(dataset, config.snapshot_prefix, args.dry_run, log)
            if snapshot_name is None:
                log.error("failed to create snapshot for %s", dataset)
                return 1
            snapshot_path = _snapshot_path(Path(mountpoint), snapshot_name)
            log.info("snapshot ready: %s at %s", snapshot_name, snapshot_path)

            prev_snapshot = _previous_snapshot(dataset, config.snapshot_prefix, snapshot_name, log)
            if prev_snapshot:
                log.info("previous snapshot: %s", prev_snapshot)
            else:
                log.info("no previous snapshot; full scan")

            if prev_snapshot:
                changed_paths = _zfs_diff_paths(dataset, prev_snapshot, snapshot_name, log)
                log.info("zfs diff reports %d changed paths", len(changed_paths))

            source_root = Path(snapshot_path)
        else:
            log.info("zfs not found; planning without snapshot")
            source_root = config.source_path

        valid_folder_pattern = re.compile(r"^[A-Z0-9]{4}$")
        if not source_root.is_dir():
            log.error("snapshot root is not a directory: %s", source_root)
            return 1

        folders: list[Path] = []
        for entry in sorted(source_root.iterdir()):
            if not entry.is_dir():
                continue
            name = entry.name
            if not valid_folder_pattern.match(name):
                continue
            folders.append(entry)

        log.info("found %d candidate folders", len(folders))

        to_process: list[Path] = []
        if prev_snapshot:
            for folder in folders:
                # Determine if any changed path falls under this folder
                prefix = f"/{folder.name}/"
                # zfs diff paths are absolute relative to the dataset root
                if any(p == f"/{folder.name}" or p.startswith(prefix) for p in changed_paths):
                    to_process.append(folder)
        else:
            to_process = folders

        log.info("%d folders to process", len(to_process))
        for folder in to_process:
            log.info("plan: would process %s", folder.name)
        # Archiving implementation will follow in subsequent steps.
        return 0
    finally:
        try:
            if lock_fd is not None:
                os.close(lock_fd)
        except Exception:
            pass

# -----------------
# ZFS helpers
# -----------------

def _run_cmd(cmd: list[str], log: logging.Logger, timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        log.error("command timed out: %s", " ".join(cmd))
        return 124, "", "timeout"
    except Exception as e:
        log.error("command failed: %s (%s)", " ".join(cmd), e)
        return 1, "", str(e)


def _find_dataset_for_path(path: Path, log: logging.Logger) -> str | None:
    abs_path = str(path)
    code, out, err = _run_cmd(["zfs", "list", "-H", "-o", "name,mountpoint"], log)
    if code != 0:
        log.error("zfs list failed: %s", err.strip())
        return None
    best_match: tuple[str, str] | None = None
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        ds, mp = parts
        if mp == "-":
            continue
        if abs_path == mp or abs_path.startswith(mp.rstrip("/") + "/"):
            if best_match is None or len(mp) > len(best_match[1]):
                best_match = (ds, mp)
    return best_match[0] if best_match else None


def _get_dataset_mountpoint(dataset: str, log: logging.Logger) -> str | None:
    code, out, err = _run_cmd(["zfs", "list", "-H", "-o", "mountpoint", dataset], log)
    if code != 0:
        log.error("zfs list mountpoint failed: %s", err.strip())
        return None
    mp = out.strip()
    return None if not mp or mp == "-" else mp


def _create_snapshot(dataset: str, prefix: str, dry_run: bool, log: logging.Logger) -> str | None:
    ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    snap_name = f"{prefix}-{ts}"
    full = f"{dataset}@{snap_name}"
    if dry_run:
        log.info("dry-run: would create snapshot %s", full)
        return snap_name
    code, out, err = _run_cmd(["zfs", "snapshot", "-r", full], log)
    if code != 0:
        log.error("zfs snapshot failed: %s", err.strip())
        return None
    return snap_name


def _previous_snapshot(dataset: str, prefix: str, current: str, log: logging.Logger) -> str | None:
    code, out, err = _run_cmd(["zfs", "list", "-t", "snapshot", "-H", "-o", "name", "-s", "creation", "-r", dataset], log)
    if code != 0:
        log.error("zfs list snapshots failed: %s", err.strip())
        return None
    snaps: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "@" not in line:
            continue
        ds, sn = line.split("@", 1)
        if ds != dataset:
            continue
        if not sn.startswith(prefix + "-"):
            continue
        snaps.append(sn)
    snaps = [s for s in snaps if s != current]
    return snaps[-1] if snaps else None


def _snapshot_path(mountpoint: Path, snapshot_name: str) -> Path:
    return mountpoint / ".zfs" / "snapshot" / snapshot_name


def _zfs_diff_paths(dataset: str, prev: str, curr: str, log: logging.Logger) -> set[str]:
    code, out, err = _run_cmd(["zfs", "diff", "-H", f"{dataset}@{prev}", f"{dataset}@{curr}"], log, timeout=120)
    if code != 0:
        log.error("zfs diff failed: %s", err.strip())
        return set()
    paths: set[str] = set()
    for line in out.splitlines():
        # Format: <change>\t<path>
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        path = parts[-1].strip()
        if not path:
            continue
        # Convert to dataset-rooted path
        # zfs diff typically prints like /mountpoint/relpath; but we need relative to dataset root.
        # We'll strip the mountpoint prefix if present.
        paths.add(_strip_mountpoint(dataset, path, log))
    return paths


def _strip_mountpoint(dataset: str, full_path: str, log: logging.Logger) -> str:
    mp = _get_dataset_mountpoint(dataset, log)
    if not mp:
        return full_path
    if full_path == mp:
        return "/"
    if full_path.startswith(mp.rstrip("/") + "/"):
        return full_path[len(mp) :]
    return full_path


# -----------------
# Notifications
# -----------------

def _send_gotify(
    gotify: GotifyConfig,
    title: str,
    message: str,
    priority: int,
    log: logging.Logger,
) -> bool:
    payload = {
        "title": title,
        "message": message,
        "priority": int(priority),
    }
    data = jsonlib.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=gotify.url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Gotify-Key": gotify.token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=gotify.timeout_seconds) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            if 200 <= code < 300:
                log.info("gotify sent: %s (%s)", title, code)
                return True
            else:
                body = resp.read().decode("utf-8", errors="ignore")
                log.error("gotify failed: HTTP %s: %s", code, body)
                return False
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        log.error("gotify http error: %s %s", e.code, body)
        return False
    except Exception as e:
        log.error("gotify error: %s", e)
        return False


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

