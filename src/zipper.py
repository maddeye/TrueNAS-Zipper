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
    return parser.parse_args(argv)


def setup_logging(log_file: Path, verbosity: int) -> logging.Logger:
    log = logging.getLogger("zipper")
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        str(log_file), maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    log.addHandler(file_handler)

    # Syslog handler (FreeBSD: /var/run/log)
    try:
        syslog_handler = logging.handlers.SysLogHandler(address="/var/run/log")
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
        # Implementation will follow in subsequent steps.
        return 0
    finally:
        try:
            if lock_fd is not None:
                os.close(lock_fd)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


