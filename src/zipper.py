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
import hashlib
from datetime import datetime, timezone
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    snapshot_retention: int
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
            snapshot_retention=int(data.get("snapshot_retention", 10)),
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

        run_id = datetime.utcnow().strftime("%Y%m%d%H%M%S") + f"-{os.getpid()}"
        host = socket.gethostname()

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
        if int(config.max_workers) > 1:
            with ThreadPoolExecutor(max_workers=int(config.max_workers)) as executor:
                futures = [
                    executor.submit(
                        _process_folder_with_retries,
                        folder,
                        snapshot_name if zfs_available else None,
                        config,
                        args.dry_run,
                        run_id,
                        host,
                        log,
                    )
                    for folder in to_process
                ]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        log.error("concurrency worker error: %s", e)
        else:
            for folder in to_process:
                success = _process_folder_with_retries(
                    source_folder=folder,
                    snapshot_name=snapshot_name if zfs_available else None,
                    config=config,
                    dry_run=args.dry_run,
                    run_id=run_id,
                    host=host,
                    log=log,
                )
                if not success:
                    # Continue to next folder after notification
                    continue

        if zfs_available and snapshot_name is not None:
            _cleanup_old_snapshots(dataset, config.snapshot_prefix, int(config.snapshot_retention), args.dry_run, log)
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


def _cleanup_old_snapshots(
    dataset: str,
    prefix: str,
    keep: int,
    dry_run: bool,
    log: logging.Logger,
) -> None:
    code, out, err = _run_cmd(
        ["zfs", "list", "-t", "snapshot", "-H", "-o", "name", "-s", "creation", "-r", dataset],
        log,
    )
    if code != 0:
        log.error("zfs list snapshots failed: %s", err.strip())
        return
    snaps: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "@" not in line:
            continue
        ds, sn = line.split("@", 1)
        if ds != dataset or not sn.startswith(prefix + "-"):
            continue
        snaps.append(sn)
    if len(snaps) <= keep:
        return
    to_delete = snaps[0 : max(0, len(snaps) - keep)]
    for sn in to_delete:
        full = f"{dataset}@{sn}"
        if dry_run:
            log.info("dry-run: would destroy snapshot %s", full)
        else:
            code, _, err = _run_cmd(["zfs", "destroy", full], log)
            if code != 0:
                log.error("failed to destroy snapshot %s: %s", full, err.strip())


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


# -----------------
# Archiving
# -----------------

def _process_folder_with_retries(
    source_folder: Path,
    snapshot_name: str | None,
    config: AppConfig,
    dry_run: bool,
    run_id: str,
    host: str,
    log: logging.Logger,
) -> bool:
    last_err: Exception | None = None
    for attempt in range(1, int(config.retries) + 1):
        try:
            _process_folder_once(source_folder, snapshot_name, config, dry_run, log)
            return True
        except Exception as e:
            last_err = e
            wait_sec = min(60, 2 ** attempt)
            log.error(
                "attempt %d/%d failed for %s: %s; retrying in %ss",
                attempt,
                config.retries,
                source_folder.name,
                e,
                wait_sec,
            )
            try:
                time.sleep(wait_sec)
            except Exception:
                pass
    # Final failure
    msg = (
        f"Backup failed on {host}\n"
        f"Run: {run_id}\n"
        f"Folder: {source_folder.name}\n"
        f"Source: {source_folder}\n"
        f"Target: {config.target_path / source_folder.name}\n"
        f"Snapshot: {snapshot_name or 'none'}\n"
        f"Attempts: {config.retries}\n"
        f"Error: {type(last_err).__name__}: {last_err}"
    )
    _send_gotify(
        gotify=config.gotify,
        title="Zipper job: backup failed",
        message=msg,
        priority=config.gotify.priority,
        log=log,
    )
    log.error(msg)
    return False


def _process_folder_once(
    source_folder: Path,
    snapshot_name: str | None,
    config: AppConfig,
    dry_run: bool,
    log: logging.Logger,
) -> None:
    folder_name = source_folder.name
    assert re.fullmatch(r"^[A-Z0-9]{4}$", folder_name), "invalid folder name"

    # Collect files
    file_list: list[Path] = []
    total_bytes = 0
    for root, dirs, files in os.walk(source_folder, followlinks=False):
        # Skip any symlinks in dirs
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for fname in files:
            full_path = Path(root) / fname
            try:
                st = os.lstat(full_path)
            except FileNotFoundError:
                continue
            # Regular files only
            if not stat_is_regular(st.st_mode):
                continue
            if os.path.islink(full_path):
                continue
            file_list.append(full_path)
            total_bytes += st.st_size

    rel_paths = [str(p.relative_to(source_folder)) for p in file_list]
    zip_name = f"{folder_name}.zip"

    # Temp paths
    run_tag = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    tmp_run_dir = config.tmp_dir / f"zipper-{run_tag}-{folder_name}"
    tmp_run_dir.mkdir(parents=True, exist_ok=True)
    tmp_zip = tmp_run_dir / zip_name
    tmp_meta = tmp_run_dir / "metadata.json"
    tmp_md5 = tmp_run_dir / f"{zip_name}.md5"
    tmp_sha256 = tmp_run_dir / f"{zip_name}.sha256"

    # Create zip
    if dry_run:
        log.info("dry-run: would zip %s into %s", folder_name, tmp_zip)
    else:
        _create_zip(tmp_zip, source_folder, file_list)
        _verify_zip_readable(tmp_zip)

    # Hashes
    if dry_run:
        zip_md5 = "0" * 32
        zip_sha256 = "0" * 64
    else:
        zip_md5 = _hash_file(tmp_zip, "md5")
        zip_sha256 = _hash_file(tmp_zip, "sha256")
        _write_text(tmp_md5, f"{zip_md5}  {zip_name}\n")
        _write_text(tmp_sha256, f"{zip_sha256}  {zip_name}\n")

    # Metadata
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "zip_name": zip_name,
        "files": rel_paths,
        "zip_md5": zip_md5,
        "zip_sha256": zip_sha256,
        "total_files": len(rel_paths),
        "total_bytes": int(total_bytes),
        "created_at_utc": created,
        "snapshot": snapshot_name or "none",
    }
    if dry_run:
        log.info("dry-run: would write metadata for %s", folder_name)
    else:
        with tmp_meta.open("w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, sort_keys=True)

    # Target org and rotation (scheme A)
    target_dir = config.target_path / folder_name
    if dry_run:
        log.info("dry-run: would ensure target dir %s", target_dir)
    else:
        target_dir.mkdir(parents=True, exist_ok=True)

    current_zip = target_dir / zip_name
    prev_zip = target_dir / f"{folder_name}.prev.zip"
    current_meta = target_dir / "metadata.json"
    prev_meta = target_dir / "metadata.prev.json"
    current_md5 = target_dir / f"{zip_name}.md5"
    prev_md5 = target_dir / f"{folder_name}.prev.zip.md5"
    current_sha256 = target_dir / f"{zip_name}.sha256"
    prev_sha256 = target_dir / f"{folder_name}.prev.zip.sha256"

    if not dry_run:
        # Delete old prev
        for p in (prev_zip, prev_meta, prev_md5, prev_sha256):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        # Rotate current to prev if exists
        if current_zip.exists():
            current_zip.rename(prev_zip)
        if current_meta.exists():
            current_meta.rename(prev_meta)
        if current_md5.exists():
            current_md5.rename(prev_md5)
        if current_sha256.exists():
            current_sha256.rename(prev_sha256)

        # Move new files atomically into place
        os.replace(tmp_zip, current_zip)
        os.replace(tmp_meta, current_meta)
        if tmp_md5.exists():
            os.replace(tmp_md5, current_md5)
        if tmp_sha256.exists():
            os.replace(tmp_sha256, current_sha256)

        # Cleanup temp dir (best-effort)
        try:
            tmp_run_dir.rmdir()
        except Exception:
            pass

    log.info("done: %s -> %s", folder_name, target_dir)


def _create_zip(zip_path: Path, source_folder: Path, file_list: list[Path]) -> None:
    import zipfile

    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for f in file_list:
            arcname = str(f.relative_to(source_folder))
            zf.write(f, arcname)


def _verify_zip_readable(zip_path: Path) -> None:
    import zipfile

    with zipfile.ZipFile(zip_path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise RuntimeError(f"zip verify failed, first bad entry: {bad}")


def _hash_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_text(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(content)


def stat_is_regular(mode: int) -> bool:
    import stat as pystat

    return pystat.S_ISREG(mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

