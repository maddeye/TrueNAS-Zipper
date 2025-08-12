## Zipping job (TrueNAS CORE) — Project TODO

Scope: Hourly cron job scans a source dataset for subfolders named with 4 uppercase alphanumerics (regex `^[A-Z0-9]{4}$`), zips each valid folder (all files and subdirectories) into `SOURCE.zip`, generates `metadata.json`, computes MD5 and SHA-256, and moves results to a matching subfolder under the target path. Operates from a read-only ZFS snapshot for atomicity and consistent reads. Logs to syslog and file, notifies via Gotify on failures, retries transient errors up to 3 times, and enforces retention of only the newest 2 archives per source folder.

### Decisions (confirmed)
- [x] Metadata schema: include `zip_name` and `files`, plus enriched fields as available (hashes, counts, snapshot, timestamps)
- [x] Retention scheme: A — rename existing `SOURCE.zip` → `SOURCE.prev.zip` and `metadata.json` → `metadata.prev.json`
- [x] Snapshot naming: `auto-zip-YYYYmmddHHMMSS`
- [x] Concurrency default: 1 (sequential) on N40L; configurable higher

### Proposed metadata.json (final)
```json
{
  "zip_name": "ABCD.zip",
  "files": [
    "relative/path/inside/source/file1.mp4",
    "relative/path/inside/source/sub/track.flac"
  ],
  "zip_md5": "<md5-hex>",
  "zip_sha256": "<sha256-hex>",
  "total_files": 123,
  "total_bytes": 9876543210,
  "created_at_utc": "2025-01-01T12:00:00Z",
  "snapshot": "auto-zip-20250101120000"
}
```

### Proposed config (config.json)
```json
{
  "source_path": "/mnt/tank/source_dataset",
  "target_path": "/mnt/tank/target_dataset",
  "snapshot_prefix": "auto-zip",
  "max_workers": 1,
  "retries": 3,
  "nice": 10,
  "umask": "027",
  "lockfile_path": "/var/run/zipper.lock",
  "tmp_dir": "/mnt/tank/tmp",
  "log_file": "/var/log/zipper.log",
  "gotify": {
    "url": "https://gotify.example.com/message",
    "token": "REPLACE_WITH_TOKEN",
    "priority": 5,
    "timeout_seconds": 10
  }
}
```

### High-level tasks
- [x] Create and track this `todo.md`
- [x] Confirm decisions above and freeze metadata/config schema
- [ ] Initialize repo scaffolding (directories, placeholders) without implementation
  - [x] Create `config.json.example`
  - [x] Create `README.md` with usage and cron notes
  - [x] Ensure Python 3 path on TrueNAS CORE (`/usr/local/bin/python3`), document shebang
- [ ] Implement CLI skeleton (no side effects)
  - [x] Entrypoint `zipper.py` with `--config`, `--dry-run`, `--verbose`
  - [x] Load config, validate paths/permissions, set `umask`, set `nice`
  - [x] Structured logging to syslog and file
  - [x] Locking (PID file + non-blocking lock; fail fast if locked)
- [ ] ZFS snapshot handling (TrueNAS CORE / FreeBSD)
  - [x] Create read-only snapshot of source dataset with prefix
  - [x] Derive snapshot mount path via `.zfs/snapshot/<name>`
  - [x] Cleanup old snapshots created by this tool (bounded)
- [ ] Folder enumeration and validation
  - [x] List subfolders in snapshot root
  - [x] Filter by `^[A-Z0-9]{4}$`
  - [x] Skip symlinks, devices, sockets, fifos
- [ ] Change detection (skip unchanged)
  - [x] Prefer `zfs diff <prev>@<curr>` if available/allowed to detect changes
  - [x] Fallback: compute manifest hash (relative path + size + mtime) and compare to stored state
  - [x] Persist per-folder state (e.g., in target subfolder `.state.json`)
- [ ] Archiving per folder
  - [x] Zip all files/subdirs (no symlink following) with `ZIP_DEFLATED`
  - [x] Create `metadata.json` per proposed schema
  - [x] Verify zip (read test)
  - [x] Compute MD5 and SHA-256; write `.md5` and `.sha256`
  - [x] Write to temp on same filesystem; atomic rename to target
- [ ] Target path organization
  - [x] Ensure subfolder `target_path/<SOURCE>` exists
  - [x] Rotation: keep only 2 archives (scheme A)
  - [x] Publish with rollback safety (no destructive changes on failure)
  - [x] Update per-folder state after successful move
- [ ] Retries and error handling
  - [x] Retry up to 3 times for transient errors with backoff
  - [x] On final failure, send Gotify notification and continue with next folder
- [ ] Notifications (Gotify)
  - [x] Implement client with timeout and error logging
  - [x] Add CLI debug command to send a test message
  - [x] Send on failures and optionally on successes (configurable; default failures only)
- [ ] Concurrency
  - [x] Worker pool capped by `max_workers`; default 1
  - [x] Per-task timeouts to avoid stalls
- [ ] Logging and observability
  - [x] Syslog integration (FreeBSD) + rotating file log
  - [x] Include correlation IDs per run and per folder
- [ ] Cron integration
  - [x] Document crontab entry and environment setup on TrueNAS CORE
  - [x] Include lock guard in cron example to avoid overlaps
- [ ] Dry run and self-checks
  - [x] `--dry-run` simulates actions and prints planned changes
  - [x] Preflight checks: free space, tmp/target writability (temp free space)
- [ ] QA on small test dataset
  - [x] Create sample source structure and validate outputs (script)
  - [x] Verify integrity, metadata correctness, and retention

### Commit guidance
- Keep each task small; commit after each feature with messages ≤ 50 chars.
- Examples:
  - "scaffold: add project skeleton"
  - "cli: config load and validation"
  - "zfs: snapshot create and cleanup"
  - "zip: archive and metadata.json"
  - "hash: write md5 and sha256"
  - "target: rotate to keep last two"
  - "notify: gotify failures"
  - "cron: docs and examples"

### Notes
- Python path on TrueNAS CORE is typically `/usr/local/bin/python3`. We'll use that shebang and avoid external deps beyond stdlib.
- If `zfs diff` requires permissions, we may use a manifest hash fallback.
- For retention without timestamps, rotation scheme confirmation is required.


