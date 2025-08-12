## TrueNAS CORE zipper job

Hourly job to zip each valid 4-char folder under a source dataset, generate `metadata.json` with file listing and hashes, and move artifacts to a matching subfolder in the target dataset. Runs from a read-only ZFS snapshot for consistency; keeps only the latest 2 archives via rename rotation.

### Requirements
- TrueNAS CORE (FreeBSD) with ZFS
- Python 3 at `/usr/local/bin/python3` (default on TrueNAS CORE)

### Install
1. Copy files to your system (e.g., `/usr/local/zipper`).
2. Copy `config.json.example` to `config.json` and edit paths/tokens.
3. Ensure temp and target paths exist and are writable.

### Config
See `config.json.example` for all options. Key fields:
- `source_path`, `target_path`
- `snapshot_prefix`: e.g., `auto-zip`
- `snapshot_retention`: keep last N snapshots created by the tool
- `max_workers`: default 1; raise carefully
- `per_task_timeout_seconds`: optional timeout per folder job (0 = no timeout)
- `retries`: default 3
- `gotify`: `url`, `token`, `priority`, `notify_success`

### Run manually
```bash
/usr/local/bin/python3 src/zipper.py --config ./config.json --dry-run
```

### Debug: send a Gotify message
```bash
/usr/local/bin/python3 src/zipper.py --config ./config.json \
  --send-gotify "hello from zipper" --title "zipper test" --priority 5
```

### QA smoke test
Requires `jq`:
```bash
chmod +x scripts/qa_smoke.sh
./scripts/qa_smoke.sh ./config.json
```

### Cron (hourly)
Use a lock to avoid overlaps:
```cron
0 * * * * /usr/bin/flock -n /var/run/zipper.cron.lock \
  /usr/local/bin/python3 /usr/local/zipper/src/zipper.py \
  --config /usr/local/zipper/config.json >> /var/log/zipper.cron 2>&1
```

### Notes
- Folder regex: `^[A-Z0-9]{4}$`
- Retention: `SOURCE.zip` is current, previous is `SOURCE.prev.zip`
- Notifications: Gotify on final failures


