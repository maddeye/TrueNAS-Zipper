#!/usr/bin/env bash
set -euo pipefail

CFG=${1:-"./config.json"}

if [[ ! -f "$CFG" ]]; then
  echo "Config not found: $CFG" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for QA script" >&2
  exit 2
fi

SRC=$(jq -r .source_path "$CFG")
DST=$(jq -r .target_path "$CFG")

if [[ -z "$SRC" || -z "$DST" || "$SRC" == "null" || "$DST" == "null" ]]; then
  echo "Invalid source/target in config" >&2
  exit 2
fi

FOLDER="QA01"
echo "Resetting test folders..."
rm -rf "$SRC/$FOLDER" "$DST/$FOLDER" || true

mkdir -p "$SRC/$FOLDER/sub"
echo -n "hello" > "$SRC/$FOLDER/hello.txt"
echo -n "world" > "$SRC/$FOLDER/sub/world.txt"

echo "Running zipper (1st run)..."
python3 src/zipper.py --config "$CFG" -v | cat

echo "Verifying outputs (1st run)..."
test -f "$DST/$FOLDER/$FOLDER.zip"
test -f "$DST/$FOLDER/metadata.json"
test -f "$DST/$FOLDER/$FOLDER.zip.md5"
test -f "$DST/$FOLDER/$FOLDER.zip.sha256"

ZIP_PATH="$DST/$FOLDER/$FOLDER.zip"
META_PATH="$DST/$FOLDER/metadata.json"
MD5_PATH="$DST/$FOLDER/$FOLDER.zip.md5"
SHA_PATH="$DST/$FOLDER/$FOLDER.zip.sha256"

# Check zip integrity
python3 - "$ZIP_PATH" <<'PY'
import sys, zipfile
zp = sys.argv[1]
with zipfile.ZipFile(zp, 'r') as zf:
    bad = zf.testzip()
    assert bad is None, f"Corrupt zip entry: {bad}"
PY

# Check metadata basics
name=$(jq -r .zip_name "$META_PATH")
[[ "$name" == "$FOLDER.zip" ]]

# Compare file lists (sorted)
mapfile -t files_from_meta < <(jq -r '.files[]' "$META_PATH" | sort)
mapfile -t files_from_zip < <(python3 - "$ZIP_PATH" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'r') as zf:
    for n in sorted(zf.namelist()):
        print(n)
PY
)
diff -u <(printf "%s\n" "${files_from_meta[@]}") <(printf "%s\n" "${files_from_zip[@]}")

# Check total_files matches
count_meta=$(jq -r '.total_files' "$META_PATH")
[[ "$count_meta" -eq "${#files_from_zip[@]}" ]]

# Check hashes match actual zip
py_md5=$(python3 - "$ZIP_PATH" <<'PY'
import sys,hashlib
h=hashlib.md5()
with open(sys.argv[1],'rb') as f:
  for chunk in iter(lambda: f.read(1<<20), b''):
    h.update(chunk)
print(h.hexdigest())
PY
)
py_sha=$(python3 - "$ZIP_PATH" <<'PY'
import sys,hashlib
h=hashlib.sha256()
with open(sys.argv[1],'rb') as f:
  for chunk in iter(lambda: f.read(1<<20), b''):
    h.update(chunk)
print(h.hexdigest())
PY
)
md5_file=$(awk '{print $1}' "$MD5_PATH")
sha_file=$(awk '{print $1}' "$SHA_PATH")
[[ "$py_md5" == "$md5_file" ]]
[[ "$py_sha" == "$sha_file" ]]

prev_md5="$py_md5"

echo "Running zipper (2nd run with changes)..."
echo -n "again" > "$SRC/$FOLDER/second.txt"
python3 src/zipper.py --config "$CFG" -v | cat

echo "Verifying rotation (2nd run)..."
test -f "$DST/$FOLDER/$FOLDER.prev.zip"
test -f "$DST/$FOLDER/metadata.prev.json"
test -f "$DST/$FOLDER/$FOLDER.prev.zip.md5"
test -f "$DST/$FOLDER/$FOLDER.prev.zip.sha256"

# Current zip should differ now
new_md5=$(python3 - "$ZIP_PATH" <<'PY'
import sys,hashlib
h=hashlib.md5()
with open(sys.argv[1],'rb') as f:
  for chunk in iter(lambda: f.read(1<<20), b''):
    h.update(chunk)
print(h.hexdigest())
PY
)
[[ "$new_md5" != "$prev_md5" ]]

# Previous md5 should match first run md5
prev_md5_file=$(awk '{print $1}' "$DST/$FOLDER/$FOLDER.prev.zip.md5")
[[ "$prev_md5_file" == "$prev_md5" ]]

# Ensure no leftover backup files
if ls "$DST/$FOLDER"/*.bak_current >/dev/null 2>&1; then
  echo "Found stray .bak_current files" >&2
  exit 1
fi

echo "QA verification: OK for folder $FOLDER"

