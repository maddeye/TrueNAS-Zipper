#!/usr/bin/env bash
set -euo pipefail

CFG=${1:-"./config.json"}

if [[ ! -f "$CFG" ]]; then
  echo "Config not found: $CFG" >&2
  exit 2
fi

SRC=$(jq -r .source_path "$CFG")
DST=$(jq -r .target_path "$CFG")

if [[ -z "$SRC" || -z "$DST" || "$SRC" == "null" || "$DST" == "null" ]]; then
  echo "Invalid source/target in config" >&2
  exit 2
fi

FOLDER="QA01"
mkdir -p "$SRC/$FOLDER"
echo "hello" > "$SRC/$FOLDER/hello.txt"
mkdir -p "$SRC/$FOLDER/sub"
echo "world" > "$SRC/$FOLDER/sub/world.txt"

echo "Running zipper..."
python3 src/zipper.py --config "$CFG" -v | cat

echo "Checking outputs..."
test -f "$DST/$FOLDER/$FOLDER.zip"
test -f "$DST/$FOLDER/metadata.json"
test -f "$DST/$FOLDER/$FOLDER.zip.md5"
test -f "$DST/$FOLDER/$FOLDER.zip.sha256"

echo "QA smoke: OK for folder $FOLDER"

