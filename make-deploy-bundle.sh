#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

VERSION="$(tr -d '[:space:]' < VERSION)"
if [ -z "$VERSION" ]; then
  echo "ERROR: VERSION file is empty or contains only whitespace." >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: The git tree is dirty. The release zip must come from a verified clean tree." >&2
  echo "       Commit or stash all changes before building." >&2
  exit 1
fi

ARTIFACT="windows-performance-diagnostics-toolkit-${VERSION}"
STAGE_DIR="dist/stage/${ARTIFACT}"
OUT_DIR="dist"
ZIP_FILE="${OUT_DIR}/${ARTIFACT}.zip"
SHA_FILE="${OUT_DIR}/${ARTIFACT}.sha256"

export STAGE_DIR
export ZIP_FILE

rm -rf dist/stage
mkdir -p "$STAGE_DIR"

git archive --format=tar HEAD | tar -x -C "$STAGE_DIR"

python3 - <<'PYEOF'
import os, zipfile, sys, subprocess, datetime

stage = os.environ.get("STAGE_DIR", "")
zip_path = os.environ.get("ZIP_FILE", "")

if not stage or not zip_path:
    print("ERROR: STAGE_DIR or ZIP_FILE not set", file=sys.stderr)
    sys.exit(1)

# Deterministic zip entries: every entry uses the HEAD commit time expressed in
# the release-build timezone (UTC+2, the build host's local time) and the mode
# of the tar entries git archive emits (0664/0775). Explicit values make the
# zip byte-identical on any platform/OS/TZ (CI runners are UTC by default), so
# the release asset can be reproduced and verified in CI via the .sha256 asset.
commit_ts = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"]).decode().strip())
base_dt = datetime.datetime.fromtimestamp(
    commit_ts, tz=datetime.timezone(datetime.timedelta(hours=2)))
entry_dt = (base_dt.year, base_dt.month, base_dt.day,
            base_dt.hour, base_dt.minute, base_dt.second)
FILE_ATTR = (0o100664 << 16)  # matches git archive's 0664 for regular files

stage = stage.rstrip("/") + "/"
parent = os.path.dirname(stage.rstrip("/")) + "/"
entries = []
for root, dirs, files in os.walk(stage):
    dirs.sort()
    for f in files:
        full = os.path.join(root, f)
        arcname = full[len(parent):]
        entries.append((arcname, full))

entries.sort(key=lambda e: e[0])

os.makedirs(os.path.dirname(zip_path) or ".", exist_ok=True)
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for arcname, full in entries:
        info = zipfile.ZipInfo(arcname, date_time=entry_dt)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = FILE_ATTR
        with open(full, "rb") as fh:
            zf.writestr(info, fh.read())

print(f"Created {zip_path} with {len(entries)} entries (timestamp {entry_dt})")
PYEOF

(cd "$OUT_DIR" && sha256sum "${ARTIFACT}.zip" > "${ARTIFACT}.sha256")

ZIP_SIZE=$(stat -c%s "$ZIP_FILE")
SHA256=$(cut -d' ' -f1 < "$SHA_FILE")

echo ""
echo "=== Build Complete ==="
echo "Zip:       $ZIP_FILE"
echo "Size:      $ZIP_SIZE bytes"
echo "SHA256:    $SHA256"
echo ""
echo "Contents (first-level entries):"
(cd "$STAGE_DIR" && ls -1)
echo ""

rm -rf "$STAGE_DIR"
