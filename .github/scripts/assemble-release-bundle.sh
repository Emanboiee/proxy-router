#!/usr/bin/env bash
#
# Assemble one proxy-router release bundle (dist/proxy-router + archive) in
# exactly the layout the release workflow publishes. Shared by:
#
#   * .github/workflows/release.yml      (every matrix target on tag/dispatch)
#   * .github/workflows/windows-smoke.yml (pull requests, windows-amd64 only)
#
# so a pull request installs byte-for-byte the same file manifest a tag would
# ship and the two cannot drift. Keep the runtime file manifest here;
# tests/test_release_bundle.py asserts it.
#
# usage: assemble-release-bundle.sh ASSET SUFFIX ARCHIVE EXE REF
#   ASSET    sing-box release asset architecture (windows-amd64, darwin-arm64, ...)
#   SUFFIX   bundle suffix used in artifact names (windows-amd64, ...)
#   ARCHIVE  tar.gz | zip
#   EXE      engine binary name inside bin/ (sing-box.exe | sing-box)
#   REF      name baked into the archive filename (release tag, PR sha, ...)
# env:
#   SING_BOX_VERSION  required: sing-box release version to download
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 ASSET SUFFIX ARCHIVE EXE REF" >&2
  exit 2
fi
asset="$1"
suffix="$2"
archive_type="$3"
exe="$4"
ref="$5"
: "${SING_BOX_VERSION:?SING_BOX_VERSION is required}"

case "$archive_type" in
  tar.gz|zip) ;;
  *) echo "error: unsupported archive type: $archive_type" >&2; exit 2 ;;
esac

bundle="sing-box-${SING_BOX_VERSION}-${asset}.${archive_type}"
# Exported so the PowerShell child processes below can read it the same way
# the release workflow's inline steps did via $GITHUB_ENV, and so the
# checksum lookup heredoc sees the asset name without textual substitution.
export BUNDLE_FILE="$bundle"
export BUNDLE_ASSET="$asset"

# The release asset URL is deterministic; querying the API is not needed
# (unauthenticated API can be rate-limited, and jq is not guaranteed on every
# runner).
url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${bundle}"
curl -fsSL --connect-timeout 20 --max-time 300 -o "$bundle" "$url"
echo "Downloaded sing-box: $url"

# Issue #63: the download used to be trusted blindly. Verify it against the
# digest recorded in sing-box-release.json (populated from the signed GitHub
# release) before anything ships.
expected=$(python3 - <<'PY'
import json
import os

with open("sing-box-release.json") as f:
    doc = json.load(f)
asset = os.environ["BUNDLE_ASSET"]
arch = {"darwin-arm64": "arm64", "darwin-amd64": "x86_64"}.get(asset)
if arch:
    rec = doc["architectures"][arch]
    assert asset in rec["name"], f"{asset} not in {rec['name']}"
    print(rec["sha256"])
else:
    print("")
PY
)
if [ -n "$expected" ]; then
  echo "$expected  $bundle" | shasum -a 256 -c -
  echo "verified sha256 for $bundle"
else
  echo "warning: no recorded digest for $asset; skipping verification"
fi

mkdir -p dist/proxy-router/bin _sb
if [ "$archive_type" = "tar.gz" ]; then
  tar -xzf "$bundle" -C _sb
  find _sb -type f -name 'sing-box' -exec cp {} dist/proxy-router/bin/ \;
  chmod +x dist/proxy-router/bin/sing-box
else
  # GNU tar (Git Bash) cannot read .zip; use PowerShell Expand-Archive.
  powershell -NoProfile -Command "Expand-Archive -Force -Path \"\$env:BUNDLE_FILE\" -DestinationPath _sb"
  find _sb -type f -name 'sing-box.exe' -exec cp {} dist/proxy-router/bin/ \;
fi
ls -la dist/proxy-router/bin

# Issue #63: packaging used to ship whatever find() collected, even zero
# binaries or a wrong-arch binary. Fail unless EXACTLY one expected binary
# exists AND executes with the expected arch/version.
bin="dist/proxy-router/bin/$exe"
count=$(find dist/proxy-router/bin -maxdepth 1 -type f \
  \( -name 'sing-box' -o -name 'sing-box.exe' \) | wc -l | tr -d ' ')
if [ "$count" -ne 1 ]; then
  echo "error: expected exactly one sing-box binary, found $count" >&2
  exit 1
fi
[ -x "$bin" ] || { echo "error: $bin is not executable" >&2; exit 1; }
file_output=$(file "$bin")
echo "$file_output"
case "$suffix" in
  *arm64*)
    echo "$file_output" | grep -qiE 'arm64|aarch64' \
      || { echo "error: expected arm64 binary" >&2; exit 1; } ;;
  *amd64*)
    echo "$file_output" | grep -qiE 'x86[_-]64|amd64' \
      || { echo "error: expected amd64 binary" >&2; exit 1; } ;;
esac
version_output=$("$bin" version 2>/dev/null || true)
echo "$version_output"
echo "$version_output" | grep -q "${SING_BOX_VERSION}" \
  || { echo "error: binary does not report version ${SING_BOX_VERSION}" >&2; exit 1; }

# Runtime file manifest. Every file install.sh / install.ps1 need at runtime,
# kept in one place for both the release and the pull request smoke job.
cp router.py setup_tui.py monitor.py network_control.py route_watcher.py proxy_tray.py autodetect_refresh.py domain_autodetect.py egress.py state.py config_schema.py worker_lock.py providers_check.py net_safety.py model_relay.py status_snapshot.py dashboard_profile_manager.py provider_lifecycle.py README.md LICENSE .gitignore router.example.json dist/proxy-router/
cp -R guides rulesets dist/proxy-router/
cp privileged_helper.py privileged_installer.py sing-box-release.json dist/proxy-router/
if [ "$archive_type" = "tar.gz" ]; then
  cp install.sh VERSION dist/proxy-router/
else
  cp install.ps1 VERSION dist/proxy-router/
fi

mkdir -p dist/proxy-router/examples
cp -R examples/. dist/proxy-router/examples/

if [ "$archive_type" = "tar.gz" ]; then
  tar -czf "proxy-router-${ref}-${suffix}.tar.gz" -C dist proxy-router
else
  # GNU tar (Git Bash) cannot write .zip; use PowerShell Compress-Archive.
  cd dist
  powershell -NoProfile -Command "Compress-Archive -Force -Path proxy-router -DestinationPath \"..\\proxy-router-${ref}-${suffix}.zip\""
  cd ..
fi

echo "assembled proxy-router-${ref}-${suffix}.${archive_type}"
