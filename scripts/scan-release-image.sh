#!/bin/sh
set -eu

docker=${DOCKER:-docker}
trivy=${TRIVY:-trivy}
command -v "$trivy" >/dev/null || { echo "Install Trivy to scan the release image." >&2; exit 1; }
scan_dir=$(mktemp -d "${TMPDIR:-/tmp}/rush-mcp-release-scan.XXXXXX")
image="rush-mcp-release-scan:${scan_dir##*.}"
cleanup() {
    "$docker" image rm "$image" >/dev/null 2>&1 || true
    rm -f "$scan_dir/image.tar"
    rmdir "$scan_dir"
}
trap cleanup EXIT

"$docker" build --tag "$image" .
"$docker" image save --output "$scan_dir/image.tar" "$image"
"$trivy" image --input "$scan_dir/image.tar" --scanners vuln --format table \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
