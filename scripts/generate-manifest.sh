#!/bin/sh
# generate-manifest.sh — Generate an integrity-guard manifest for container files.
#
# Usage: ./scripts/generate-manifest.sh [files...] > manifest.json
#
# The manifest is unsigned at this point (signature field is a placeholder).
# In production, the CI pipeline signs it via PKCS#11/HSM before embedding
# it in the container image.
set -eu

if [ $# -eq 0 ]; then
    echo "Usage: $0 <file> [file...]" >&2
    exit 1
fi

# Build the files array
FILES=""
for f in "$@"; do
    if [ ! -f "$f" ]; then
        echo "Error: $f not found" >&2
        exit 1
    fi
    DIGEST=$(sha256sum "$f" | awk '{print $1}')
    if [ -n "$FILES" ]; then
        FILES="${FILES},"
    fi
    FILES="${FILES}{\"path\":\"$f\",\"digest\":\"$DIGEST\"}"
done

cat <<EOF
{
  "version": 1,
  "files": [${FILES}],
  "signature": "unsigned-placeholder"
}
EOF
