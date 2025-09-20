#!/bin/sh
# Count SARIF results in a given file

if [ $# -ne 1 ]; then
    echo "Usage: $0 file.sarif" >&2
    exit 1
fi

file="$1"

jq '[.runs[].results[]] | length' "$file"
