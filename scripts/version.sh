#!/bin/sh
MAJOR=1
MINOR=0
FIX=1
# Use test for posix shell compatability
if [ -e ".git" ]; then
    COMMIT_DATE=$(TZ=UTC git show -s --pretty=%cd --date=format-local:%Y%m%d HEAD 2>/dev/null)
    COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null)
    git update-index --really-refresh >/dev/null 2>/dev/null
    if ! git diff-index --quiet HEAD >/dev/null 2>/dev/null; then
        COMMIT_DIRTY='-dirty'
    fi
    COMMIT_INFO="-${COMMIT_DATE}.${COMMIT_HASH}${COMMIT_DIRTY}"
else
    COMMIT_INFO="-unknown"
fi

echo "v${MAJOR}.${MINOR}.${FIX}${COMMIT_INFO}"