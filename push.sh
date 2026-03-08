#!/usr/bin/env bash
set -e
 
if [ -z "$1" ]; then
  echo "Usage: $0 \"commit message\""
  exit 1
fi

git add -A
git commit -m "$1"
git push origin main:main
