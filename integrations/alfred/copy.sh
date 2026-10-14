#!/bin/bash
# Alfred Run Script: copies the picked name, or one field of it when the item set `field`
set -u
passbox=${PASSBOX:-/opt/homebrew/bin/passbox}
export PASSBOX_AGENT=${PASSBOX_AGENT:-alfred}

if [ -n "${field:-}" ]; then
  "$passbox" copy "$1" --field "$field" 2>&1
else
  "$passbox" copy "$1" 2>&1
fi
