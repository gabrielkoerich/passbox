#!/bin/bash
# Alfred Run Script: copies the picked field of a name, its password, or a whole note
set -u
passbox=${PASSBOX:-/opt/homebrew/bin/passbox}
export PASSBOX_AGENT=${PASSBOX_AGENT:-alfred}

if [ -n "${whole:-}" ]; then
  "$passbox" copy "$1" 2>&1
else
  "$passbox" copy "$1" --field "${field:-password}" 2>&1
fi
