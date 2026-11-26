#!/bin/bash
# Alfred Run Script: copies the picked field of a name, or its password, the first line
set -u
passbox=${PASSBOX:-/opt/homebrew/bin/passbox}
export PASSBOX_AGENT=${PASSBOX_AGENT:-alfred}

"$passbox" copy "$1" --field "${field:-password}" 2>&1
