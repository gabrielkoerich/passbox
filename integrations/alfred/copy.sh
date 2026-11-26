#!/bin/bash
# Alfred Run Script: copies the password of the picked name, the first line of a multi-line entry
set -u
passbox=${PASSBOX:-/opt/homebrew/bin/passbox}
export PASSBOX_AGENT=${PASSBOX_AGENT:-alfred}

"$passbox" copy "$1" --field password 2>&1
