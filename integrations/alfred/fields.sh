#!/bin/bash
# Alfred Run Script: lists the picked name's fields while Alfred is closed, since the Touch ID prompt would close it
set -u
passbox=${PASSBOX:-/opt/homebrew/bin/passbox}
export PASSBOX_AGENT=${PASSBOX_AGENT:-alfred}

quote() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '"%s"' "$s"
}

err="${TMPDIR:-/tmp}/passbox-alfred.err"
error=""
if ! labels=$("$passbox" fields "$1" 2>"$err"); then
  labels=""
  error=$(tr '\n' ' ' <"$err")
fi

# The labels name fields and carry no value, so Alfred's log and cache never hold a secret
printf '{"alfredworkflow":{"arg":"","variables":{"name":%s,"labels":%s,"error":%s}}}\n' \
  "$(quote "$1")" "$(quote "$labels")" "$(quote "$error")"
