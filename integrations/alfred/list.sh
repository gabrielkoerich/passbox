#!/bin/bash
# Alfred Run Script: lists the names while Alfred is closed, since the Touch ID prompt would close it
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
if ! names=$("$passbox" ls 2>"$err"); then
  names=""
  error=$(tr '\n' ' ' <"$err")
fi

# The names travel as a stream variable to the Script Filter, so they never touch disk
printf '{"alfredworkflow":{"arg":"","variables":{"names":%s,"error":%s}}}\n' \
  "$(quote "$names")" "$(quote "$error")"
