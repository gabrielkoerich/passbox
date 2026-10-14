#!/bin/bash
# Alfred Script Filter: one item per secret name. Alfred does the fuzzy matching, so this runs once
set -u
passbox=${PASSBOX:-/opt/homebrew/bin/passbox}
export PASSBOX_AGENT=${PASSBOX_AGENT:-alfred}

quote() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

err="${TMPDIR:-/tmp}/passbox-alfred.err"
if ! names=$("$passbox" ls 2>"$err"); then
  printf '{"items":[{"title":"passbox ls failed","subtitle":%s,"valid":false}]}\n' \
    "$(quote "$(tr '\n' ' ' <"$err")")"
  exit 0
fi

items=""
while IFS= read -r name; do
  [ -n "$name" ] || continue
  n=$(quote "$name")
  items+="${items:+,}{\"uid\":$n,\"title\":$n,\"arg\":$n,\"autocomplete\":$n,"
  items+="\"subtitle\":\"Copy the password\","
  items+="\"mods\":{\"cmd\":{\"arg\":$n,\"subtitle\":\"Copy the username\",\"variables\":{\"field\":\"username\"}}}}"
done <<<"$names"

# Off by default: Alfred keeps a cached list on disk unencrypted, and passbox otherwise never writes names in the clear
cache=""
if [ "${cache_seconds:-0}" -gt 0 ] 2>/dev/null; then
  cache=",\"cache\":{\"seconds\":${cache_seconds},\"loosereload\":true}"
fi

printf '{"items":[%s]%s}\n' "$items" "$cache"
