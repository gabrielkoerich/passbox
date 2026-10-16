#!/bin/bash
# Alfred Script Filter: one item per name from list.sh. Alfred does the fuzzy matching, so this runs once
set -u

quote() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

if [ -n "${error:-}" ]; then
  printf '{"items":[{"title":"passbox ls failed","subtitle":%s,"valid":false}]}\n' "$(quote "$error")"
  exit 0
fi

items=""
while IFS= read -r name; do
  [ -n "$name" ] || continue
  n=$(quote "$name")
  items+="${items:+,}{\"uid\":$n,\"title\":$n,\"arg\":$n,\"autocomplete\":$n,"
  items+="\"subtitle\":\"Copy the password\","
  items+="\"mods\":{\"cmd\":{\"arg\":$n,\"subtitle\":\"Copy the username\",\"variables\":{\"field\":\"username\"}}}}"
done <<<"${names:-}"

printf '{"items":[%s]}\n' "$items"
