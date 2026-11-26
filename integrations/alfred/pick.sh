#!/bin/bash
# Alfred Script Filter: one item per field of the picked name, masked, and ⏎ copies that field alone
set -u

quote() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

if [ -n "${error:-}" ]; then
  printf '{"items":[{"title":"passbox fields failed","subtitle":%s,"valid":false}]}\n' "$(quote "$error")"
  exit 0
fi

n=$(quote "${name:-}")
items=""
while IFS= read -r label; do
  [ -n "$label" ] || continue
  l=$(quote "$label")
  items+="${items:+,}{\"uid\":$l,\"title\":$l,\"subtitle\":\"•••••••••• ⏎ to copy\","
  items+="\"arg\":$n,\"variables\":{\"field\":$l}}"
done <<<"${labels:-}"

if [ -z "$items" ]; then
  items="{\"title\":$n,\"subtitle\":\"No field to copy\",\"valid\":false}"
fi
printf '{"items":[%s]}\n' "$items"
