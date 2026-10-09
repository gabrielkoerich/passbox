#!/usr/bin/env bash
# What a client machine can and cannot do against a remote host.
#
# Run it on the Linux box, with ~/.passbox/host or PASSBOX_HOST pointing at the Mac and a
# broker running there. Every check names what it expects, so a failure says what broke.
#
#   ./smoke.sh acme/api-key
set -uo pipefail

SECRET="${1:?usage: smoke.sh <a-secret-name>}"
AGENT="${PASSBOX_AGENT:-smoke}"
pass=0; fail=0

check() { # check <what> <expected> <actual>
    if [ "$2" = "$3" ]; then
        printf '  ok    %s\n' "$1"; pass=$((pass + 1))
    else
        printf '  FAIL  %s\n    expected: %s\n    actual:   %s\n' "$1" "$2" "$3"; fail=$((fail + 1))
    fi
}

echo "passbox client smoke test"
echo "  version: $(passbox --version 2>&1)"
echo "  host:    ${PASSBOX_HOST:-$(cat ~/.passbox/host 2>/dev/null || echo unset)}"
echo

# A client holds nothing. If these are here the test is not proving what it claims.
check "no store on this machine" "" "$(ls ~/.passbox/store 2>/dev/null)"
check "no wraps on this machine" "" "$(ls ~/.passbox/wraps 2>/dev/null)"

out=$(PASSBOX_AGENT="$AGENT" passbox get "$SECRET" 2>&1)
if [ -n "$out" ] && ! printf '%s' "$out" | grep -q '^passbox:'; then
    printf '  ok    read %s (%s bytes)\n' "$SECRET" "${#out}"; pass=$((pass + 1))
else
    printf '  FAIL  read %s\n    %s\n' "$SECRET" "$out"; fail=$((fail + 1))
fi

# A name that is not there must say so, not hang or return something
out=$(PASSBOX_AGENT="$AGENT" passbox get "no/such/secret" 2>&1 | tail -1)
case "$out" in
    *"no secret named"*) printf '  ok    an unknown name is refused\n'; pass=$((pass + 1)) ;;
    *) printf '  FAIL  an unknown name is refused\n    %s\n' "$out"; fail=$((fail + 1)) ;;
esac

# Injection is the point: the value reaches the child and not the caller
out=$(PASSBOX_AGENT="$AGENT" passbox exec --env V="$SECRET" -- sh -c 'printf %s "${#V}"' 2>&1)
case "$out" in
    ''|*[!0-9]*) printf '  FAIL  exec injects into a child\n    %s\n' "$out"; fail=$((fail + 1)) ;;
    *) printf '  ok    exec injects into a child (%s bytes)\n' "$out"; pass=$((pass + 1)) ;;
esac

# The caller never sees it in its own environment
check "the value is not in the caller's environment" "" "${V:-}"

# Plugins run on the Mac and return their output here. They prompt there, so they are opt-in
if [ "${PASSBOX_DEMO_PLUGINS:-0}" = "1" ]; then
    echo
    echo "plugins (the Mac runs these, and prompts there)"
    out=$(PASSBOX_AGENT="$AGENT" passbox plugin things3 today 2>&1)
    case "$out" in
        *"passbox:"*) printf '  FAIL  things3 today\n    %s\n' "$out"; fail=$((fail + 1)) ;;
        *) printf '  ok    things3 today ran on the host\n'; pass=$((pass + 1)) ;;
    esac
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
