#!/bin/bash
# List events from today through today+N days, via icalBuddy, which reads recurrences correctly
# N arrives as the first argument, passed by passbox as one whole argument, never evaluated
set -euo pipefail

days="${1:-0}"
if [[ -z "$days" ]]; then
    days=0
fi
if ! [[ "$days" =~ ^[0-9]+$ ]]; then
    echo "days must be a whole number" >&2
    exit 1
fi

icalBuddy -f -nc -nrd -b "" -df "%Y-%m-%d" -tf "%H:%M" \
    -iep "datetime,title,location,calendar" \
    -po "datetime,title,location,calendar" -ps "| | |" -ss "" \
    "eventsFrom:today" "to:today+${days}" | sed $'s/\033\[[0-9;]*m//g'
