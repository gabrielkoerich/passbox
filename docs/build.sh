#!/usr/bin/env bash
# Generate the site's pages from the repository's own docs, then build.
#
# The README and AGENTS.md are the single source. Copying them in at build time is what stops
# the site drifting from the code, which is the failure mode a separate docs tree always has.
set -euo pipefail
cd "$(dirname "$0")/.."

gen() {
    local src="$1" title="$2" desc="$3" weight="$4" out="$5"
    {
        printf '+++\ntitle = "%s"\ndescription = "%s"\nweight = %s\n+++\n\n' "$title" "$desc" "$weight"
        # Drop the leading H1: the front matter title renders it already
        sed '1{/^# /d;}' "$src" \
            | sed -E 's|\]\(docs/content/design\.md\)|](/design)|g;
                      s|\]\(docs/content/design\.md#([^)]*)\)|](/design#\1)|g;
                      s|\]\(AGENTS\.md\)|](/agents)|g;
                      s|\]\((examples[^)]*)\)|](https://github.com/gabrielkoerich/passbox/tree/main/\1)|g;
                      s|\]\((skills[^)]*)\)|](https://github.com/gabrielkoerich/passbox/tree/main/\1)|g;
                      s|\]\(docs/prompt\.png\)|](/prompt.png)|g;
                      s|src="docs/([^"]*)"|src="/\1"|g;
                      s|\]\(LICENCE\)|](https://github.com/gabrielkoerich/passbox/blob/main/LICENCE)|g'
    } > "$out"
}

gen README.md "Guide" "Install passbox, store a secret, and hand it to a program" 1 docs/content/guide.md
gen AGENTS.md "For agents" "How an agent reads a secret without putting it in its context" 4 docs/content/agents.md

cp docs/prompt.png docs/static/prompt.png 2>/dev/null || true
exec zola --root docs build "$@"
