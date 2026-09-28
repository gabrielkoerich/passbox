#!/usr/bin/env bash
# Generate the site's pages from the repository's own docs, then build.
#
# README.md and AGENTS.md are the single source. Copying them in at build time is what stops
# the site drifting from the code, which is the failure mode a separate docs tree always has.
#
# One `## ` heading in the README is one page, in the order they appear. There is no list of
# pages here on purpose: a mapping is a second place to maintain, and a section added to the
# README would quietly never reach the site.
set -euo pipefail
cd "$(dirname "$0")/.."

rewrite() {
    sed -E 's|\]\(docs/content/design\.md\)|](/design)|g;
            s|\]\(docs/content/design\.md#([^)]*)\)|](/design#\1)|g;
            s|\]\(AGENTS\.md\)|](/agents)|g;
            s|\]\(README\.md#([a-z0-9-]*)\)|](/\1)|g;
            s|\]\(#if-you-lose-the-mac\)|](/backup-and-sync#if-you-lose-the-mac)|g;
            s|\]\(#unattended\)|](/unattended)|g;
            s|\]\((examples[^)]*)\)|](https://github.com/gabrielkoerich/passbox/tree/main/\1)|g;
            s|\]\((skills[^)]*)\)|](https://github.com/gabrielkoerich/passbox/tree/main/\1)|g;
            s|\]\(docs/prompt\.png\)|](/prompt.png)|g;
            s|src="docs/([^"]*)"|src="/\1"|g;
            s|\]\(LICENCE\)|](https://github.com/gabrielkoerich/passbox/blob/main/LICENCE)|g'
}

# Drop pages from a previous run, so a renamed section does not leave an orphan behind
find docs/content -name '*.md' ! -name '_index.head.md' ! -name 'design.md' \
    ! -name 'roadmap.md' -delete

# Everything above the first `## ` is the pitch, and belongs on the landing page
{ cat docs/content/_index.head.md
  echo
  awk '/^## /{exit} {print}' README.md | sed '1{/^# /d;}' | rewrite
} > docs/content/_index.md

# One page per `## `, weighted by the order the README puts them in. A state machine rather
# than a multi-character RS, which BSD awk does not support.
rm -rf /tmp/pb-sections && mkdir -p /tmp/pb-sections
awk -v out=/tmp/pb-sections '
    /^## / {
        n++
        title = substr($0, 4)
        slug = tolower(title)
        gsub(/[^a-z0-9]+/, "-", slug); gsub(/^-|-$/, "", slug)
        file = out "/" n "-" slug
        printf "%s\n", title > (file ".title")
        next
    }
    file { print >> (file ".body") }
' README.md

for body in /tmp/pb-sections/*.body; do
    base="${body%.body}"
    n="${base##*/}"; n="${n%%-*}"
    slug="${base##*/}"; slug="${slug#*-}"
    title=$(cat "$base.title")
    { printf '+++\ntitle = "%s"\nweight = %s\n+++\n\n' "$title" "$n"
      cat "$body"
    } | rewrite > "docs/content/$slug.md"
done

{ printf '+++\ntitle = "For agents"\ndescription = "How an agent reads a secret without putting it in its context"\nweight = 7\n+++\n\n'
  sed '1{/^# /d;}' AGENTS.md
} | rewrite > docs/content/agents.md

cp docs/prompt.png docs/static/prompt.png 2>/dev/null || true
exec zola --root docs build "$@"
