#!/bin/bash
# Packs the workflow into OUT, stamped with VERSION so Alfred shows which release is installed
set -euo pipefail
version=${1:?usage: build.sh VERSION OUT}
out=${2:?usage: build.sh VERSION OUT}
[ "${out:0:1}" = / ] || out="$PWD/$out"
here=$(cd "$(dirname "$0")" && pwd)

work=$(mktemp -d)
trap 'rm -r "$work"' EXIT
cp "$here/info.plist" "$here/icon.png" "$here/list.sh" "$here/filter.sh" "$here/copy.sh" "$work/"

python3 - "$work/info.plist" "${version#v}" <<'PY'
import plistlib, sys
path, version = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    plist = plistlib.load(f)
plist["version"] = version
with open(path, "wb") as f:
    plistlib.dump(plist, f)
PY

(cd "$work" && zip -qX "$out" info.plist icon.png list.sh filter.sh copy.sh)
echo "built $out, version ${version#v}"
