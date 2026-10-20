#!/bin/bash
# Builds passbox.app at OUT, stamped with VERSION, with the Command Line Tools alone
set -euo pipefail
version=${1:?usage: build.sh VERSION OUT}
out=${2:?usage: build.sh VERSION OUT}
[ "${out:0:1}" = / ] || out="$PWD/$out"
here=$(cd "$(dirname "$0")" && pwd)

swift build -c release --package-path "$here"
mkdir -p "$out/Contents/MacOS"
cp "$here/.build/release/PassboxApp" "$out/Contents/MacOS/"
cp "$here/Info.plist" "$out/Contents/"
plutil -replace CFBundleShortVersionString -string "${version#v}" "$out/Contents/Info.plist"

# Ad hoc, no account needed. Built on this Mac, so it carries no quarantine flag
codesign -s - --force --options runtime "$out"
echo "built $out, version ${version#v}"
