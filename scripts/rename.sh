#!/usr/bin/env bash
# One-command product rename: scripts/rename.sh <newname>
#
# internal/brand/brand.go is the runtime SSOT for the product name; this
# script covers everything a Go constant cannot reach — the module path,
# the cmd/ directory names, packaging configs, docs prose — and finally
# rewrites brand.go itself. docs/history/ is left untouched by design.
#
# After running: review `git diff`, then `make build test lint`.
set -euo pipefail

new="${1:?usage: scripts/rename.sh <newname>}"
case "$new" in
  *[!a-z0-9]*) echo "error: new name must be a lowercase single token, got '$new'" >&2; exit 1 ;;
esac

old="$(perl -ne 'print $1 if /^\tName = "([a-z0-9]+)"$/' internal/brand/brand.go)"
if [ -z "$old" ]; then
  echo "error: could not read current Name from internal/brand/brand.go" >&2
  exit 1
fi
if [ "$old" = "$new" ]; then
  echo "already named '$new' — nothing to do"
  exit 0
fi

old_upper="$(printf '%s' "$old" | tr '[:lower:]' '[:upper:]')"
new_upper="$(printf '%s' "$new" | tr '[:lower:]' '[:upper:]')"
old_camel="$(printf '%s' "${old:0:1}" | tr '[:lower:]' '[:upper:]')${old:1}"
new_camel="$(printf '%s' "${new:0:1}" | tr '[:lower:]' '[:upper:]')${new:1}"

git mv "cmd/$old" "cmd/$new"
git mv "cmd/${old}d" "cmd/${new}d"
[ -f "schema/$old.schema.json" ] && git mv "schema/$old.schema.json" "schema/$new.schema.json"

# The bare lowercase rule intentionally also rewrites the daemon name
# (<old>d -> <new>d) and the module path. Ordered most-specific first.
git ls-files | grep -v '^docs/history/' | grep -vE '\.(png|jpg|gif|ico|exe)$' | \
while IFS= read -r f; do
  perl -pi -e "
    s/${old_upper}_/${new_upper}_/g;
    s/${old_camel}/${new_camel}/g;
    s/${old_upper}/${new_upper}/g;
    s/${old}/${new}/g;
  " "$f"
done

gofmt -l . | grep -v '^$' && { echo "error: gofmt drift after rename" >&2; exit 1; }
echo "renamed '$old' -> '$new'. Review git diff, then: make build test lint"
echo "human follow-ups: GitHub repo rename, domain, release tap/bucket names"
