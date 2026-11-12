#!/usr/bin/env bash
# Cases for gh-release.sh, against a stand-in for the gh command. The
# stand-in keeps the repo's releases and the assets of release 7 as GitHub
# API JSON in $STATE, runs the script's --jq filters on it with jq, and logs
# every call.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

cat > "$tmp/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
s=$STATE
echo "gh $*" >> "$s/log"
edit() { # edit <file> <jq program> [jq args...]
  local f=$1 prog=$2
  shift 2
  jq "$@" "$prog" "$s/$f" > "$s/$f.new"
  mv "$s/$f.new" "$s/$f"
}
case "$*" in
  'api --paginate repos/o/r/releases --jq '*)
    [ -z "${LIST_FAIL:-}" ] || { echo 'gh: Server Error (HTTP 500)' >&2; exit 1; }
    # After a create, the list leaves the new release out for $s/lag calls,
    # as GitHub's list can lag behind the create.
    lag=$(cat "$s/lag" 2>/dev/null || echo 0)
    if [ "$lag" -gt 0 ]; then
      echo $((lag - 1)) > "$s/lag"
      jq -r "map(select(.id != 7)) | $5" "$s/releases.json"
    else
      jq -r "$5" "$s/releases.json"
    fi ;;
  'api --paginate repos/o/r/releases/7/assets --jq '*)
    [ -z "${ASSETS_FAIL:-}" ] || { echo 'gh: Server Error (HTTP 500)' >&2; exit 1; }
    jq -r "$5" "$s/assets.json" ;;
  'api -X DELETE repos/o/r/releases/assets/'*)
    edit assets.json 'map(select(.id != $id))' --argjson id "${4##*/}" ;;
  'release create '*)
    edit releases.json '. + [{id: 7, tag_name: $t, draft: true}]' --arg t "$3"
    echo "${CREATE_LAG:-0}" > "$s/lag" ;;
  'release upload '*)
    tag=$3
    shift 3
    while [ "$1" != --repo ]; do
      [ -z "${UPLOAD_FAIL:-}" ] || { echo 'upload failed' >&2; exit 1; }
      if [ -z "${UPLOAD_DROP:-}" ]; then
        edit assets.json '. + [{name: $n, state: "uploaded", id: 900, digest: $d}]' \
          --arg n "$(basename "$1")" --arg d "sha256:$(sha256sum "$1" | cut -d' ' -f1)"
      fi
      shift
    done ;;
  'release edit '*' --repo o/r --draft=false --latest='*)
    edit releases.json 'map(if .tag_name == $t then .draft = false else . end)' --arg t "$3" ;;
  *) echo "unexpected: gh $*" >&2; exit 99 ;;
esac
EOF
chmod +x "$tmp/gh"
export GH="$tmp/gh" GITHUB_REPOSITORY=o/r STATE="$tmp/state" RELEASE_POLL_SECONDS=0

mkdir -p "$tmp/dist"
echo a > "$tmp/dist/a.tar.gz"
echo b > "$tmp/dist/b.tar.gz"
sha() { echo "sha256:$(sha256sum "$tmp/dist/$1" | cut -d' ' -f1)"; }

# JSON for a release and an asset, as the GitHub API returns them (trimmed).
rel() { # rel <id> <tag> <draft>
  printf '{"id":%s,"tag_name":"%s","draft":%s,"name":"%s"}' "$1" "$2" "$3" "$2"
}
asset() { # asset <name> <state> <id> [<digest>]
  if [ $# -ge 4 ]; then
    printf '{"name":"%s","state":"%s","id":%s,"digest":"%s","size":2}' "$1" "$2" "$3" "$4"
  else
    printf '{"name":"%s","state":"%s","id":%s,"digest":null,"size":2}' "$1" "$2" "$3"
  fi
}
# Every case also has a release for another tag, which must be left alone.
other=$(rel 5 v0.9.0 false)

given() { # given <releases, comma-separated> <assets of release 7, comma-separated>
  rm -rf "$STATE"
  mkdir "$STATE"
  : > "$STATE/log"
  echo "[$other${1:+,$1}]" > "$STATE/releases.json"
  echo "[$2]" > "$STATE/assets.json"
}

c=
run() { # run <case> <tag> <latest>: sets rc
  c=$1
  rc=0
  "$dir/gh-release.sh" "$2" "$3" "$tmp/dist" > "$tmp/out" 2>&1 || rc=$?
  expect "no unexpected gh calls" not_said '^unexpected: gh'
}

expect() { # expect <what> <command...>
  local what=$1
  shift
  if ! "$@"; then
    echo "FAIL: $c: $what"
    cat "$tmp/out"
    fail=1
  fi
}
exit_is() { [ "$rc" -eq "$1" ]; }
logged() { grep -q -- "$1" "$STATE/log"; }
not_logged() { ! grep -q -- "$1" "$STATE/log"; }
said() { grep -q -- "$1" "$tmp/out"; }
not_said() { ! grep -q -- "$1" "$tmp/out"; }
draft_is() { [ "$(jq -r '.[] | select(.id == 7) | .draft' "$STATE/releases.json")" = "$1" ]; }
other_untouched() { [ "$(jq -c '.[] | select(.id == 5)' "$STATE/releases.json")" = "$other" ]; }
on_release() { # on_release <name>: one uploaded asset with the digest of dist/<name>
  [ "$(jq --arg n "$1" --arg d "$(sha "$1")" \
    '[.[] | select(.name == $n and .state == "uploaded" and .digest == $d)] | length' \
    "$STATE/assets.json")" = 1 ]
}
a_ok=$(asset a.tar.gz uploaded 1 "$(sha a.tar.gz)")
b_ok=$(asset b.tar.gz uploaded 2 "$(sha b.tar.gz)")

given "" ""
run "new release" v1.0.0 true
expect "exit 0" exit_is 0
expect "created as a draft" logged 'release create v1.0.0 --repo o/r --draft --verify-tag --title v1.0.0 --prerelease=false'
expect "a uploaded" on_release a.tar.gz
expect "b uploaded" on_release b.tar.gz
expect "published as latest" logged 'release edit v1.0.0 --repo o/r --draft=false --latest=true'
expect "published" draft_is false
expect "other release untouched" other_untouched

given "" ""
CREATE_LAG=3 run "release list lags behind the create" v1.0.0 true
expect "exit 0" exit_is 0
expect "created once" [ "$(grep -c 'release create' "$STATE/log")" -eq 1 ]
expect "a uploaded" on_release a.tar.gz
expect "published" draft_is false

given "" ""
CREATE_LAG=20 run "release never shows up in the list" v1.0.0 true
expect "exit 1" exit_is 1
expect "says why" said '::error::release v1.0.0 not found after creating it'
expect "created once" [ "$(grep -c 'release create' "$STATE/log")" -eq 1 ]
expect "nothing uploaded" not_logged 'release upload'

given "$(rel 7 v1.0.0 false)" "$a_ok,$b_ok"
run "re-run on the published release" v1.0.0 true
expect "exit 0" exit_is 0
expect "nothing created" not_logged 'release create'
expect "nothing uploaded" not_logged 'release upload'
expect "not edited" not_logged 'release edit'

given "$(rel 7 v1.0.0 true)" "$a_ok"
run "draft with one file uploaded" v1.0.0 true
expect "exit 0" exit_is 0
expect "only b uploaded" logged "release upload v1.0.0 $tmp/dist/b.tar.gz --repo o/r"
expect "b uploaded" on_release b.tar.gz
expect "published" draft_is false

given "$(rel 7 v1.0.0 true)" "$a_ok,$(asset b.tar.gz starter 2)"
run "draft with an unfinished upload" v1.0.0 true
expect "exit 0" exit_is 0
expect "unfinished file deleted" logged 'api -X DELETE repos/o/r/releases/assets/2'
expect "b uploaded" on_release b.tar.gz
expect "published" draft_is false

given "$(rel 7 v1.0.0 true)" "$(asset a.tar.gz uploaded 1 sha256:0000)"
run "file with other bytes" v1.0.0 true
expect "exit 1" exit_is 1
expect "says which file" said '::error::a.tar.gz on release v1.0.0 has digest sha256:0000, which does not match'
expect "still a draft" draft_is true

given "$(rel 7 v1.0.0 true)" "$(asset a.tar.gz uploaded 1)"
run "file without a digest" v1.0.0 true
expect "exit 1" exit_is 1
expect "says no digest" said '::error::a.tar.gz on release v1.0.0 has no digest'
expect "still a draft" draft_is true

given "$(rel 7 v1.0.0 true)" "$(asset c.tar.gz uploaded 3 sha256:0000)"
run "file on the release that is not in the build" v1.0.0 true
expect "exit 1" exit_is 1
expect "says which file" said '::error::c.tar.gz is on release v1.0.0 but not in this build'
expect "still a draft" draft_is true

given "" ""
UPLOAD_FAIL=1 run "upload fails" v1.0.0 true
expect "exit non-zero" [ "$rc" -ne 0 ]
expect "says why" said 'upload failed'
expect "still a draft" draft_is true

given "" ""
UPLOAD_DROP=1 run "upload reports success but the file is missing" v1.0.0 true
expect "exit 1" exit_is 1
expect "says which file" said '::error::a.tar.gz is not on release v1.0.0 with the digest of this build'
expect "still a draft" draft_is true

given "" ""
run "prerelease" v1.1.0-rc.1 false
expect "exit 0" exit_is 0
expect "created as a prerelease" logged 'release create v1.1.0-rc.1 --repo o/r --draft --verify-tag --title v1.1.0-rc.1 --prerelease=true'
expect "published, not latest" logged 'release edit v1.1.0-rc.1 --repo o/r --draft=false --latest=false'

given "" ""
LIST_FAIL=1 run "release list fails" v1.0.0 true
expect "exit non-zero" [ "$rc" -ne 0 ]
expect "says why" said 'HTTP 500'
expect "nothing created" not_logged 'release create'

given "$(rel 7 v1.0.0 true)" ""
ASSETS_FAIL=1 run "asset list fails" v1.0.0 true
expect "exit non-zero" [ "$rc" -ne 0 ]
expect "says why" said 'HTTP 500'
expect "nothing uploaded" not_logged 'release upload'
expect "still a draft" draft_is true

given "$(rel 7 v1.0.0 true),$(rel 8 v1.0.0 true)" ""
run "two releases for the tag" v1.0.0 true
expect "exit 1" exit_is 1
expect "says why" said '::error::more than one release for v1.0.0'

given "" ""
mv "$tmp/dist" "$tmp/full"
mkdir "$tmp/dist"
run "no files to release" v1.0.0 true
expect "exit 1" exit_is 1
expect "says why" said '::error::no files in'
expect "nothing created" not_logged 'release create'
rmdir "$tmp/dist"
mv "$tmp/full" "$tmp/dist"

[ "$fail" -eq 0 ] || exit 1
echo "gh-release: ok"
