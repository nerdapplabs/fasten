#!/usr/bin/env bash
# Install a package the way a user gets it and run the integration smoke
# against that install: the files a publish would upload, in an empty
# directory outside the repo, with no path back to the source tree.
#
#   node  `npm pack` of js/, installed with npm into a new project.
#   rust  `cargo package` of fasten-core and rust/, unpacked, and built by
#         a new crate that depends on the unpacked SDK.
#
# The smoke programs and verify.py are the ones in tests/integration.
# (The Python wheel has its own check in python-wheels.yml.)
#
# Usage: scripts/release/install-check.sh <node|rust>
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <node|rust>" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../.." && pwd)
itest=$root/tests/integration
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

case $1 in
  node)
    name=$(cd "$root/js" && node -p 'require("./package.json").name')
    tgz=$(cd "$root/js" && npm pack --silent --pack-destination "$tmp")
    mkdir "$tmp/app"
    cd "$tmp/app"
    printf '{"name":"install-check","version":"0.0.0","private":true,"type":"module"}\n' > package.json
    npm install --no-audit --no-fund --silent "$tmp/$tgz"
    # The smoke imports the SDK as 'fasten'; a user imports the package name.
    sed "s|from 'fasten'|from '$name'|" "$itest/node/smoke.mjs" > smoke.mjs
    grep -q "from '$name'" smoke.mjs || { echo "::error::smoke.mjs does not import 'fasten'" >&2; exit 1; }
    node smoke.mjs | python3 "$itest/verify.py"
    ;;
  rust)
    field() { sed -n "s/^$2 = \"\(.*\)\"\$/\1/p" "$1/Cargo.toml" | head -n 1; }
    core=fasten-core-$(field "$root/fasten-core" version)
    sdk=$(field "$root/rust" name)-$(field "$root/rust" version)
    # --no-verify: the consumer crate below builds both. fasten-core may not
    # be on crates.io yet, so the SDK is packaged against the tree's copy.
    (cd "$root/fasten-core" && CARGO_TARGET_DIR="$tmp/target" cargo package -q --locked --no-verify)
    (cd "$root/rust" && CARGO_TARGET_DIR="$tmp/target" cargo package -q --no-verify \
        --config "patch.crates-io.fasten-core.path=\"$root/fasten-core\"")
    mkdir "$tmp/crates"
    tar -xzf "$tmp/target/package/$core.crate" -C "$tmp/crates"
    tar -xzf "$tmp/target/package/$sdk.crate" -C "$tmp/crates"
    mkdir -p "$tmp/app/src"
    cp "$itest/rust/src/"*.rs "$tmp/app/src/"
    cat > "$tmp/app/Cargo.toml" <<TOML
[package]
name = "fasten-itest"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
fasten-sdk = { path = "$tmp/crates/$sdk" }
serde_json = "1"

[patch.crates-io]
fasten-core = { path = "$tmp/crates/$core" }
TOML
    cd "$tmp/app"
    CARGO_TARGET_DIR="$tmp/target" cargo run -q --release | python3 "$itest/verify.py"
    ;;
  *)
    echo "usage: $0 <node|rust>" >&2; exit 2 ;;
esac
