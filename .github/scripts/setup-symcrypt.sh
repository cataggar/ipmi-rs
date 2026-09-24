#!/usr/bin/env bash
set -euo pipefail

# Official SymCrypt v103.4.2 release; required for ipmi-rs --all-features.
asset=symcrypt-linux-generic-amd64-release-103.4.2-171f697.tar.gz
expected=bd018f8f3c2d331e5124d8ecc659bbbad590e840d7fba113cd31b9889acfeeaa
mkdir -p .native-symcrypt
curl --fail --location --retry 3 \
  "https://github.com/microsoft/SymCrypt/releases/download/v103.4.2/$asset" \
  --output ".native-symcrypt/$asset"
echo "$expected  .native-symcrypt/$asset" | sha256sum --check
tar -xzf ".native-symcrypt/$asset" -C .native-symcrypt

# symcrypt-sys 0.4.0 asks the linker for -lsymcrypt; the loader needs the
# same directory when running tests and compiled binaries.
echo "RUSTFLAGS=-L native=$GITHUB_WORKSPACE/.native-symcrypt/lib" >> "$GITHUB_ENV"
echo "LD_LIBRARY_PATH=$GITHUB_WORKSPACE/.native-symcrypt/lib:${LD_LIBRARY_PATH:-}" >> "$GITHUB_ENV"
