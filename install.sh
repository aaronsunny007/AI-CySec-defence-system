#!/usr/bin/env sh
# AEGIS one-command install (Linux / macOS). Free and local: no accounts, no paid services.
#
#   curl -fsSL https://raw.githubusercontent.com/aaronsunny007/AI-CySec-defence-system/main/install.sh | sh
#   or, from a clone:  ./install.sh
#
# What it does: gets the source (if you ran it via curl), makes sure a Go toolchain exists
# (downloads the official one into ~/.aegis/go if needed - no root), builds the gateway,
# and puts an `aegis` command on your PATH. It never touches your app.
set -eu

REPO_URL="${AEGIS_REPO:-https://github.com/aaronsunny007/AI-CySec-defence-system.git}"
REF="${AEGIS_REF:-main}"
HOME_DIR="${AEGIS_HOME:-$HOME/.aegis}"
GO_BOOTSTRAP="1.24.7"        # any Go >= 1.21 works: gateway/go.mod makes Go fetch the exact toolchain itself
GO_INDEX="${AEGIS_GO_INDEX:-https://go.dev/dl/?mode=json&include=all}"   # official download index (has SHA-256s)

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }


fetch() {   # fetch URL DEST
  if have curl; then curl -fsSL "$1" -o "$2"; elif have wget; then wget -q "$1" -O "$2"; else die "need curl or wget"; fi
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
  elif have openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else die "need sha256sum, shasum or openssl to verify the download"; fi
}

# The SHA-256 of one file as published in the official Go download index; empty if unavailable.
expected_sha256() {
  tmp="$(mktemp)"
  if fetch "$GO_INDEX" "$tmp" 2>/dev/null; then
    "$PY" -c 'import json,sys
fn=sys.argv[2]
for rel in json.load(open(sys.argv[1])):
    for f in rel.get("files", []):
        if f.get("filename") == fn:
            print(f.get("sha256", "")); sys.exit()' "$tmp" "$1" 2>/dev/null || true
  fi
  rm -f "$tmp"
}

safe_path() {
  case "$1" in *[\"\$\`\\]*|*"
"*) die "refusing a path containing a quote, backslash, dollar sign, backtick or newline: $1";; esac
}

main() {
  # --- python ---------------------------------------------------------------------
  PY=""
  for c in python3 python; do
    if have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then PY="$c"; break; fi
  done
  [ -n "$PY" ] || die "Python 3.10+ is required (https://www.python.org/downloads/ or your package manager), then re-run."

  # --- source ---------------------------------------------------------------------
  SELF_DIR=""
  case "$0" in */install.sh|install.sh) SELF_DIR="$(cd "$(dirname "$0")" && pwd)";; esac
  if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/aegis.py" ]; then
    SRC="$SELF_DIR"
  else
    have git || die "git is required to fetch AEGIS (or download the repo zip and run ./install.sh from it)."
    SRC="$HOME_DIR/src"
    mkdir -p "$HOME_DIR"
    if [ -d "$SRC/.git" ]; then
      say "Updating $SRC ..."; git -C "$SRC" fetch --depth 1 origin "$REF" && git -C "$SRC" checkout -q FETCH_HEAD
    else
      say "Fetching AEGIS into $SRC ..."; git clone --depth 1 --branch "$REF" "$REPO_URL" "$SRC"
    fi
  fi

  # --- go ---------------------------------------------------------------------------
  GO=""
  go_ok() { "$1" version 2>/dev/null | awk '{split(substr($3,3),v,"."); exit !(v[1]>1 || (v[1]==1 && v[2]>=21))}'; }
  if have go && go_ok go; then GO="$(command -v go)"
  elif [ -x "$HOME_DIR/go/bin/go" ] && go_ok "$HOME_DIR/go/bin/go"; then GO="$HOME_DIR/go/bin/go"
  else
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"; arch="$(uname -m)"
    case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die "unsupported CPU: $arch";; esac
    case "$os" in linux|darwin) ;; *) die "unsupported OS: $os (on Windows use install.ps1)";; esac
    fname="go${GO_BOOTSTRAP}.${os}-${arch}.tar.gz"
    url="https://go.dev/dl/${fname}"
    say "No Go toolchain found - downloading the official one to $HOME_DIR/go ($url) ..."
    mkdir -p "$HOME_DIR"
    fetch "$url" "$HOME_DIR/go.tgz"
    want="$(expected_sha256 "$fname")"
    [ -n "$want" ] || { rm -f "$HOME_DIR/go.tgz"; die "could not get the official SHA-256 for $fname from $GO_INDEX; not installing an unverified toolchain"; }
    got="$(sha256_of "$HOME_DIR/go.tgz")"
    if [ "$got" != "$want" ]; then rm -f "$HOME_DIR/go.tgz"; die "SHA-256 mismatch for $fname (expected $want, got $got); download discarded"; fi
    say "Checksum verified."
    rm -rf "$HOME_DIR/go"; tar -C "$HOME_DIR" -xzf "$HOME_DIR/go.tgz"; rm -f "$HOME_DIR/go.tgz"
    GO="$HOME_DIR/go/bin/go"
  fi
  say "Using Go: $GO"

  # --- build ----------------------------------------------------------------------------
  say "Building the gateway (first build downloads Coraza + the OWASP Core Rule Set, about a minute) ..."
  mkdir -p "$SRC/bin"
  ( cd "$SRC/gateway" && "$GO" build -o ../bin/gateway . && "$GO" build -o ../bin/replay ./cmd/replay )

  # --- command on PATH -----------------------------------------------------------------------
  BIN_DIR="${AEGIS_BIN:-$HOME/.local/bin}"
  mkdir -p "$BIN_DIR"
  # the launcher embeds these paths in a shell script: refuse anything that could break out of the quotes
  safe_path "$SRC"; safe_path "$PY"
  printf '#!/usr/bin/env sh\ncd "%s" && exec "%s" "%s/aegis.py" "$@"\n' "$SRC" "$(command -v "$PY")" "$SRC" > "$BIN_DIR/aegis"
  chmod +x "$BIN_DIR/aegis"

  say ""
  "$BIN_DIR/aegis" --help >/dev/null 2>&1 || die "aegis did not start after install"
  say "AEGIS installed in $SRC"
  case ":$PATH:" in *":$BIN_DIR:"*) ;; *) say "Add this to your shell profile so \`aegis\` is found:  export PATH=\"$BIN_DIR:\$PATH\"";; esac
  say ""
  say "Next:"
  say "  aegis init --target http://127.0.0.1:3000     # the app you want to protect"
  say "  aegis doctor"
  say "  aegis learn                                    # observe-only: records your normal traffic"
  say "  aegis protect                                  # when learn has seen enough traffic"
}

main "$@"
