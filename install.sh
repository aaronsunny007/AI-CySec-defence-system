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

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

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
  url="https://go.dev/dl/go${GO_BOOTSTRAP}.${os}-${arch}.tar.gz"
  say "No Go toolchain found - downloading the official one to $HOME_DIR/go ($url) ..."
  mkdir -p "$HOME_DIR"
  if have curl; then curl -fsSL "$url" -o "$HOME_DIR/go.tgz"; elif have wget; then wget -q "$url" -O "$HOME_DIR/go.tgz"; else die "need curl or wget"; fi
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
cat > "$BIN_DIR/aegis" <<EOF
#!/usr/bin/env sh
cd "$SRC" && exec $PY "$SRC/aegis.py" "\$@"
EOF
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
