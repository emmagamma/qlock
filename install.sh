#!/usr/bin/env bash
set -e

echo "🪬 Installing qlock..."

# Check for required dependencies: git and cargo
for dep in cargo git; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "❌ $dep is required but not found. Please install it first."
    exit 1
  fi
done

# Function to compare semantic versions: returns 0 if $1 >= $2, else 1
version_ge() {
  [ "$1" = "$(printf '%s\n%s' "$1" "$2" | sort -V | tail -n1)" ]
}

# Fetch the latest release tag from GitHub
LATEST_TAG=$(git ls-remote --tags https://github.com/emmagamma/qlock.git \
  | awk -F/ '{print $3}' | grep -E '^v?[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -V | tail -n1)
LATEST_VERSION=${LATEST_TAG#v}
echo "📦 Latest available version: $LATEST_VERSION"

# Check existing installation, if any
if command -v qlock >/dev/null 2>&1; then
  INSTALLED_VERSION=$(qlock --version 2>/dev/null | awk '{print $NF}')
  INSTALLED_VERSION=${INSTALLED_VERSION#v}
  echo "📍 Installed version: $INSTALLED_VERSION"
else
  INSTALLED_VERSION="none"
fi

# Compare versions and skip install if up to date
if [[ "$INSTALLED_VERSION" != "none" ]] && version_ge "$INSTALLED_VERSION" "$LATEST_VERSION"; then
  echo "✅ Already up to date: installed ($INSTALLED_VERSION) ≥ latest ($LATEST_VERSION)"
  exit 0
fi

# Clone, build, and install
TMP_DIR=$(mktemp -d)
echo "📁 Cloning into temp directory: $TMP_DIR"
if ! git clone --depth 1 --branch "$LATEST_TAG" https://github.com/emmagamma/qlock.git "$TMP_DIR/qlock" >/dev/null 2>&1; then
  echo "❌ Failed to clone qlock repository. Please check your internet connection and try again."
  exit 1
fi
cd "$TMP_DIR/qlock"

echo "⚙️ Building qlock version $LATEST_VERSION..."
cargo install --path . --force

# Install bash completion script from the cloned repo instead of downloading it
COMPLETION_DIR="$HOME/.bash_completion.d"
mkdir -p "$COMPLETION_DIR"

completion_missing=false
if [[ -f ./completions/qlock.bash ]]; then
  cp ./completions/qlock.bash "$COMPLETION_DIR/qlock"
  echo "🛠 Copied completion script from cloned repo."
else
  echo "⚠️ Completion script not found in cloned repo, skipping."
  completion_missing=true
fi

# Determine user default shell config file
SHELL_NAME=$(basename "$SHELL")
case "$SHELL_NAME" in
  zsh)
    SHELL_RC="$HOME/.zshrc"
    ;;
  bash)
    SHELL_RC="$HOME/.bashrc"
    ;;
  *)
    SHELL_RC="$HOME/.bashrc"
    ;;
esac

# Only add source line if completion script copied successfully
if [[ "$completion_missing" = false ]]; then
  if ! grep -q "bash_completion.d/qlock" "$SHELL_RC"; then
    echo "source \"$COMPLETION_DIR/qlock\"" >> "$SHELL_RC"
    echo "✅ Added completion support to $SHELL_RC"
  fi
fi

# Clean up temp directory
cd ~
rm -rf "$TMP_DIR"
echo "🧹 Removed cloned repo & all temp files."

echo ""
echo "🎉 qlock v$LATEST_VERSION installed successfully!"

if [ "$completion_missing" = false ]; then
  echo ""
  echo "⚠️ To enable shell tab completion, please run:"
  echo "   source ~/${SHELL_RC##*/}"
  echo "   or restart your terminal session."
fi
