#!/usr/bin/env bash
# Erebyx installer
#
# Usage (from inside the cloned repository):
#   ./install.sh               -> install / update Erebyx (interactive language prompt)
#   ./install.sh --lang id     -> install and set default language to Indonesian
#   ./install.sh --lang en     -> install and set default language to English
#   ./install.sh --uninstall   -> uninstall Erebyx

set -euo pipefail

APP="erebyx"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$APP"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/$APP"
CONFIG_FILE="$CONFIG_DIR/config"
VENV_DIR="$DATA_DIR/venv"
BIN_DIR="$HOME/.local/bin"
LINK="$BIN_DIR/$APP"

info() { printf '\033[1;36m[erebyx]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[erebyx]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[erebyx]\033[0m %s\n' "$*" >&2; exit 1; }

uninstall() {
    if command -v pipx >/dev/null 2>&1 && pipx list --short 2>/dev/null | grep -q "^$APP "; then
        pipx uninstall "$APP"
    fi
    if [ -L "$LINK" ]; then rm -f "$LINK"; fi
    if [ -d "$DATA_DIR" ]; then rm -rf "$DATA_DIR"; fi
    if [ -d "$CONFIG_DIR" ]; then rm -rf "$CONFIG_DIR"; fi
    info "Erebyx has been uninstalled."
}

CHOSEN_LANG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall)
            uninstall
            exit 0
            ;;
        --lang)
            shift
            CHOSEN_LANG="${1:-}"
            ;;
        --lang=*)
            CHOSEN_LANG="${1#*=}"
            ;;
        *)
            fail "Unknown option: $1 (supported: --lang id|en, --uninstall)"
            ;;
    esac
    shift || true
done

select_language() {
    if [ -n "$CHOSEN_LANG" ]; then
        case "$CHOSEN_LANG" in
            id|ID|indonesian) CHOSEN_LANG="id"; return ;;
            en|EN|english)    CHOSEN_LANG="en"; return ;;
            *) fail "Unsupported language '$CHOSEN_LANG'. Use 'id' or 'en'." ;;
        esac
    fi

    if [ -t 0 ]; then
        printf '\n\033[1;36m[erebyx]\033[0m Choose default output language for Erebyx:\n'
        printf '  [1] Bahasa Indonesia (id) [default]\n'
        printf '  [2] English (en)\n'
        printf 'Select language [1/2]: '
        read -r answer || answer=""
        case "${answer,,}" in
            2|en|english) CHOSEN_LANG="en" ;;
            *)            CHOSEN_LANG="id" ;;
        esac
    else
        CHOSEN_LANG="id"
    fi
}

PYTHON="$(command -v python3 || command -v python || true)"
[ -n "$PYTHON" ] || fail "Python 3.10+ not found. Please install Python first."
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || fail "Erebyx requires Python 3.10 or newer."

select_language

mkdir -p "$CONFIG_DIR"
printf 'lang=%s\n' "$CHOSEN_LANG" > "$CONFIG_FILE"
if [ "$CHOSEN_LANG" = "id" ]; then
    info "Default output language set to: Bahasa Indonesia (id) -> $CONFIG_FILE"
else
    info "Default output language set to: English (en) -> $CONFIG_FILE"
fi
info "(You can change this anytime with: erebyx --set-lang en|id)"

if command -v pipx >/dev/null 2>&1; then
    info "pipx detected, installing Erebyx via pipx..."
    pipx install --force "$SRC_DIR"
else
    info "Creating isolated environment in $VENV_DIR ..."
    mkdir -p "$DATA_DIR" "$BIN_DIR"
    "$PYTHON" -m venv "$VENV_DIR" \
        || fail "Failed to create venv. On Debian/Ubuntu run: sudo apt install python3-venv"
    "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
    "$VENV_DIR/bin/python" -m pip install --quiet --upgrade "$SRC_DIR"
    ln -sf "$VENV_DIR/bin/$APP" "$LINK"
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        warn "$BIN_DIR is not in your PATH yet. Add this line to ~/.bashrc or ~/.zshrc:"
        warn "    export PATH=\"\$HOME/.local/bin:\$PATH\""
        warn "Then open a new terminal (or run: source ~/.bashrc)."
        ;;
esac

info "Installation complete! Try running:  erebyx --list-modules"
