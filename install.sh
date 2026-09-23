#!/usr/bin/env bash
# ==============================================================================
# CyberEDT NEX — Installer for Kali Linux (Live + Persistence)
# Offline-friendly setup script for authorized security training environments.
# ==============================================================================
set -e

# Resolve repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "  CyberEDT NEX — Deployment & Setup (Kali Linux)"
echo "============================================================"

# 1. Verify Python 3.11+
if ! command -v python3 &>/dev/null; then
    echo "[!] Error: python3 is not installed."
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "[!] Error: Python 3.10+ required (detected $PY_VER)."
    exit 1
fi
echo "[+] Detected Python $PY_VER"

# 2. Setup Virtual Environment
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "[+] Existing virtual environment found at $VENV_DIR"
fi

# Activate venv
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# 3. Upgrade pip and install NEX package
echo "[+] Installing NEX and core dependencies (PyYAML)..."
pip install --upgrade pip --quiet
pip install -e . --quiet

# Optional: try installing llama-cpp-python if wheels or compilation available
if python3 -c "import llama_cpp" &>/dev/null; then
    echo "[+] llama-cpp-python is already installed."
else
    echo "[*] Optional: llama-cpp-python is not installed yet."
    echo "    To install offline with pre-built wheel: pip install llama-cpp-python"
fi

# 4. Check for GGUF model files in models/
MODELS_DIR="$SCRIPT_DIR/models"
mkdir -p "$MODELS_DIR"

QWEN_MODEL="$MODELS_DIR/qwen3-0.6b-instruct.Q4_K_M.gguf"
GEMMA_MODEL="$MODELS_DIR/functiongemma-270m-it.Q8_0.gguf"

echo "------------------------------------------------------------"
echo " Model Weight Verification (Offline Storage)"
echo "------------------------------------------------------------"

if [ -f "$QWEN_MODEL" ]; then
    QWEN_SIZE=$(du -h "$QWEN_MODEL" | cut -f1)
    echo "[✓] Qwen3 0.6B model found: $QWEN_MODEL ($QWEN_SIZE)"
else
    echo "[-] Qwen3 0.6B GGUF weights not found at:"
    echo "    $QWEN_MODEL"
    echo "    (NEX will run in intelligent deterministic offline mode until weights are placed here)"
fi

if [ -f "$GEMMA_MODEL" ]; then
    GEMMA_SIZE=$(du -h "$GEMMA_MODEL" | cut -f1)
    echo "[✓] FunctionGemma 270M model found: $GEMMA_MODEL ($GEMMA_SIZE)"
else
    echo "[-] FunctionGemma 270M GGUF weights not found at:"
    echo "    $GEMMA_MODEL"
    echo "    (Needed only when running with --dual flag)"
fi

# 5. Create launcher wrapper in PATH
BIN_DEST=""
if [ -w "/usr/local/bin" ]; then
    BIN_DEST="/usr/local/bin/nex"
elif [ -d "$HOME/.local/bin" ] && [ -w "$HOME/.local/bin" ]; then
    BIN_DEST="$HOME/.local/bin/nex"
else
    mkdir -p "$HOME/.local/bin"
    BIN_DEST="$HOME/.local/bin/nex"
fi

echo "[+] Creating entrypoint launcher at $BIN_DEST..."
cat << 'EOF' > "$BIN_DEST"
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
# Try finding virtual environment
if [ -f "$SCRIPT_DIR/share/nex/.venv/bin/nex" ]; then
    exec "$SCRIPT_DIR/share/nex/.venv/bin/nex" "$@"
fi
EOF

# Write direct absolute launcher pointing to venv python
cat << EOF > "$BIN_DEST"
#!/usr/bin/env bash
export NEX_ROOT="$SCRIPT_DIR"
exec "$VENV_DIR/bin/nex" "\$@"
EOF
chmod +x "$BIN_DEST"

# Ensure runtime directories exist
mkdir -p "$SCRIPT_DIR/.nex/raw"

echo "============================================================"
echo "  [✓] NEX Installation Complete!"
echo "============================================================"
echo "  Launch interactive assistant with:"
echo "    $ nex"
echo "  Or with dual-model reasoning:"
echo "    $ nex --dual"
echo "  Or inspect status:"
echo "    $ nex status"
echo "============================================================"
