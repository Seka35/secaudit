#!/bin/bash

# Get the absolute path of the directory where install.sh is located
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"

echo "🚀 Installing SecAudit globally..."

# Check if virtual environment exists, if not, create it
if [ ! -d "$INSTALL_DIR/venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
fi

# Install requirements
echo "📥 Installing dependencies..."
source "$INSTALL_DIR/venv/bin/activate"
pip install -r "$INSTALL_DIR/requirements.txt" --quiet

# Create ~/.local/bin if it doesn't exist
mkdir -p "$BIN_DIR"

# Create the wrapper script content
WRAPPER_SCRIPT="#!/bin/bash
# Wrapper script for SecAudit
cd \"$INSTALL_DIR\" && source venv/bin/activate && exec python3 secaudit.py \"\$@\""

# Write the wrapper script
echo "$WRAPPER_SCRIPT" > "$BIN_DIR/secaudit"

# Make it executable
chmod +x "$BIN_DIR/secaudit"

echo ""
echo "✅ SecAudit has been successfully installed!"
echo "👉 You can now run the tool from anywhere by typing: secaudit"
echo ""
echo "Note: If 'secaudit' command is not found, restart your terminal or add $BIN_DIR to your PATH."
