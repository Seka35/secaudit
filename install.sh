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

# Auto-install Nuclei if not present
if ! command -v nuclei &> /dev/null; then
    echo "⚙️ Nuclei not found. Auto-installing Nuclei..."
    VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -n "$VERSION" ]; then
        VERSION_NUM=${VERSION#v}
        OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
        ARCH="$(uname -m)"
        if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
        if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then ARCH="arm64"; fi
        
        wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${VERSION}/nuclei_${VERSION_NUM}_${OS}_${ARCH}.zip" -O /tmp/nuclei.zip
        if [ -f /tmp/nuclei.zip ]; then
            unzip -q /tmp/nuclei.zip nuclei -d /tmp/
            mv /tmp/nuclei "$BIN_DIR/"
            rm /tmp/nuclei.zip
            echo "✅ Nuclei installed successfully to $BIN_DIR/nuclei"
        else
            echo "⚠️ Failed to download Nuclei. Please install it manually for extended vulnerability scanning."
        fi
    else
        echo "⚠️ Failed to find latest Nuclei version. Please install it manually."
    fi
fi

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
