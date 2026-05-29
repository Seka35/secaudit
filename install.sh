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

# Auto-pull WPScan Docker image if Docker is available
if command -v docker &> /dev/null; then
    if ! docker image inspect wpscanteam/wpscan &> /dev/null; then
        echo "⚙️ Pulling WPScan Docker image..."
        docker pull wpscanteam/wpscan 2>/dev/null && echo "✅ WPScan Docker image ready" || echo "⚠️ Failed to pull WPScan image"
    fi
fi

# Auto-install Gitleaks if not present
if ! command -v gitleaks &> /dev/null; then
    echo "⚙️ Gitleaks not found. Auto-installing Gitleaks..."
    VERSION="8.18.2"
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then ARCH="arm64"; fi

    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_${OS}_${ARCH}.zip" -O /tmp/gitleaks.zip
    if [ -f /tmp/gitleaks.zip ]; then
        unzip -q /tmp/gitleaks.zip -d /tmp/
        chmod +x /tmp/gitleaks
        if command -v sudo &> /dev/null; then
            sudo mv /tmp/gitleaks "$BIN_DIR/"
        else
            mv /tmp/gitleaks "$BIN_DIR/"
        fi
        rm /tmp/gitleaks.zip
        echo "✅ Gitleaks installed successfully to $BIN_DIR/gitleaks"
    else
        echo "⚠️ Failed to download Gitleaks. Run: sudo apt install gitleaks"
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
