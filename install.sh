#!/bin/bash

# Skill Credential Scanner - Installation Script
# Author: @justabotx
# Version: 1.0.0
# Date: 2026-02-01

set -e

echo "=================================="
echo "Skill Credential Scanner Install"
echo "=================================="
echo ""

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo ""

# Install YARA Python (optional but recommended)
echo "📦 Installing YARA Python bindings for better detection..."
pip3 install yara-python || {
    echo "⚠️  Warning: Failed to install yara-python"
    echo "   Scanner will use fallback pattern matching instead"
    echo "   This is acceptable but provides less accurate detection"
}
echo ""

# Create symlink for easy access
SCAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_SCRIPT="$SCAN_DIR/scripts/scan.py"

if [ ! -L "$HOME/.local/bin/skill-cred-scan" ]; then
    echo "🔗 Creating command symlink..."
    mkdir -p "$HOME/.local/bin"
    ln -s "$SCAN_SCRIPT" "$HOME/.local/bin/skill-cred-scan"
    echo "✅ Created symlink: $HOME/.local/bin/skill-cred-scan"

    # Add to PATH if not already there
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        echo ""
        echo "📝 Add $HOME/.local/bin to your PATH:"
        echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
        echo "   Add this to your ~/.bashrc or ~/.zshrc"
    fi
else
    echo "✅ Symlink already exists: $HOME/.local/bin/skill-cred-scan"
fi
echo ""

# Test installation
echo "🧪 Testing installation..."
python3 "$SCAN_SCRIPT" --help > /dev/null 2>&1 || {
    echo "❌ Error: Scanner not working correctly"
    exit 1
}
echo "✅ Scanner is working!"
echo ""

echo "=================================="
echo "Installation Complete!"
echo "=================================="
echo ""
echo "Usage:"
echo "  skill-cred-scan /path/to/skill"
echo "  python3 scripts/scan.py /path/to/skill"
echo ""
echo "For more information, see README.md"
