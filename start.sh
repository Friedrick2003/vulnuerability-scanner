#!/bin/bash
echo ""
echo " ============================================="
echo "  RealVulnScan - Starting server..."
echo " ============================================="
echo ""

if ! command -v node &> /dev/null; then
    echo " ERROR: Node.js is not installed!"
    echo " Install with:"
    echo "   Ubuntu/Debian: sudo apt install nodejs npm"
    echo "   Mac:           brew install node"
    echo "   Or download:   https://nodejs.org"
    exit 1
fi

if [ ! -d "node_modules" ]; then
    echo " Installing dependencies..."
    npm install
    echo ""
fi

echo " Server starting at: http://localhost:3000"
echo " Open that URL in your browser to scan."
echo ""
echo " Press Ctrl+C to stop."
echo ""
node server.js
