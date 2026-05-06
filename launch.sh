#!/bin/bash
# TanOS Launcher
# This script builds and starts the TanOS node.

echo "🚀 Starting TanOS..."

# Build if necessary
cargo build -p tanos-node

# Check if port 7700 is taken and try to be helpful
if lsof -Pi :7700 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️  Port 7700 is already in use. I'll try the next one, but if you want to clear it, run:"
    echo "   kill -9 \$(lsof -t -i:7700)"
fi

# Start the node
cargo run -p tanos-node -- start
