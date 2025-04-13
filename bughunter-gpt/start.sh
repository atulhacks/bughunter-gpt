#!/bin/bash

echo "Starting BugHunter GPT server..."
echo "The application will be available at http://localhost:8000"
echo "Press Ctrl+C to stop the server"
echo ""

# Check if Python 3 is installed
if command -v python3 &>/dev/null; then
    python3 -m http.server 8000
elif command -v python &>/dev/null; then
    python -m http.server 8000
else
    echo "Error: Python is not installed"
    echo "Please install Python 3 to run the server"
    exit 1
fi