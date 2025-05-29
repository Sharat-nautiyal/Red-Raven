#!/bin/bash

echo "Attempting to run Red Raven with 'sudo -E' (preserving environment)..."
sudo -E python3 "Red Raven.py"
exit_code=$?

if [ "$exit_code" -ne 0 ]; then
    echo ""
    echo "Application failed to start with 'sudo -E' (exit code: $exit_code)."
    echo "Trying again with plain 'sudo' (without preserving environment)..."
    sudo python3 "Red Raven.py"
    exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        echo ""
        echo "Application also failed to start with plain 'sudo' (exit code: $exit_code)."
        echo "Please ensure you have PyQt6 installed and that your display server is running."
        echo "If you continue to have issues, you might need to investigate your system's permissions or environment settings."
        exit 1
    fi
fi

echo ""
echo "Red Raven started successfully."
