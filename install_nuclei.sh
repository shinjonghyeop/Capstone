#!/bin/bash

# This script automates the installation of the nuclei tool from a local source.
# It builds the binary, and moves it to /usr/local/bin.

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting the installation of nuclei..."
# Change directory to the nuclei command source folder
echo "Step 1: Navigating to the build directory..."
cd scanners

# nuclei.crt Download
cd nuclei/pkg/keys
wget https://raw.githubusercontent.com/projectdiscovery/nuclei/refs/heads/dev/pkg/keys/nuclei.crt
cd ../../../

# Build the Go application
echo "Step 2: Building the nuclei binary..."
cd nuclei/cmd/nuclei
go build

# Move the built binary to a directory in the system's PATH
# This makes the 'nuclei' command available system-wide.
# Note: This command requires administrator privileges (sudo).
echo "Step 3: Moving the binary to /usr/local/bin/. You might be asked for your password."
echo 'export PATH="$PATH:$HOME/secure_ai_project/scanners/nuclei/cmd/nuclei"' >> ~/.bashrc
source ~/.bashrc

echo "Nuclei has been successfully installed."
