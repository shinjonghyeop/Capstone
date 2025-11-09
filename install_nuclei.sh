#!/bin/bash

# This script automates the installation of the nuclei tool from a local source.
# It builds the binary, and moves it to /usr/local/bin.

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting the installation of nuclei..."
<<<<<<< HEAD
wget https://go.dev/dl/go1.25.4.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.4.linux-amd64.tar.gz
rm go1.25.4.linux-amd64.tar.gz
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.zshrc
source ~/.zshrc
=======
>>>>>>> cd77f50b45ceeadc840edfb7e093464b903be931
# Change directory to the nuclei command source folder
echo "Step 1: Navigating to the build directory..."
cd scanners

# Build the Go application
echo "Step 2: Building the nuclei binary..."
git clone https://github.com/projectdiscovery/nuclei.git
cd nuclei/cmd/nuclei
go build

# Move the built binary to a directory in the system's PATH
# This makes the 'nuclei' command available system-wide.
# Note: This command requires administrator privileges (sudo).
echo "Step 3: Moving the binary to /usr/local/bin/. You might be asked for your password."
<<<<<<< HEAD
echo 'export PATH="$PATH:$(pwd)"' >> ~/.zshrc
source ~/.zshrc
=======
echo 'export PATH="$PATH:$(pwd)"' >> ~/.bashrc
>>>>>>> cd77f50b45ceeadc840edfb7e093464b903be931

# Verify the installation by checking the version
echo "Step 4: Verifying the installation..."

echo "Nuclei has been successfully installed."
