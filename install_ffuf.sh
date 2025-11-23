#!/bin/bash
cd ~
git clone https://github.com/ffuf/ffuf ; cd ffuf ; go get ; go build
echo 'export PATH="$PATH:$HOME/ffuf"' >> ~/.bashrc
source ~/.bashrc
echo "ffuf has been successfully installed."