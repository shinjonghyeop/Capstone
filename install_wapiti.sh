#!/bin/bash
set -e

echo "Starting Wapiti installation..."

# Python3와 pip3 설치 확인
if ! command -v python3 &> /dev/null; then
    echo "[!] python3가 설치되어 있지 않습니다. 설치를 진행합니다."
    sudo apt-get update
    sudo apt-get install -y python3
fi

if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3가 설치되어 있지 않습니다. 설치를 진행합니다."
    sudo apt-get install -y python3-pip
fi

# Wapiti 디렉토리로 이동
cd scanners/wapiti || {
    echo "[!] Error: scanners/wapiti 디렉토리를 찾을 수 없습니다."
    exit 1
}

# 의존성 설치
echo "[+] Installing Python dependencies..."
python3 -m pip install -r requirements.txt

# PATH에 추가
cd bin
WAPITI_BIN_PATH="$(pwd)"
echo "[+] Adding Wapiti to PATH..."
echo "export PATH=\"\$PATH:$WAPITI_BIN_PATH\"" >> ~/.bashrc

# 설치 확인
if [ -f "wapiti" ]; then
    echo "[+] Wapiti has been successfully installed."
    echo "[+] Location: $WAPITI_BIN_PATH"
    echo "[!] Please run 'source ~/.bashrc' to update your PATH"
else
    echo "[!] Warning: wapiti binary not found in bin directory"
    exit 1
fi
