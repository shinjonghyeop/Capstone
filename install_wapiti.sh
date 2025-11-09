#!/bin/bash

# python3와 pip3 설치 유무 확인
cd scanners/wapiti

if ! command -v python3 &> /dev/null; then
    echo "python3가 설치되어 있지 않습니다. 설치를 진행합니다."
    apt-get update
    apt-get install -y python3
fi

if ! command -v pip3 &> /dev/null; then
    echo "pip3가 설치되어 있지 않습니다. 설치를 진행합니다."
    apt-get install -y python3-pip
fi

python3 -m pip install -r requirements.txt
cd bin
echo 'export PATH="$PATH:$(pwd)"' >> ~/.bashrc
echo "Wapiti has been successfully installed."
