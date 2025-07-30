#!/bin/bash

# Hacklipse OSINT 파이프라인 의존성 설치 스크립트
# Ubuntu/Debian 기반 시스템용

echo "=================================="
echo "Hacklipse OSINT 의존성 설치 시작"
echo "=================================="

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 함수: 성공 메시지
success_msg() {
    echo -e "${GREEN}✓ $1${NC}"
}

# 함수: 경고 메시지
warning_msg() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# 함수: 에러 메시지
error_msg() {
    echo -e "${RED}✗ $1${NC}"
}

# 함수: 도구 설치 여부 확인
check_tool() {
    if command -v "$1" &> /dev/null; then
        success_msg "$1 이미 설치됨"
        return 0
    else
        return 1
    fi
}

# root 권한 확인
if [[ $EUID -eq 0 ]]; then
   echo "이 스크립트는 root 권한으로 실행하지 마세요."
   echo "필요한 경우 sudo를 자동으로 사용합니다."
   exit 1
fi

echo "1. 시스템 패키지 업데이트 중..."
sudo apt update -qq

echo -e "\n2. Python 및 기본 도구 설치 중..."

# Python 3 및 pip 설치
if ! check_tool python3; then
    sudo apt install -y python3 python3-pip
    success_msg "Python3 설치 완료"
fi

if ! check_tool pip3; then
    sudo apt install -y python3-pip
    success_msg "pip3 설치 완료"
fi

echo -e "\n3. 보안 도구들 설치 중..."

# nmap 설치
if ! check_tool nmap; then
    sudo apt install -y nmap
    success_msg "nmap 설치 완료"
fi

# whatweb 설치
if ! check_tool whatweb; then
    sudo apt install -y whatweb
    success_msg "whatweb 설치 완료"
fi

# nikto 설치
if ! check_tool nikto; then
    sudo apt install -y nikto
    success_msg "nikto 설치 완료"
fi

# ffuf 설치 (최신 버전)
if ! check_tool ffuf; then
    echo "ffuf 설치 중..."
    # ffuf GitHub에서 최신 릴리즈 다운로드
    FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/
    sudo mv /tmp/ffuf /usr/local/bin/
    sudo chmod +x /usr/local/bin/ffuf
    rm /tmp/ffuf.tar.gz
    success_msg "ffuf 설치 완료"
fi

# searchsploit (exploitdb) 설치
if ! check_tool searchsploit; then
    sudo apt install -y exploitdb
    success_msg "searchsploit 설치 완료"
fi

# ssh-audit 설치
if ! check_tool ssh-audit; then
    sudo apt install -y ssh-audit
    success_msg "ssh-audit 설치 완료"
fi

# enum4linux 설치
if ! check_tool enum4linux; then
    sudo apt install -y enum4linux
    success_msg "enum4linux 설치 완료"
fi

echo -e "\n4. Python 라이브러리 설치 중..."

# Python 라이브러리들 설치 (requirements.txt 방식)
cat > requirements.txt << EOF
# Hacklipse OSINT 파이프라인 Python 의존성
asyncio>=3.4.3
subprocess32>=3.5.4
typing>=3.7.4
glob2>=0.7
datetime>=4.3
shutil>=1.0.0
EOF

pip3 install -r requirements.txt --user
success_msg "Python 라이브러리 설치 완료"

echo -e "\n5. SecLists 워드리스트 설치 (선택사항)..."
read -p "SecLists 워드리스트를 자동으로 설치하시겠습니까? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ ! -d "/usr/share/seclists" ] && [ ! -d "/opt/SecLists" ]; then
        echo "SecLists 다운로드 중..."
        cd /tmp
        git clone https://github.com/danielmiessler/SecLists.git
        sudo mv SecLists /opt/
        sudo chown -R $USER:$USER /opt/SecLists
        success_msg "SecLists 설치 완료: /opt/SecLists"
        echo "pipe.py 실행 시 다음과 같이 사용하세요:"
        echo "python3 pipe.py -t [대상] -w /opt/SecLists"
    else
        success_msg "SecLists 이미 설치됨"
    fi
else
    warning_msg "SecLists 설치 건너뜀 - 수동으로 설치 후 -w 옵션으로 경로 지정하세요"
fi

echo -e "\n6. 설치 확인 중..."

# 설치된 도구들 버전 확인
echo -e "\n설치된 도구 버전:"
echo "- Python: $(python3 --version)"
echo "- nmap: $(nmap --version | head -1)"
echo "- whatweb: $(whatweb --version 2>/dev/null | head -1 || echo 'whatweb installed')"
echo "- nikto: $(nikto -Version 2>/dev/null | head -1 || echo 'nikto installed')"
echo "- ffuf: $(ffuf -V 2>/dev/null || echo 'ffuf installed')"
echo "- searchsploit: $(searchsploit --version 2>/dev/null | head -1 || echo 'searchsploit installed')"
echo "- ssh-audit: $(ssh-audit --version 2>/dev/null | head -1 || echo 'ssh-audit installed')"
echo "- enum4linux: $(enum4linux -h 2>/dev/null | head -1 || echo 'enum4linux installed')"

# 임시 파일 정리
rm -f requirements.txt

echo -e "\n=================================="
success_msg "모든 의존성 설치 완료!"
echo "=================================="

echo -e "\n사용법:"
echo "python3 pipe.py -t [대상IP/도메인] -w [SecLists경로]"
echo ""
echo "예시:"
echo "sudo python3 pipe.py -t 192.168.1.100 -w /opt/SecLists"
echo "sudo python3 pipe.py -t example.com -w /usr/share/seclists"
echo ""
warning_msg "주의: pipe.py는 nmap의 SYN 스캔을 위해 sudo 권한이 필요합니다."