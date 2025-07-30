# OSINT 자동화 도구 - 한국어 주석 버전
# 이 스크립트는 AI 기반 자동 취약점 탐지 프레임워크를 위한 데이터 수집 파이프라인입니다.
# Hacklipse 팀의 연구과제용으로 개발되었습니다.

# 필수 라이브러리 임포트
import asyncio          # 비동기 처리를 위한 라이브러리
import subprocess       # 외부 명령어 실행을 위한 라이브러리
import json            # JSON 데이터 처리
import time            # 시간 관련 함수
import re              # 정규표현식 처리
import os              # 운영체제 인터페이스
import sys             # 시스템 관련 기능
from typing import Dict, List, Optional, Tuple  # 타입 힌팅
import glob, datetime, shutil  # 파일 패턴 매칭, 날짜/시간, 파일 조작

class OSINTStager:
    """OSINT(공개정보수집) 자동화 도구 메인 클래스
    
    이 클래스는 대상 시스템에 대한 정보를 자동으로 수집하고 분석합니다.
    nmap -> 전문도구들 순서로 2단계 파이프라인을 실행합니다.
    
    주요 기능:
    1. 1단계: nmap을 이용한 포트 스캔 및 서비스 탐지
    2. 2단계: 발견된 서비스별 전문 도구 병렬 실행
    3. 결과 통합 및 AI 학습용 데이터 형식으로 변환
    """
    
    def __init__(self, target: str, wordlist_path: str = None):
        """OSINTStager 초기화
        
        Args:
            target (str): 스캔할 대상 IP 주소 또는 도메인명
            wordlist_path (str): SecLists 워드리스트 경로 (옵션)
        """
        self.original_target = target     # 원본 대상 (사용자 입력)
        self.target_ip = None            # 대상의 실제 IP 주소
        self.target = self._process_target(target)  # 처리된 최종 대상 (도메인으로 변환 가능)
        self.nmap_results = None          # nmap 스캔 결과 저장
        self.discovered_ports = {}        # 발견된 포트와 서비스 정보 딕셔너리
        self.web_urls = []               # 발견된 웹 서비스 URL 리스트
        self.temp_files = []             # 생성된 임시 파일들 추적 (정리용)
        self.seclists_path = wordlist_path  # 사용자가 지정한 워드리스트 경로
        self.nmap_xml_file = None        # nmap XML 결과 파일 경로
        self.cve_results = []            # searchsploit으로 발견된 CVE 목록
        
    def _process_target(self, target: str) -> str:
        """대상 처리: IP인 경우 도메인으로 변환하고 /etc/hosts 업데이트
        
        Args:
            target (str): 원본 대상 (IP 또는 도메인)
            
        Returns:
            str: 처리된 대상 (항상 도메인 형태)
        """
        if self._is_ip_address(target):
            print(f"IP 주소 감지: {target}")
            self.target_ip = target
            # IP를 도메인으로 매핑
            domain_name = self._generate_domain_name(target)
            success = self._update_hosts_file(target, domain_name)
            if success:
                print(f"도메인 매핑 완료: {target} -> {domain_name}")
                return domain_name
            else:
                print(f"도메인 매핑 실패, 원본 IP 사용: {target}")
                return target
        else:
            print(f"도메인 감지: {target}")
            self.target_ip = target  # 도메인인 경우 target_ip도 동일하게 설정
            return target
    
    def _is_ip_address(self, target: str) -> bool:
        """IP 주소 여부 검사
        
        Args:
            target (str): 검사할 대상 문자열
            
        Returns:
            bool: IP 주소이면 True, 아니면 False
        """
        import re
        # IPv4 주소 패턴 (간단한 검증)
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, target):
            # 각 옥텟이 0-255 범위인지 검증
            octets = target.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False
    
    def _generate_domain_name(self, ip: str) -> str:
        """IP 주소를 기반으로 도메인명 생성
        
        Args:
            ip (str): IP 주소
            
        Returns:
            str: 생성된 도메인명
        """
        # IP 주소의 점을 하이픈으로 변경하여 도메인명 생성
        # 예: 192.168.1.100 -> target-192-168-1-100.local
        sanitized_ip = ip.replace('.', '-')
        return f"target-{sanitized_ip}.local"
    
    def _update_hosts_file(self, ip: str, domain: str) -> bool:
        """/etc/hosts 파일에 IP-도메인 매핑 추가
        
        Args:
            ip (str): IP 주소
            domain (str): 매핑할 도메인명
            
        Returns:
            bool: 성공하면 True, 실패하면 False
        """
        hosts_file = '/etc/hosts'
        mapping_line = f"{ip} {domain}"
        
        try:
            # 기존 매핑이 있는지 확인
            with open(hosts_file, 'r') as f:
                content = f.read()
                if mapping_line in content:
                    print(f"이미 매핑됨: {mapping_line}")
                    return True
                    
                # 같은 도메인의 다른 IP 매핑이 있는지 확인
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if domain in line and not line.strip().startswith('#'):
                        print(f"기존 매핑 발견, 교체: {line.strip()} -> {mapping_line}")
                        lines[i] = mapping_line
                        updated_content = '\n'.join(lines)
                        break
                else:
                    # 새로운 매핑 추가
                    updated_content = content.rstrip() + f"\n{mapping_line}\n"
            
            # /etc/hosts 파일 업데이트 (sudo 권한 필요)
            import subprocess
            echo_process = subprocess.Popen(['echo', updated_content], stdout=subprocess.PIPE)
            tee_process = subprocess.Popen(['sudo', 'tee', hosts_file], 
                                         stdin=echo_process.stdout, 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.PIPE)
            echo_process.stdout.close()
            _, stderr = tee_process.communicate()
            
            if tee_process.returncode == 0:
                print(f"/etc/hosts 업데이트 성공")
                return True
            else:
                print(f"/etc/hosts 업데이트 실패: {stderr.decode('utf-8', errors='ignore')}")
                return False
                
        except Exception as e:
            print(f"/etc/hosts 업데이트 중 오류: {e}")
            return False
        
    def validate_wordlist_path(self) -> bool:
        """사용자가 지정한 워드리스트 경로 유효성 검증
        
        Returns:
            bool: 워드리스트 경로가 유효하면 True, 아니면 False
        """
        if not self.seclists_path:
            print("워드리스트 경로가 지정되지 않았습니다. -w 옵션을 사용해주세요.")
            return False
            
        if not os.path.isdir(self.seclists_path):
            print(f"워드리스트 경로가 존재하지 않습니다: {self.seclists_path}")
            return False
            
        # SecLists의 핵심 디렉토리 존재 여부 검증
        if not os.path.exists(f"{self.seclists_path}/Discovery/Web-Content"):
            print(f"올바른 SecLists 디렉토리가 아닙니다: {self.seclists_path}")
            print("디렉토리 내에 'Discovery/Web-Content' 폴더가 있는지 확인해주세요.")
            return False
            
        print(f"SecLists 경로 확인됨: {self.seclists_path}")
        return True
        
    async def run_command(self, name: str, command: List[str], timeout: int = 300) -> Optional[str]:
        """비동기 방식으로 외부 명령어 실행
        
        Args:
            name (str): 명령어 이름 (로깅용)
            command (List[str]): 실행할 명령어와 인자들
            timeout (int): 최대 실행 시간 (초), 기본값 300초
            
        Returns:
            Optional[str]: 명령어 실행 결과 (성공시) 또는 None (실패시)
        """
        print(f"[{time.strftime('%H:%M:%S')}] {name} 시작...")  # 시작 시간 로깅
        
        try:
            # 비동기 프로세스 생성 및 실행
            process = await asyncio.create_subprocess_exec(
                *command,                        # 명령어와 인자들 언팩
                stdout=subprocess.PIPE,          # 표준 출력 캐치
                stderr=subprocess.PIPE           # 에러 출력 캐치
            )
            
            # 타임아웃과 함께 프로세스 완료 대기
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
            
            # 명령어 실행 결과에 따른 처리
            if process.returncode == 0:  # 성공 (return code 0)
                print(f"[{time.strftime('%H:%M:%S')}] {name} 완료")
                return stdout.decode('utf-8', errors='ignore')  # UTF-8 디코딩
            else:  # 실패 (return code != 0)
                error_msg = stderr.decode('utf-8', errors='ignore')
                print(f"[{time.strftime('%H:%M:%S')}] {name} 실패 (코드: {process.returncode})")
                print(f"   오류: {error_msg[:200]}...")  # 에러 메시지 일부만 표시
                return None
            
        except asyncio.TimeoutError:  # 타임아웃 발생
            print(f"[{time.strftime('%H:%M:%S')}] {name} 타임아웃 ({timeout}초)")
            return None
        except Exception as e:  # 기타 예외 발생
            print(f"[{time.strftime('%H:%M:%S')}] {name} 오류: {e}")
            return None
    
    async def stage1_nmap_discovery(self) -> str:
        """단계 1: nmap을 이용한 기본 네트워크 정보 수집
        
        이 단계에서는 대상 시스템의 열린 포트, 서비스 버전,
        기본적인 운영체제 정보 등을 수집합니다.
        
        Returns:
            str: nmap 스캔 결과 문자열
        """
        print("=" * 50)
        print("STAGE 1: 포트 및 서비스 탐지 (nmap)")
        print("=" * 50)
        
        # nmap 스캔 결과를 저장할 파일명 생성 (특수문자 치환)
        nmap_output_file = f'nmap_{self.target.replace(".", "_").replace(":", "_")}.txt'
        nmap_xml_file = f'nmap_{self.target.replace(".", "_").replace(":", "_")}.xml'
        self.nmap_xml_file = nmap_xml_file  # 인스턴스 변수에 저장
        self.temp_files.append(nmap_output_file)  # 나중에 정리할 파일 목록에 추가
        self.temp_files.append(nmap_xml_file)     # XML 파일도 정리 대상에 추가
        
        # 대상에 따른 nmap 스캔 옵션 설정
        if self.target in ['localhost', '127.0.0.1', '::1']:  # 로컬호스트 스캔
            command = [
                'sudo', 'nmap',           # root 권한 필요 (SYN 스캔용)
                '-sS',                    # SYN 스캔 (스텔스 스캔)
                '-sV',                    # 서비스 버전 탐지
                '-sC',                    # 기본 NSE 스크립트 실행
                '--script=banner,http-title',  # 배너 및 HTTP 제목 수집
                '-oN', nmap_output_file,  # 일반 형식으로 결과 저장
                '-oX', nmap_xml_file,     # XML 형식으로 결과 저장 (searchsploit용)
                self.target
            ]
        else:  # 원격 대상 스캔
            command = [
                'sudo', 'nmap', 
                '-sS', '-sV', '-sC',      # 기본 스캔 옵션
                '-O',                     # 운영체제 탐지
                '--script=banner,http-title,ssl-cert',  # SSL 인증서 정보 추가
                '-oN', nmap_output_file,
                '-oX', nmap_xml_file,     # XML 형식으로 결과 저장 (searchsploit용)
                self.target
            ]
        
        print(f"실행 명령어: {' '.join(command)}")  # 디버깅용 명령어 출력
        
        # nmap 스캔 실행 (3분 타임아웃)
        self.nmap_results = await self.run_command("nmap", command, timeout=180)
        
        if self.nmap_results:  # 스캔 성공
            print(f"nmap 스캔 성공 ({len(self.nmap_results)} bytes)")
            self._parse_nmap_results()      # 결과 파싱
            self._print_discovery_summary() # 요약 정보 출력
        else:  # 스캔 실패
            print("nmap 스캔 실패")
            print(f"   {' '.join(command)}")
        
        return self.nmap_results
    
    def _parse_nmap_results(self):
        """nmap 스캔 결과를 파싱하여 발견된 서비스 정보 정리
        
        nmap 출력에서 열린 포트, 서비스 이름, 버전 정보를 추출하고
        웹 서비스의 경우 URL을 생성합니다.
        """
        if not self.nmap_results:
            return
            
        # nmap 결과를 줄별로 분석하여 포트 정보 추출
        lines = self.nmap_results.split('\n')
        
        for line in lines:
            line = line.strip()
            # nmap 출력에서 포트 정보 라인 탐지
            # 예시: "8082/tcp open http Apache httpd 2.4.25"
            if '/tcp' in line and 'open' in line:
                parts = line.split()  # 공백으로 분할
                if len(parts) >= 3:
                    port_service = parts[0]  # "8082/tcp"
                    status = parts[1]        # "open"
                    service = parts[2] if len(parts) > 2 else "unknown"  # "http"
                    
                    # 정규표현식으로 포트 번호 추출
                    port_match = re.match(r'(\d+)/tcp', port_service)
                    if port_match and status == 'open':
                        port = port_match.group(1)  # 포트 번호
                        
                        # 서비스 버전 정보 추출 (4번째 이후 모든 부분)
                        version_parts = parts[3:] if len(parts) > 3 else []
                        version = ' '.join(version_parts) if version_parts else 'unknown'
                        
                        # 발견된 포트 정보를 딕셔너리에 저장
                        self.discovered_ports[port] = {
                            'service': service,   # 서비스 이름 (http, ssh, ftp 등)
                            'version': version    # 서비스 버전 정보
                        }
                        
                        # 웹 서비스인 경우 URL 생성 (나중에 웹 스캔에 사용)
                        if service in ['http', 'https', 'http-proxy', 'ssl/http']:
                            # SSL/HTTPS 여부 판단
                            protocol = 'https' if 'ssl' in service or service == 'https' else 'http'
                            # 기본 포트(80, 443)가 아닌 경우 포트 번호 포함
                            url = f"{protocol}://{self.target}:{port}" if port not in ['80', '443'] else f"{protocol}://{self.target}"
                            self.web_urls.append(url)  # 웹 URL 목록에 추가
        
        # 디버깅용 출력 - 파싱 결과 확인
        print(f"\n[DEBUG] 파싱된 포트 정보:")
        for port, info in self.discovered_ports.items():
            print(f"  포트 {port}: {info['service']} - {info['version']}")
        print()
    
    def _print_discovery_summary(self):
        """발견된 서비스들의 요약 정보를 사용자에게 출력"""
        print(f"\n발견된 서비스 ({len(self.discovered_ports)}개):")
        for port, info in self.discovered_ports.items():
            print(f"  - {port}/tcp: {info['service']} ({info['version']})")
        
        if self.web_urls:
            print(f"\n웹 서비스 ({len(self.web_urls)}개):")
            for url in self.web_urls:
                print(f"  - {url}")
    
    async def stage2_specialized_scans(self) -> Dict[str, str]:
        """단계 2: nmap 결과를 기반으로 보안 도구들을 병렬 실행
        
        1단계에서 발견된 서비스들을 분석하여 적절한 전문 도구들을 선택하고
        비동기적으로 병렬 실행하여 상세한 취약점 정보를 수집합니다.
        
        Returns:
            Dict[str, str]: 각 도구별 실행 결과를 담은 딕셔너리
        """
        print("\n" + "=" * 50)
        print("STAGE 2: 전문 도구 실행 (병렬 처리)")
        print("=" * 50)
        
        tasks = []       # 비동기 작업 리스트
        task_names = []  # 작업 이름 리스트 (결과 매칭용)
        
        # 웹 서비스 발견 시 웹 전용 보안 도구들 실행
        if self.web_urls:
            print("웹 서비스 탐지 - 웹 전용 스캐너들 병렬 실행")
            
            for url in self.web_urls:
                # ffuf - 디렉토리/파일 브루트포싱 (숨겨진 경로 탐지)
                tasks.append(self.run_ffuf(url))
                task_names.append(f"ffuf_{url}")
                
                # whatweb - 웹 기술 스택 분석 (사용 기술 식별)
                tasks.append(self.run_whatweb(url))
                task_names.append(f"whatweb_{url}")
                
                # nikto - 웹 취약점 스캔 (일반적인 웹 취약점 탐지)
                tasks.append(self.run_nikto(url))
                task_names.append(f"nikto_{url}")

        
        # SSH 서비스 발견 시 SSH 전용 보안 감사 도구 실행
        if self.has_service('ssh'):
            print("SSH 서비스 탐지 - SSH 보안 감사 실행")
            tasks.append(self.run_ssh_audit())  # SSH 설정 및 취약점 분석
            task_names.append("ssh_audit")
        
        # SMB/NetBIOS 서비스 발견 시 윈도우 네트워크 열거 도구 실행
        if self.has_service('microsoft-ds') or self.has_service('netbios-ssn'):
            print("SMB 서비스 탐지 - 윈도우 네트욬크 열거 실행")
            tasks.append(self.run_enum4linux())  # SMB 공유, 사용자 정보 등 열거
            task_names.append("enum4linux")
        
        # nmap 결과가 있으면 searchsploit으로 CVE 검색 실행
        if self.discovered_ports:
            print("서비스 발견 - searchsploit CVE 검색 실행")
            tasks.append(self.run_searchsploit())  # 알려진 취약점 검색
            task_names.append("searchsploit")
        
        # 실행할 도구가 없는 경우 처리
        if not tasks:
            print("실행할 전문 도구가 없습니다. (웹/SSH/SMB 서비스 미발견)")
            return {}
        
        print(f"총 {len(tasks)}개 도구를 병렬 실행합니다... (성능 최적화)")
        # asyncio.gather로 모든 작업을 병렬 실행 (예외 발생 시에도 계속 진행)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 각 도구별 실행 결과 정리 및 에러 처리
        final_results = {}
        for i, (task_name, result) in enumerate(zip(task_names, results)):
            if isinstance(result, Exception):  # 예외 발생한 작업 처리
                print(f"{task_name} 실행 중 오류: {result}")
                final_results[task_name] = None
            else:  # 정상 완료된 작업
                final_results[task_name] = result
        
        return final_results
    
    def has_service(self, service_name: str) -> bool:
        """발견된 포트 중에서 특정 서비스가 실행 중인지 확인
        
        Args:
            service_name (str): 찾을 서비스 이름 (예: 'ssh', 'http', 'microsoft-ds')
            
        Returns:
            bool: 해당 서비스가 발견되면 True, 없으면 False
        """
        for port_info in self.discovered_ports.values():
            # 대소문자 구분 없이 서비스 이름 비교
            if service_name.lower() in port_info['service'].lower():
                return True
        return False
    
    # === 개별 보안 도구 실행 함수들 ===
    # 각 도구는 특정 서비스에 특화된 전문 스캐닝을 수행합니다.
    
    async def run_ffuf(self, url: str) -> str:
        """ffuf를 이용한 전문 웹 디렉토리/파일 브루트포싱 (5단계 전략)
        
        이 함수는 웹 서버에서 숨겨진 디렉토리와 파일들을 찾기 위해
        5단계에 걸쳐 다양한 워드리스트와 패턴을 사용합니다.
        
        단계별 전략:
        1. 디렉토리 퍼징 (recursion 사용)
        2. 일반 파일 퍼징
        3. 확장자 퍼징
        4. API 엔드포인트 퍼징
        5. 백업/설정 파일 퍼징
        
        Args:
            url (str): 스캔할 웹 서비스 URL
            
        Returns:
            str: 전체 6단계 스캔 결과를 JSON 형식으로 집계
        """
        print(f"[{time.strftime('%H:%M:%S')}] ffuf 6단계 전문 스캔 시작 ({url})")
        
        # SecLists 경로 설정
        seclists_path = self.seclists_path
        
        # URL에서 프로토콜 제거하여 호스트명만 추출 (스크립트 사용용)
        target_host = url.replace('http://', '').replace('https://', '')
        
        # 다단계 ffuf 스캔을 수행할 Bash 스크립트 동적 생성
        # 이 스크립트는 6가지 다른 전략으로 ffuf를 실행합니다.
        script_content = f'''#!/bin/bash
TARGET="{target_host}"  # 스캔 대상 호스트
OUTPUT_DIR="ffuf_results_{self.target.replace('.', '_').replace(':', '_')}"  # 결과 저장 디렉토리
SEC_PATH="{seclists_path}"  # SecLists 워드리스트 경로
mkdir -p "$OUTPUT_DIR"  # 결과 디렉토리 생성


# 디렉토리 퍼징
echo "디렉토리 퍼징 시작..."
if [ -f "$SEC_PATH/Discovery/Web-Content/raft-medium-directories.txt" ]; then
    ffuf \\
        -w "$SEC_PATH/Discovery/Web-Content/raft-medium-directories.txt" \\
        -u "{url}/FUZZ" \\
        -mc 200,204,301,302,307,401,403 \\
        -fc 404,500 \\
        -fs 0 \\
        -t 50 \\
        -o "$OUTPUT_DIR/01_directories.json" -of json \\
        -v
else
    echo "경고: raft-medium-directories.txt 파일을 찾을 수 없습니다."
    touch "$OUTPUT_DIR/01_directories.json"
fi

# 일반 파일 퍼징
echo "일반 파일 퍼징 시작..."
if [ -f "$SEC_PATH/Discovery/Web-Content/raft-medium-files.txt" ]; then
    ffuf \\
        -w "$SEC_PATH/Discovery/Web-Content/raft-medium-files.txt" \\
        -u "{url}/FUZZ" \\
        -mc 200,204,301,302,307,401,403 \\
        -fc 404,500 \\
        -fs 0 \\
        -t 80 \\
        -o "$OUTPUT_DIR/02_files.json" -of json \\
        -v
else
    echo "경고: raft-medium-files.txt 파일을 찾을 수 없습니다."
    touch "$OUTPUT_DIR/02_files.json"
fi


# 확장자 퍼징 (일반 파일명 + 다양한 확장자)
echo "확장자 퍼징 시작..."
if [ -f "$SEC_PATH/Discovery/Web-Content/common.txt" ]; then
    ffuf \\
        -w "$SEC_PATH/Discovery/Web-Content/common.txt" \\
        -u "{url}/FUZZ" \\
        -e .php,.html,.htm,.js,.txt,.xml,.json,.log,.bak,.backup,.old,.tmp,.sql,.conf,.config,.ini,.env,.yml,.yaml \\
        -mc 200,204,301,302,307,401,403 \\
        -fc 404,500 \\
        -fs 0 \\
        -t 80 \\
        -o "$OUTPUT_DIR/03_extensions.json" -of json \\
        -v
else
    echo "경고: common.txt 파일을 찾을 수 없습니다."
    touch "$OUTPUT_DIR/03_extensions.json"
fi

# 히든 파일 & 백업 파일 퍼징
echo "히든 파일 & 백업 파일 퍼징 시작..."
if [ -f "$SEC_PATH/Discovery/Web-Content/quickhits.txt" ]; then
    ffuf \\
        -w "$SEC_PATH/Discovery/Web-Content/quickhits.txt" \\
        -u "{url}/FUZZ" \\
        -mc 200,204,301,302,307,401,403 \\
        -fc 404,500 \\
        -fs 0 \\
        -t 60 \\
        -o "$OUTPUT_DIR/04_hidden.json" -of json \\
        -v
else
    echo "경고: quickhits.txt 파일을 찾을 수 없습니다."
    touch "$OUTPUT_DIR/04_hidden.json"
fi

# 서브도메인 퍼징
ffuf \\
    -w "$SEC_PATH/Discovery/DNS/subdomains-top1million-5000.txt" \\
    -u "http://FUZZ.{self.target}" \\
    -H "Host: FUZZ.{self.target}" \\
    -mc 200,204,301,302,307,401,403 \\  # 성공/리다이렉트/인증 코드 매치
    -fc 404,500 \\             # 오류 코드 필터링
    -fs 0 \\                   # 크기 0인 응답 필터링 (일반적으로 빈 응답)
    -t 50 \\                   # 동시 스레드 수 (속도 vs 안정성 균형)
    -o "$OUTPUT_DIR/05_subdomains.json" -of json \\  # JSON 형식으로 결과 저장

# Vhost 퍼징
ffuf \\
    -w "$SEC_PATH/Discovery/DNS/subdomains-top1million-5000.txt" \\
    -u "https://{self.target}" \\
    -H "Host: FUZZ.{self.target}" \\
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \\
    -mc 200,204,301,302,307,401,403 \\  # 성공/리다이렉트/인증 코드 매치
    -fc 404,500 \\             # 오류 코드 필터링
    -t 100 \\                   # 동시 스레드 수
    -ac \\                     # 자동 칼리브레이션 (기본 응답 자동 필터링)
    -o "$OUTPUT_DIR/06_vhosts.json" -of json \\  # JSON 형식으로 결과 저장
'''
        
        # 임시 스크립트 파일 생성 (실행 후 정리됨)
        script_path = f"/tmp/ffuf_scan_{self.target.replace('.', '_').replace(':', '_')}_{int(time.time())}.sh"
        self.temp_files.append(script_path)
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # 스크립트 실행 권한 부여 및 실행
        import os
        os.chmod(script_path, 0o755)
        
        try:
            # 30분 타임아웃으로 전체 ffuf 스캔 실행
            result = await self.run_command(f"ffuf 전문스캔 ({url})", ['bash', script_path], timeout=1800)
            
            # 각 단계별 결과 파일들을 읽어서 통합
            results_dir = f"ffuf_results_{self.target.replace('.', '_').replace(':', '_')}"
            self.temp_files.append(results_dir)  # 디렉토리도 정리 대상에 추가
            
            # 6단계 결과를 하나의 딕셔너리로 통합
            combined_results = {
                "directories": self._read_ffuf_result(f"{results_dir}/01_directories.json"),
                "files": self._read_ffuf_result(f"{results_dir}/02_files.json"), 
                "extensions": self._read_ffuf_result(f"{results_dir}/03_extensions.json"),
                "hidden": self._read_ffuf_result(f"{results_dir}/04_hidden.json"),
                "subdomains": self._read_ffuf_result(f"{results_dir}/05_subdomains.json"),
                "vhosts": self._read_ffuf_result(f"{results_dir}/06_vhosts.json")
            }
            
            return json.dumps(combined_results, indent=2)
            
        except Exception as e:
            print(f"ffuf 전문스캔 오류: {e}")
            return None
    
    def _read_ffuf_result(self, filepath: str) -> dict:
        """ffuf JSON 결과 파일 읽기 (에러 처리 포함)"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return {"error": f"Could not read {filepath}"}
    
    async def run_whatweb(self, url: str) -> str:
        """whatweb을 이용한 웹 기술 스택 분석
        
        웹 애플리케이션에서 사용된 기술들을 식별합니다.
        (웹 서버, 프레임워크, CMS, 라이브러리, 플러그인 등)
        """
        command = [
            'whatweb', 
            '--no-errors',           # 에러 출력 억제
            '--colour=never',        # 색상 완전 비활성화
            '-a', '3',               # 공격성 레벨 3 (상세 분석)
            '-v',                    # 상세 출력
            url
        ]
        return await self.run_command(f"whatweb ({url})", command, timeout=60)
    
    async def run_nikto(self, url: str) -> str:
        """nikto를 이용한 웹 취약점 스캔
        
        일반적인 웹 애플리케이션 취약점들을 탐지합니다.
        (구식 버전, 설정 오류, 위험한 파일/스크립트 등)
        """
        command = [
            'nikto', 
            '-h', url,                                              # 대상 호스트
            '-output', f'nikto_{self.target.replace(".", "_")}.txt' # 결과 파일 저장
        ]
        return await self.run_command(f"nikto ({url})", command, timeout=600)  # 10분 타임아웃
    
    
    async def run_ssh_audit(self) -> str:
        """ssh-audit을 이용한 SSH 서비스 보안 감사
        
        SSH 서버의 보안 구성을 분석합니다.
        (암호화 알고리즘, 키 교환 방식, 보안 설정 등)
        """
        command = ['ssh-audit', self.target]
        return await self.run_command("ssh-audit", command, timeout=30)
    
    async def run_enum4linux(self) -> str:
        """enum4linux를 이용한 SMB 서비스 열거
        
        윈도우/삼바 시스템의 네트워크 정보를 열거합니다.
        (공유 폴더, 사용자 계정, 그룹 정보 등)
        """
        command = ['enum4linux', '-a', self.target]  # 모든 정보 열거
        return await self.run_command("enum4linux", command, timeout=120)
    
    async def run_searchsploit(self) -> str:
        """searchsploit을 이용한 nmap XML 결과 기반 CVE 검색
        
        nmap XML 결과에서 발견된 서비스 및 버전 정보를 기반으로
        알려진 취약점과 CVE를 자동으로 검색합니다.
        
        Returns:
            str: searchsploit 검색 결과
        """
        if not self.nmap_xml_file or not os.path.exists(self.nmap_xml_file):
            print("nmap XML 파일을 찾을 수 없어 searchsploit 실행을 건너뜁니다.")
            return "nmap XML file not found - searchsploit skipped"
        
        print(f"[{time.strftime('%H:%M:%S')}] searchsploit CVE 검색 시작...")
        
        # searchsploit에 nmap XML 파일을 직접 전달
        command = ['searchsploit', '--nmap', self.nmap_xml_file]
        
        result = await self.run_command("searchsploit", command, timeout=60)
        
        if result:
            # CVE 정보 추출 및 저장
            self._parse_cve_results(result)
            print(f"searchsploit 완료 - {len(self.cve_results)}개 CVE 발견")
        
        return result
    
    def _parse_cve_results(self, searchsploit_output: str):
        """핵심 searchsploit 출력에서 CVE 정보 추출
        
        Args:
            searchsploit_output (str): searchsploit 원본 출력
        """
        if not searchsploit_output:
            return
            
        lines = searchsploit_output.split('\n')
        
        for line in lines:
            line = line.strip()
            # CVE 패턴 찾기 (CVE-YYYY-NNNNN 형식)
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', line)
            
            for cve in cve_matches:
                if cve not in [item['cve'] for item in self.cve_results]:
                    # 취약점 제목도 추출 (라인에서 CVE 전 부분)
                    title_part = line.split(cve)[0].strip()
                    if '|' in title_part:
                        title = title_part.split('|')[-1].strip()
                    else:
                        title = title_part
                    
                    self.cve_results.append({
                        'cve': cve,
                        'title': title[:100] if title else 'Unknown',  # 제목 길이 제한
                        'line': line[:200]  # 전체 라인 저장 (길이 제한)
                    })
        
        print(f"[DEBUG] 추출된 CVE: {[item['cve'] for item in self.cve_results]}")


    def cleanup_temp_files(self):
        """스캔 과정에서 생성된 모든 임시 파일들을 정리
        
        디스크 공간 절약과 보안을 위해 스캔 후 임시 파일들을 삭제합니다.
        """
        print(f"\n임시 파일 정리 중...")
        cleaned_count = 0
        
        # 추적된 임시 파일들 삭제
        for temp_item in self.temp_files:
            try:
                if os.path.isfile(temp_item):          # 일반 파일인 경우
                    os.remove(temp_item)
                    print(f"   삭제: {temp_item}")
                    cleaned_count += 1
                elif os.path.isdir(temp_item):         # 디렉토리인 경우
                    shutil.rmtree(temp_item)
                    print(f"   삭제: {temp_item}/ (디렉토리)")
                    cleaned_count += 1
            except Exception as e:
                print(f"   삭제 실패: {temp_item} - {e}")
        
        # 패턴으로 생성된 추가 파일들도 정리
        patterns = [
            f"ffuf_results_{self.target.replace('.', '_').replace(':', '_')}*",
            f"nmap_{self.target.replace('.', '_').replace(':', '_')}*",
            f"nikto_{self.target.replace('.', '_').replace(':', '_')}*",
            f"searchsploit_{self.target.replace('.', '_').replace(':', '_')}*"
        ]
        
        for pattern in patterns:
            for file_path in glob.glob(pattern):
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        print(f"   삭제: {file_path}")
                        cleaned_count += 1
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        print(f"   삭제: {file_path}/ (디렉토리)")
                        cleaned_count += 1
                except Exception as e:
                    print(f"삭제 실패: {file_path} - {e}")
        
        print(f"총 {cleaned_count}개 파일/디렉토리 정리 완료")
    
    def generate_natural_language_context(self, results: Dict) -> str:
        """OSINT 수집 결과를 AI 학습용 자연어 형식으로 변환
        
        수집된 모든 정보를 LLM이 분석하기 쉬운 구조화된 텍스트로 변환합니다.
        이는 AI 모델이 공격 시나리오를 분석하고 취약점을 평가하는데 사용됩니다.
        """
        print("\nLLM 분석용 정보 정리 중...")
        
        sections = []
        
        # 보고서 헤더 생성
        timestamp = datetime.datetime.now().strftime("%Y년 %m월 %d일 %H:%M")
        sections.append(f"""# 보안 정찰 정보 보고서

**대상**: {results['target']}
**스캔 일시**: {timestamp}  
**실행 시간**: {results['execution_time']}

다음은 {results['target']}에 대한 OSINT 수집 결과입니다. 이 정보를 바탕으로 공격 시나리오를 분석해주세요.""")

        # 포트 스캔 결과 섹션
        sections.append("## 포트 스캔 결과 (nmap)")
        if results['discovered_ports']:
            sections.append(f"총 {len(results['discovered_ports'])}개 포트가 열려있음:")
            for port, info in results['discovered_ports'].items():
                sections.append(f"- **포트 {port}**: {info['service']} ({info['version']})")
        
        # 웹 서비스 정보 섹션
        if results['web_urls']:
            sections.append(f"\n## 웹 서비스 응답")
            sections.append(f"HTTP/HTTPS 서비스 {len(results['web_urls'])}개 발견:")
            for url in results['web_urls']:
                sections.append(f"- {url}")

        # WhatWeb 기술 스택 분석 결과
        for key, value in results['specialized_scans'].items():
            if 'whatweb' in key and value:
                url = key.replace('whatweb_', '')
                sections.append(f"\n### {url} 기술 스택 정보")
                
                # ANSI 색상 코드 완전 제거
                clean_value = self._clean_ansi_codes(value)
                
                # WhatWeb 결과에서 핵심 정보만 추출
                if 'Summary' in clean_value:
                    summary_start = clean_value.find('Summary   :')
                    if summary_start != -1:
                        summary_end = clean_value.find('\n\n', summary_start)
                        summary = clean_value[summary_start:summary_end] if summary_end != -1 else clean_value[summary_start:summary_start+300]
                        clean_summary = summary.replace('Summary   :', '').strip()
                        # 추가 정리
                        clean_summary = re.sub(r'\s+', ' ', clean_summary)  # 연속 공백 제거
                        sections.append(f"기술 스택: {clean_summary}")
                
                # HTTP 헤더 정보 (더 깔끔하게)
                if 'HTTP Headers:' in clean_value:
                    header_start = clean_value.find('HTTP Headers:')
                    header_end = clean_value.find('\n\n', header_start)
                    if header_end != -1:
                        header_section = clean_value[header_start:header_end]
                        # 불필요한 탭 제거하고 정리
                        clean_headers = '\n'.join([line.strip() for line in header_section.split('\n') if line.strip()])
                        sections.append(f"HTTP 헤더:\n{clean_headers}")

        # Nikto 웹 취약점 스캔 결과
        for key, value in results['specialized_scans'].items():
            if 'nikto' in key and value:
                url = key.replace('nikto_', '')
                sections.append(f"\n### {url} 취약점 스캔 결과 (Nikto)")
                
                # Nikto 결과를 라인별로 분석해서 핵심 정보만
                lines = value.split('\n')
                findings = []
                for line in lines:
                    line = line.strip()
                    if line.startswith('+') and any(keyword in line for keyword in 
                        ['OSVDB', 'header', 'found', 'redirects', 'leaks', 'reveals']):
                        findings.append(line)
                
                if findings:
                    sections.append("발견된 취약점들:")
                    for finding in findings[:10]:  # 상위 10개만
                        sections.append(f"  {finding}")

        # nmap 스크립트 상세 결과
        if results.get('nmap_output'):
            sections.append("\n## 추가 서비스 정보 (nmap scripts)")
            nmap_lines = results['nmap_output'].split('\n')
            script_results = []
            
            for line in nmap_lines:
                # nmap 스크립트 결과나 배너 정보 추출
                if any(keyword in line for keyword in ['http-title:', '|_http', 'Service Info:', '| http']):
                    script_results.append(line.strip())
            
            if script_results:
                sections.append("서비스 상세 정보:")
                for result in script_results[:15]:  # 상위 15개만
                    sections.append(f"  {result}")

        # ffuf 디렉토리/파일 탐색 결과
        for key, value in results['specialized_scans'].items():
            if 'ffuf' in key and value:
                actual_url = key.replace('ffuf_', '')  # 실제 스캔한 URL
                sections.append(f"\n### {actual_url} 웹 취약점 탐색 (ffuf)")
                
                try:
                    ffuf_data = json.loads(value) if isinstance(value, str) else value
                    
                    # 일반 웹 경로 결과 (디렉토리, 파일, 확장자, 히든파일)
                    web_paths = []
                    web_categories = ['directories', 'files', 'extensions', 'hidden']
                    
                    for category in web_categories:
                        if category in ffuf_data and isinstance(ffuf_data[category], dict) and 'results' in ffuf_data[category]:
                            for result in ffuf_data[category]['results'][:3]:  # 각 카테고리당 3개만
                                if 'url' in result:
                                    web_paths.append(f"{result['url']} (상태: {result.get('status', '?')}, 유형: {category})")
                    
                    if web_paths:
                        sections.append("발견된 웹 경로:")
                        for path in list(set(web_paths))[:8]:  # 중복 제거 + 최대 8개
                            sections.append(f"  {path}")
                    
                    # 서브도메인 결과 별도 처리
                    if 'subdomains' in ffuf_data and isinstance(ffuf_data['subdomains'], dict) and 'results' in ffuf_data['subdomains']:
                        subdomain_results = ffuf_data['subdomains']['results'][:5]  # 상위 5개
                        if subdomain_results:
                            sections.append("\n발견된 서브도메인:")
                            for result in subdomain_results:
                                if 'url' in result:
                                    sections.append(f"  {result['url']} (상태: {result.get('status', '?')})")
                    
                    # VHost 결과 별도 처리
                    if 'vhosts' in ffuf_data and isinstance(ffuf_data['vhosts'], dict) and 'results' in ffuf_data['vhosts']:
                        vhost_results = ffuf_data['vhosts']['results'][:5]  # 상위 5개
                        if vhost_results:
                            sections.append("\n발견된 가상 호스트 (VHost):")
                            for result in vhost_results:
                                if 'url' in result:
                                    sections.append(f"  {result['url']} (상태: {result.get('status', '?')})")
                    
                    # 아무것도 찾지 못한 경우
                    if not web_paths and not (ffuf_data.get('subdomains', {}).get('results')) and not (ffuf_data.get('vhosts', {}).get('results')):
                        sections.append("특별한 경로나 서브도메인 발견되지 않음")
                        
                except Exception as e:
                    sections.append(f"ffuf 결과 파싱 중 오류: {e}")

        # CVE 취약점 정보 섹션 (새로 추가)
        if self.cve_results:
            sections.append(f"\n## 발견된 취약점 (CVE)")
            sections.append(f"searchsploit으로 {len(self.cve_results)}개의 알려진 취약점을 발견했습니다:")
            
            # CVE 중요도에 따른 정렬 (연도 역순으로)
            sorted_cves = sorted(self.cve_results, key=lambda x: x['cve'], reverse=True)
            
            for i, cve_info in enumerate(sorted_cves[:10]):  # 상위 10개만 표시
                sections.append(f"\n### {i+1}. {cve_info['cve']}")
                sections.append(f"**제목**: {cve_info['title']}")
                sections.append(f"**세부사항**: {cve_info['line']}")
                
                # CVE 연도 추출 및 위험도 평가
                year = cve_info['cve'].split('-')[1] if '-' in cve_info['cve'] else '????'
                current_year = datetime.datetime.now().year
                age = current_year - int(year) if year.isdigit() else 0
                
                if age <= 2:
                    risk_level = "🔴 높음 (최신 취약점)"
                elif age <= 5:
                    risk_level = "🟡 중간 (비교적 최신)"
                else:
                    risk_level = "🟢 낮음 (거비 취약점)"
                
                sections.append(f"**위헙도**: {risk_level} ({year}년, {age}년 전)")
            
            if len(self.cve_results) > 10:
                sections.append(f"\n*총 {len(self.cve_results)}개 취약점 중 상위 10개만 표시*")
        else:
            sections.append("\n## CVE 취약점 검색 결과")
            sections.append("알려진 CVE 취약점이 발견되지 않았습니다.")
        
        # 시스템 환경 분석 
        sections.append("\n## 시스템 환경 정보")
        
        port_info = []
        if any(port in ['8080', '8081', '8082', '8083', '8084'] for port in results['discovered_ports'].keys()):
            port_info.append("비표준 포트(8000번대) 사용 확인")
        
        db_ports = [port for port, info in results['discovered_ports'].items() 
                   if info['service'] in ['postgresql', 'mysql', 'mongodb']]
        if db_ports:
            port_info.append(f"데이터베이스 포트 외부 노출: {', '.join(db_ports)}")
        
        tcpwrapped_count = len([p for p in results['discovered_ports'].values() 
                               if p['service'] == 'tcpwrapped'])
        if tcpwrapped_count > 0:
            port_info.append(f"접근 제어된 서비스 {tcpwrapped_count}개 확인")
        
        for info in port_info:
            sections.append(f"- {info}")

        # AI 분석 요청 섹션 (CVE 정보 반영)
        cve_mention = ""
        if self.cve_results:
            high_risk_cves = [cve for cve in self.cve_results if int(cve['cve'].split('-')[1]) >= datetime.datetime.now().year - 2]
            cve_mention = f"\n\n특히 {len(self.cve_results)}개의 알려진 CVE 취약점이 발견되었으며, 이 중 {len(high_risk_cves)}개는 최신 취약점입니다. 이러한 CVE 정보를 활용한 공격 시나리오를 우선적으로 고려해주세요."
        
        sections.append(f"""\n## AI 분석 요청

위의 수집된 정보를 바탕으로 다음을 분석해주세요:

1. **공격 가능성이 높은 진입점** 식별
2. **CVE 기반 우선 공격 벡터** 도출
3. **단계별 공격 시나리오** 수립  
4. **취약점들을 연계한 공격 체인** 구성
5. **각 공격 경로의 성공 가능성** 평가
6. **공격자 관점에서의 우선순위** 제시{cve_mention}

특히 발견된 웹 서비스들과 데이터베이스 노출 상황을 고려하여 실제 공격에서 어떤 순서로 접근할지 구체적인 시나리오를 제시해주세요.""")
        
        return "\n\n".join(sections)
    
    def _clean_ansi_codes(self, text: str) -> str:
        """터미널 출력에서 ANSI 색상 코드와 특수 문자 제거
        
        도구들의 출력에 포함된 색상 코드를 제거하여 깔끔한 텍스트로 만듭니다.
        """
        if not text:
            return ""
        
        # ANSI 색상 코드 제거 (모든 패턴)
        text = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', text)
        text = re.sub(r'\x1b\[[0-9;]*m', '', text)
        text = re.sub(r'\[1m', '', text)
        text = re.sub(r'\[0m', '', text)
        text = re.sub(r'\[\d+m', '', text)
        text = re.sub(r'\[\d+;\d+m', '', text)
        text = re.sub(r'\[[\d;]*m', '', text)
        
        # 기타 특수 문자 정리
        text = re.sub(r'\[\d+\]', '', text)  # [32], [0] 같은 것들
        text = re.sub(r'\[{2,}', '[', text)  # [[[ → [
        text = re.sub(r'\]{2,}', ']', text)  # ]]] → ]
        
        return text.strip()
    
    async def execute_full_pipeline(self) -> Dict[str, any]:
        """전체 OSINT 파이프라인 실행 (메인 함수)
        
        1단계와 2단계를 순차적으로 실행하고 결과를 통합합니다.
        최종적으로 AI 학습용 형태로 데이터를 구조화합니다.
        
        Returns:
            Dict: 전체 스캔 결과와 분석 정보를 포함한 딕셔너리
        """
        start_time = time.time()
        
        print("OSINT 자동화 파이프라인 시작")
        print("=" * 60)
        
        # 사전 준비: 워드리스트 경로 검증
        if not self.validate_wordlist_path():
            return {"error": "Invalid wordlist path"}
        
        # 1단계: nmap 포트 스캔 및 서비스 탐지
        nmap_result = await self.stage1_nmap_discovery()
        
        if not nmap_result:
            print("nmap 실행 실패 - 파이프라인 중단")
            return {"error": "nmap failed"}
        
        # 1단계와 2단계 사이 잠시 대기 (시스템 안정화)
        await asyncio.sleep(1)
        
        # 2단계: 발견된 서비스별 전문 도구들 병렬 실행
        specialized_results = await self.stage2_specialized_scans()
        
        total_time = time.time() - start_time
        
        # 최종 결과 구조화
        final_results = {
            'target': self.target,                        # 스캔 대상
            'execution_time': f"{total_time:.2f}초",      # 전체 실행 시간
            'discovered_ports': self.discovered_ports,    # 발견된 포트/서비스
            'web_urls': self.web_urls,                   # 웹 서비스 URL들
            'nmap_output': nmap_result,                  # nmap 원본 출력
            'specialized_scans': specialized_results,     # 전문 도구 결과들
            'cve_vulnerabilities': self.cve_results       # CVE 취약점 목록
        }
        
        print(f"\n전체 파이프라인 완료: {total_time:.2f}초")
        
        # AI 학습용 자연어 형태로 변환
        natural_context = self.generate_natural_language_context(final_results)
        final_results['natural_language_context'] = natural_context
        
        return final_results

# === 메인 실행 부분 ===

async def main():
    """명령줄 인터페이스 및 메인 실행 로직"""
    import argparse
    
    # 명령줄 인자 파싱 설정
    parser = argparse.ArgumentParser(
        description='OSINT 자동화 도구 - AI 학습용 데이터 수집 파이프라인',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 pipe.py -t 192.168.1.100
  python3 pipe.py --target localhost --output ./results
  python3 pipe.py -t example.com --verbose
        """
    )
    
    parser.add_argument(
        '-t', '--target', 
        required=True,
        help='스캔할 대상 IP 또는 도메인 (예: 192.168.1.100, localhost)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='./',
        help='결과 파일 저장 경로 (기본값: 현재 디렉토리)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='상세한 진행상황 출력'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='각 도구의 최대 실행 시간(초) (기본값: 300)'
    )
    
    parser.add_argument(
        '-w', '--wordlist-path',
        help='SecLists 워드리스트 경로 (예: /usr/share/seclists)'
    )
    
    args = parser.parse_args()
    
    # 입력 검증
    target = args.target.strip()
    if not target:
        print("오류: 대상을 입력해주세요.")
        return
    
    print(f"대상: {target}")
    if args.verbose:
        print(f"출력 경로: {args.output}")
        print(f"타임아웃: {args.timeout}초")
    
    # OSINT 스캐너 인스턴스 생성 및 실행
    scanner = OSINTStager(target, args.wordlist_path)
    
    try:
        # 전체 파이프라인 실행
        results = await scanner.execute_full_pipeline()
        
        # 결과 파일 저장
        import os
        os.makedirs(args.output, exist_ok=True)
        
        # JSON 결과 파일 저장
        output_file = os.path.join(
            args.output, 
            f"osint_results_{target.replace('.', '_')}_{int(time.time())}.json"
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n결과가 {output_file}에 저장되었습니다.")
        
        # 자연어 보고서 저장 (AI 학습용)
        if 'natural_language_context' in results:
            report_file = os.path.join(
                args.output,
                f"security_report_{target.replace('.', '_')}_{int(time.time())}.md"
            )
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(results['natural_language_context'])
            print(f"자연어 보고서가 {report_file}에 저장되었습니다.")
        
        # 실행 결과 요약 출력
        print("\n" + "="*50)
        print("실행 요약")
        print("="*50)
        print(f"대상: {results['target']}")
        print(f"실행 시간: {results['execution_time']}")
        print(f"발견된 포트: {len(results['discovered_ports'])}개")
        print(f"웹 서비스: {len(results['web_urls'])}개")
        print(f"전문 스캔: {len(results['specialized_scans'])}개")
        
        if args.verbose and results['discovered_ports']:
            print("\n발견된 서비스 상세:")
            for port, info in results['discovered_ports'].items():
                print(f"   {port}/tcp: {info['service']} ({info['version']})")
        
    finally:
        # 항상 임시 파일 정리 (보안과 디스크 공간을 위해)
        scanner.cleanup_temp_files()

def print_banner():
    """Hacklipse OSINT 파이프라인 시작 배너 출력"""
    banner = r"""
    __  _____   ________ __ __    ________  _____ ______
   / / / /   | / ____/ //_// /   /  _/ __ \/ ___// ____/
  / /_/ / /| |/ /   / ,<  / /    / // /_/ /\__ \/ __/   
 / __  / ___ / /___/ /| |/ /____/ // ____/___/ / /___   
/_/ /_/_/  |_\____/_/ |_/_____/___/_/    /____/_____/   
                                                        
  ___  ___ ___ _  _ _____   ___ _           _ _          
 / _ \/ __|_ _| \| |_   _| | _ (_)_ __  ___| (_)_ _  ___ 
| (_) \__ \| || .` | | |   |  _/ | '_ \/ -_) | | ' \/ -_)
 \___/|___/___|_|\_| |_|   |_| |_| .__/\___|_|_|_||_\___|
                                 |_|                     
"""
    
    print(banner)
    print("2025 인공지능빅데이터센터 연구과제")
    print("방어적 보안 연구용 - 로컬호스트 테스트 전용")
    print("AI 학습용 데이터 수집 및 분석 자동화")
    print()
    print("=" * 60)
    print()

def check_sudo_privileges():
    """sudo 권한 확인 및 자동 상승
    
    nmap 등의 도구는 SYN 스캔을 위해 root 권한이 필요합니다.
    권한이 없으면 자동으로 sudo로 재실행을 시도합니다.
    """
    import os
    import sys
    
    # 이미 root 권한인지 확인
    if os.geteuid() == 0:
        print("Root 권한으로 실행 중")
        return True
    
    # sudo 가능한지 확인
    try:
        import subprocess
        result = subprocess.run(['sudo', '-n', 'true'], 
                              capture_output=True, timeout=5)
        if result.returncode == 0:
            print("sudo 권한 확인됨")
            return True
    except:
        pass
    
    # sudo 권한이 필요한 경우 자동 재실행
    print("nmap 등의 도구를 위해 sudo 권한이 필요합니다.")
    print("sudo 권한으로 재실행 중...")
    
    try:
        # 현재 스크립트를 sudo로 재실행
        import sys
        import os
        
        # Python 실행 경로와 스크립트 경로, 모든 인자들 보존
        cmd = ['sudo', sys.executable] + sys.argv
        os.execvp('sudo', cmd)
        
    except Exception as e:
        print(f"sudo 권한 획득 실패: {e}")
        print("수동으로 다음 명령어를 실행하세요:")
        print(f"sudo {' '.join(sys.argv)}")
        sys.exit(1)

def check_required_tools():
    """필수 보안 도구들 설치 여부 확인
    
    스크립트 실행에 필요한 도구들이 설치되어 있는지 확인하고
    누락된 도구에 대한 설치 방법을 안내합니다.
    """
    required_tools = {
        'nmap': 'sudo apt install nmap',
        'whatweb': 'sudo apt install whatweb', 
        'nikto': 'sudo apt install nikto'
    }
    
    missing_tools = []
    
    for tool, install_cmd in required_tools.items():
        try:
            result = subprocess.run(['which', tool], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"{tool} 설치됨")
            else:
                missing_tools.append((tool, install_cmd))
        except:
            missing_tools.append((tool, install_cmd))
    
    if missing_tools:
        print("\n누락된 도구들:")
        for tool, cmd in missing_tools:
            print(f"   {tool}: {cmd}")
        print("\n설치 후 다시 실행해주세요.")
        return False
    
    return True

if __name__ == "__main__":
    """메인 실행 진입점"""
    import sys
    
    # 멋진 배너 출력
    print_banner()
    
    # 1. sudo 권한 확인 및 자동 상승
    check_sudo_privileges()
    
    # 2. 필수 도구 설치 여부 확인
    if not check_required_tools():
        sys.exit(1)
    
    print("모든 준비 완료, OSINT 파이프라인 시작...")
    print()
    
    # 3. 메인 파이프라인 실행
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n사용자에 의해 중단됨")
    except Exception as e:
        print(f"\n실행 중 오류 발생: {e}")
        sys.exit(1)