# scanners/nuclei_scanner.py

import subprocess
import os
import tempfile
from datetime import datetime
from pathlib import Path


def run_scan(url_file: str, headers: str = "", cookies: str = "") -> None:
    """
    Nuclei 스캔을 실행하고 결과를 저장합니다.
    
    Args:
        url_file: URL이 저장된 파일 경로 (예: scanners/url.txt)
        headers: 헤더 문자열 (예: "User-Agent:curl/7.0; Accept:*/*")
        cookies: 쿠키 문자열 (예: "sess=abc; uid=1")
    """
    print("\n[Nuclei] 스캔 시작...")
    
    # 템플릿 경로 (홈 디렉토리 고정)
    templates_path = os.path.expanduser("./nuclei-templates")
    # templates_path = os.path.expanduser("./scanners/nuclei-templates")
    
    # 결과 저장 디렉토리
    results_dir = "nuclei_results"
    os.makedirs(results_dir, exist_ok=True)
    
    # 출력 파일명 (타임스탬프 포함)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(results_dir, f"nuclei_scan_{timestamp}.json")
    
    # 기본 명령어 구성
    command = [
        "nuclei",
        "-l", url_file,                # URL 리스트 파일
        "-je", output_file,             # JSON export
        "-t", templates_path,           # 템플릿 경로
        "-silent",                      # 조용한 실행
        "-rate-limit", "150",           # 초당 요청 제한
        "-concurrency", "25",           # 동시 실행
        "-retries", "2",                # 재시도 횟수
        "-timeout", "10",               # 타임아웃
    ]
    
    # 태그 설정 (고정값)
    tags = [
        "hacklipse"
    ]
    command.extend(["-tags", ",".join(tags)])
    
    # 심각도 필터
    command.extend(["-severity", "critical,high,medium"])
    
    # HTTP 프로토콜만
    command.extend(["-type", "http"])
    
    # 헤더 처리
    if headers:
        # 세미콜론으로 구분된 헤더들을 파싱
        header_pairs = headers.split(";")
        for header_pair in header_pairs:
            header_pair = header_pair.strip()
            if header_pair:
                # "Key:Value" 형식을 "Key: Value"로 변환
                if ":" in header_pair:
                    key, value = header_pair.split(":", 1)
                    command.extend(["-H", f"{key.strip()}: {value.strip()}"])
    
    # 쿠키 처리
    if cookies:
        command.extend(["-H", f"Cookie: {cookies}"])
    
    print(f"[Nuclei] 명령어: {' '.join(command)}")  # 일부만 출력
    print(f"[Nuclei] 결과 파일: {output_file}")
    
    try:
        # Nuclei 실행
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900  # 15분 타임아웃
        )
        
        if result.returncode == 0:
            print(f"[Nuclei] 스캔 완료! 결과가 {output_file}에 저장되었습니다.")
            
            # 결과 파일 크기 확인
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                if file_size > 2:  # 빈 JSON ([])보다 큰 경우
                    print(f"[Nuclei] 발견사항이 있습니다. (파일 크기: {file_size} bytes)")
                else:
                    print("[Nuclei] 취약점이 발견되지 않았습니다.")
        else:
            print(f"[Nuclei] 실행 중 경고 또는 오류 (코드: {result.returncode})")
            if result.stderr:
                print(f"[Nuclei] 오류 메시지: {result.stderr[:500]}")
                
    except subprocess.TimeoutExpired:
        print("[Nuclei] 타임아웃 (15분 초과)")
    except FileNotFoundError:
        print("[Nuclei] nuclei 명령어를 찾을 수 없습니다. 설치를 확인하세요.")
    except Exception as e:
        print(f"[Nuclei] 예상치 못한 오류: {e}")
    
    print("[Nuclei] 스캔 종료.")

if __name__ == "__main__":
    """
    테스트용 메인 함수
    """
    test_url_file = "../urls.txt"
    
    run_scan(test_url_file)