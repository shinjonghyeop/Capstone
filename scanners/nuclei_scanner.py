# scanners/nuclei_scanner.py

import subprocess
import os
from datetime import datetime
from pathlib import Path
import re

def run_scan(headers: str = "", cookies: str = "") -> None:
    """
    Nuclei 스캔을 병렬로 실행하고 결과를 저장합니다.
    urls.txt 파일에서 URL을 읽어 각 URL에 대해 xss, sql, cve 태그를 사용하여 스캔합니다.
    
    Args:
        headers: 헤더 문자열 (예: "User-Agent:curl/7.0; Accept:*/*")
        cookies: 쿠키 문자열 (예: "sess=abc; uid=1")
    """
    print("\n[Nuclei] 스캔 시작...")
    
    # URL 파일 경로
    url_file = './urls.txt'
    
    # 템플릿 경로 (홈 디렉토리 고정)
    templates_path = os.path.expanduser("./scanners/nuclei-templates")
    
    # 결과 저장 디렉토리
    results_dir = "nuclei_results"
    os.makedirs(results_dir, exist_ok=True)
    
    # URL 파일 읽기
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[Nuclei] URL 파일을 찾을 수 없습니다: {url_file}")
        return
        
    tags_to_scan = ["xss", "sql", "cve"]

    for url in urls:
        url_processes = [] # 각 URL에 대한 프로세스 리스트
        for tag in tags_to_scan:
            # 출력 파일명 생성 (URL과 태그 포함)
            sanitized_url = re.sub(r'https?://', '', url).replace('/', '_').replace(':', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(results_dir, f"nuclei_scan_{sanitized_url}_{tag}_{timestamp}.json")
            
            # 기본 명령어 구성
            command = [
                "nuclei",
                "-u", url,                      # 개별 URL
                "-je", output_file,             # JSON export
                "-t", templates_path,           # 템플릿 경로
                "-silent",                      # 조용한 실행
                "-rate-limit", "150",           # 초당 요청 제한
                "-concurrency", "20",           # 동시 실행
                "-retries", "2",                # 재시도 횟수
                "-timeout", "10",               # 타임아웃
                "-tags", tag                   # 개별 태그
            ]
            
            # 헤더 처리
            if headers:
                header_pairs = headers.split(";")
                for header_pair in header_pairs:
                    header_pair = header_pair.strip()
                    if header_pair and ":" in header_pair:
                        key, value = header_pair.split(":", 1)
                        command.extend(["-H", f"{key.strip()}: {value.strip()}"])
            
            # 쿠키 처리
            if cookies:
                command.extend(["-H", f"Cookie: {cookies}"])
            
            print(f"[Nuclei] 명령어 실행: {' '.join(command)}")
            
            # Nuclei 프로세스 시작
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                url_processes.append((proc, output_file))
                
            except FileNotFoundError:
                print("[Nuclei] 'nuclei' 명령을 찾을 수 없습니다. 설치되었는지 확인하세요.")
                return
            except Exception as e:
                print(f"[Nuclei] 프로세스 시작 중 오류 발생: {e}")

    print(f"[Nuclei] {url} 의 태그 스캔들 종료 대기…")
    # 모든 프로세스가 완료될 때까지 대기
    for proc, output_file in url_processes:
        try:
            stdout, stderr = proc.communicate(timeout=900) # 15분 타임아웃
            
            if proc.returncode == 0:
                print(f"[Nuclei] 스캔 완료: {output_file}")
                if os.path.exists(output_file) and os.path.getsize(output_file) > 2:
                    print(f"[Nuclei] 발견사항 있음: {output_file}")
                else:
                    print(f"[Nuclei] 취약점 없음: {output_file}")
            else:
                print(f"[Nuclei] 오류 발생 (코드: {proc.returncode}): {output_file}")
                if stderr:
                    print(f"[Nuclei] 오류 메시지: {stderr[:500]}")

        except subprocess.TimeoutExpired:
            print(f"[Nuclei] 타임아웃 (15분 초과): {output_file}")
            proc.kill()
            stdout, stderr = proc.communicate()
        except Exception as e:
            print(f"[Nuclei] 스캔 중 예상치 못한 오류: {e}")

    print("\n[Nuclei] 모든 스캔이 종료되었습니다.")

if __name__ == "__main__":
    """
    테스트용 메인 함수
    """
    run_scan()
