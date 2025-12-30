# scanners/nuclei_scanner.py

import subprocess
import shutil
import os
from datetime import datetime
from pathlib import Path
import re

RESULTS_DIR = "nuclei_results"

def run_scan(url_file: str = "./urls.txt", headers: str = "", cookies: str = "") -> None:
    """
    Nuclei 스캔을 병렬로 실행하고 결과를 저장합니다.
    urls.txt 파일에서 URL을 읽어 각 URL에 대해 xss, sql, cve 태그를 사용하여 스캔합니다.
    
    Args:
        url_file: 스캔 대상 URL 파일 경로
        headers: 헤더 문자열 (예: "User-Agent:curl/7.0; Accept:*/*")
        cookies: 쿠키 문자열 (예: "sess=abc; uid=1")
    """
    print("\n[Nuclei] 스캔 시작...")
    
    # 템플릿 경로 (홈 디렉토리 고정)
    templates_path = os.path.expanduser("./scanners/nuclei-templates")
    # templates_path = os.path.expanduser("./nuclei-templates")
    
    # 결과 디렉토리 존재할 경우 삭제 후 재생성
    # 현재 main.py에서 디렉터리를 삭제하고 있음,
    # 때문에 여기서는 makedirs만 수행해도 됨.
    if os.path.exists(RESULTS_DIR):
        shutil.rmtree(RESULTS_DIR)
    os.makedirs(RESULTS_DIR)
    
    # URL 파일 읽기
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[Nuclei] URL 파일을 찾을 수 없습니다: {url_file}")
        return
    if not urls:
        print(f"[Nuclei] URL 파일에서 유효한 URL을 찾을 수 없습니다: {url_file}")
        return
        
    # rce, lfi, file, file-upload, ssrf 등 태그 추가 예정
    tags_to_scan = ["xss", "sqli", "cve"]
    # 각 URL에 대해 동기로 Nuclei 스캔 실행
    for url in urls:

        for tag in tags_to_scan:
            # 출력 파일명 생성 (URL과 태그 포함)
            sanitized_url = re.sub(r'https?://', '', url).replace('/', '_').replace(':', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(RESULTS_DIR, f"nuclei_scan_{sanitized_url}_{tag}_{timestamp}.json")
            
            # 기본 명령어 구성
            command = [
                "nuclei",
                "-u", url,                      # 개별 URL
                "-je", output_file,             # JSON export
                "-t", templates_path,           # 템플릿 경로
                "-silent",                      # 조용한 실행
                #"-debug",                       # 디버그 모드
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
                command.extend(["-H", f"Cookies: {cookies}"])
            
            print(f"[Nuclei] 명령어 실행: {' '.join(command)}")
            
            # Nuclei 프로세스 시작
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(timeout=900) # 태그 하나당 최대 15분 대기

                if proc.returncode == 0:
                    print(f"[Nuclei] 스캔 완료: {output_file}")
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 2:
                        print(f"[Nuclei] 발견사항 있음: {output_file}")
                    else:
                        print(f"[Nuclei] 취약점 없음: {output_file}")
                        os.remove(output_file)  # 빈 결과 파일 삭제
                else:
                    print(f"[Nuclei] 오류 발생 (코드: {proc.returncode}): {output_file}")

            except subprocess.TimeoutExpired:
                print(f"[Nuclei] 타임아웃 (15분 초과): {output_file}")
                proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except:
                    pass
            except FileNotFoundError:
                print("[Nuclei] 'nuclei' 명령을 찾을 수 없습니다. 설치되었는지 확인하세요.")
                return
            except Exception as e:
                print(f"[Nuclei] 스캔 중 예상치 못한 오류: {e}")

    print("\n[Nuclei] 모든 스캔이 종료되었습니다.")

if __name__ == "__main__":
    """
    테스트용 메인 함수
    """
    run_scan()
