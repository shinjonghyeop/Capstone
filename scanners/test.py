import sys
import shutil
import argparse
import json
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from wapiti_scanner import run_scan

def main():
    parser = argparse.ArgumentParser(description="Wapiti 스캐너 모듈 테스트 스크립트 (개선판)")
    parser.add_argument("-u", "--urls", nargs='+', required=True, dest="urls",
                        help="스캔할 대상 URL 목록 (여러 개 가능)")
    parser.add_argument("-C", "--cookies", type=str, dest="cookies",
                        help="Wapiti에 전달할 쿠키 문자열 또는 쿠키 파일 경로")
    parser.add_argument("-H", "--headers", nargs='+', metavar='"Header: Value"',
                        help="커스텀 헤더들. 예: -H \"User-Agent: X\" \"Authorization: Bearer ...\"")
    args = parser.parse_args()

    # 실행 환경 검사: CLI wapiti 존재 여부는 선택적
    wapiti_cli_exists = shutil.which("wapiti") is not None
    if not wapiti_cli_exists:
        print("[!] 주의: 시스템 PATH에 'wapiti'가 없습니다. run_scan이 내부 API를 이용하는지 확인하세요.")

    # 실제 스캔 호출
    try:
        findings = run_scan(
            targets=args.urls,
            cookies=args.cookies,
            headers=args.headers
        )
    except Exception as e:
        print(f"[!] run_scan 실행 중 예외 발생: {e}")
        sys.exit(2)

    # 결과 출력
    print("\n[*] 테스트가 완료되었습니다.")

if __name__ == "__main__":
    # run_scan이 내부 라이브러리를 사용하는 경우 wapiti CLI 검사 생략 가능.
    main()