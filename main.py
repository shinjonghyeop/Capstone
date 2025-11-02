#!/usr/bin/env python3
"""
FFUF + Wapiti + Nuclei 통합 취약점 스캐너

웹 애플리케이션에 대해 디렉토리 스캔(FFUF) 후,
발견된 URL들을 대상으로 취약점 스캔(Wapiti, Nuclei)을 병렬 실행합니다.
"""

import asyncio
import os
import sys
import argparse
from typing import Optional, Tuple, List
from scanners.wapiti_scanner import run_scan as wapiti_scan
from scanners.ffuf_scanner import run_ffuf, OUTPUT_DIR
from scanners.nuclei_scanner import run_scan as nuclei_scan
from utils.web_crawler import crawl_website
from utils.nuclei_filter import filter_nuclei_results
from utils.wapiti_filter import filter_dir

# 상수 정의
RESULTS_FILE = "urls.txt"
BANNER = r"""
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

def validate_url(url: str) -> bool:
    """URL 형식이 올바른지 검증"""
    if not url:
        return False
    return url.startswith(("http://", "https://"))


def get_user_input() -> Optional[Tuple[str, str, str]]:
    """
    사용자로부터 스캔 대상 정보를 입력받습니다.

    Returns:
        (url, cookies, headers) 튜플 또는 취소 시 None
    """
    print(BANNER)
    print()

    # URL 입력
    url = input("URL 입력 (예: http://yc22469.iptime.org:9991/www/homepage.html): ").strip()
    if not validate_url(url):
        print("[!] 오류: 올바른 URL 형식이 아닙니다. (http:// 또는 https://로 시작해야 합니다)")
        return None

    # 쿠키 및 헤더 입력
    cookies = input("쿠키 입력 (예: sess=abc; uid=1) [없으면 엔터]: ").strip()
    headers = input("헤더 입력 (예: User-Agent:curl/7.0; Accept:*/*) [없으면 엔터]: ").strip()

    # 입력값 확인
    print("\n[INFO] 입력값 확인")
    print(f"  URL     : {url}")
    print(f"  Headers : {headers if headers else '(없음)'}")
    print(f"  Cookies : {cookies if cookies else '(없음)'}")

    # 실행 확인
    confirm = input("\n이 값으로 실행하시겠습니까? (y/n): ").strip().lower()
    if confirm != "y":
        print("[INFO] 실행이 취소되었습니다.")
        return None

    return url, cookies, headers

def parse_arguments():
    """명령줄 인자 파싱"""
    parser = argparse.ArgumentParser(
        description='FFUF + Wapiti + Nuclei 통합 취약점 스캐너',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--url', type=str, help='스캔 대상 URL')
    parser.add_argument('--cookies', type=str, default='', help='쿠키 문자열 (예: session=abc; uid=1)')
    parser.add_argument('--headers', type=str, default='', help='헤더 문자열 (예: User-Agent:curl)')
    parser.add_argument('--json', action='store_true', help='결과를 JSON 형태로 출력')
    
    return parser.parse_args()

def merge_and_deduplicate(ffuf_urls: List[str], crawler_urls: List[str]) -> List[str]:
    """
    FFUF와 크롤러 결과를 병합하고 중복 제거

    Args:
        ffuf_urls: FFUF에서 발견한 URL 리스트
        crawler_urls: 크롤러에서 발견한 URL 리스트

    Returns:
        중복 제거된 URL 리스트 (정렬됨)
    """
    # Set으로 중복 제거
    unique_urls = set()

    # FFUF 결과 추가
    if ffuf_urls:
        for url in ffuf_urls:
            unique_urls.add(url.strip())

    # 크롤러 결과 추가
    if crawler_urls:
        for url in crawler_urls:
            unique_urls.add(url.strip())

    # 정렬된 리스트로 반환
    return sorted(list(unique_urls))


async def run_discovery_stage(url: str, cookies: str) -> bool:
    """
    1단계: FFUF와 웹 크롤러를 병렬로 실행하여 URL 발견

    Args:
        url: 스캔 대상 URL
        cookies: 인증용 쿠키 문자열

    Returns:
        성공 여부
    """
    print(f"\n[+] 1단계: Discovery 시작... ({url})")
    print("[+] FFUF와 웹 크롤러를 병렬 실행합니다...")

    try:
        # FFUF와 크롤러를 병렬로 실행
        ffuf_urls, crawler_urls = await asyncio.gather(
            asyncio.to_thread(run_ffuf, url, OUTPUT_DIR, cookies),
            asyncio.to_thread(crawl_website, url, cookies, ""),
            return_exceptions=True
        )

        # 에러 체크
        if isinstance(ffuf_urls, Exception):
            print(f"[!] FFUF 실행 중 오류: {ffuf_urls}")
            ffuf_urls = []

        if isinstance(crawler_urls, Exception):
            print(f"[!] 크롤러 실행 중 오류: {crawler_urls}")
            crawler_urls = []

        # 결과 병합 및 중복 제거
        all_urls = merge_and_deduplicate(ffuf_urls, crawler_urls)

        # 통계 출력
        print(f"\n[+] Discovery 완료:")
        print(f"    FFUF: {len(ffuf_urls)}개 URL")
        print(f"    크롤러: {len(crawler_urls)}개 URL")
        print(f"    중복 제거 후: {len(all_urls)}개 URL")

        # urls.txt 저장
        if all_urls:
            with open(RESULTS_FILE, 'w') as f:
                f.write('\n'.join(all_urls))
            print(f"[+] {RESULTS_FILE} 저장 완료")
            return True
        else:
            print("[!] 발견된 URL이 없습니다.")
            return False

    except FileNotFoundError:
        print("[!] ffuf 명령어를 찾을 수 없습니다. ffuf가 설치되어 있는지 확인하세요.")
        return False
    except Exception as e:
        print(f"[!] Discovery 단계 실행 중 오류 발생: {e}")
        return False


def run_directory_scan(url: str, cookies: str) -> bool:
    """
    FFUF를 실행하여 디렉토리 및 파일을 스캔합니다.

    Args:
        url: 스캔 대상 URL
        cookies: 인증용 쿠키 문자열

    Returns:
        성공 여부
    """
    print(f"\n[+] FFUF 디렉토리 스캔 시작... ({url})")
    try:
        result = run_ffuf(url, output_dir=OUTPUT_DIR, cookies=cookies)

        if result and os.path.exists(result):
            print(f"[+] FFUF 스캔 완료. 결과: {result}")
            return True
        else:
            print("[!] FFUF 결과 파일이 생성되지 않았습니다.")
            return False

    except FileNotFoundError:
        print("[!] ffuf 명령어를 찾을 수 없습니다. ffuf가 설치되어 있는지 확인하세요.")
        return False
    except Exception as e:
        print(f"[!] FFUF 실행 중 오류 발생: {e}")
        return False


async def run_vulnerability_scanners(url_file: str, headers: str, cookies: str) -> None:
    """
    Wapiti와 Nuclei 스캐너를 비동기로 병렬 실행합니다.

    Args:
        url_file: 스캔 대상 URL 목록이 저장된 파일 경로
        headers: HTTP 헤더 문자열
        cookies: 쿠키 문자열
    """
    print(f"\n[+] 취약점 스캐너 실행 시작: {url_file}")

    try:
        # Wapiti와 Nuclei를 병렬로 실행
        results = await asyncio.gather(
            asyncio.to_thread(
                wapiti_scan,
                [url_file],
                cookies=cookies,
                headers=[headers] if headers else None
            ),
            asyncio.to_thread(
                nuclei_scan,
                headers=headers,
                cookies=cookies
            ),
            return_exceptions=True
        )

        # 각 스캐너 결과 확인
        for idx, result in enumerate(results):
            scanner_name = ["Wapiti", "Nuclei"][idx]
            if isinstance(result, Exception):
                print(f"[!] {scanner_name} 실행 중 오류: {result}")

        print("[+] 모든 취약점 스캐너 실행 완료.")

    except Exception as e:
        print(f"[!] 스캐너 실행 중 예상치 못한 오류 발생: {e}")


async def main_async(url: str = None, cookies: str = "", headers: str = ""):
    """메인 실행 함수 (비동기)"""
    # url이 있으면 input() 건너뛰기
    if url:
        print(f"[INFO] 명령줄 모드로 실행")
    else:
        user_input = get_user_input()
        if user_input is None:
            return
        url, cookies, headers = user_input

    # 1단계: Discovery (FFUF + 크롤러 병렬 실행)
    if not await run_discovery_stage(url, cookies):
        print("[!] Discovery 단계 실패. 프로그램을 종료합니다.")
        sys.exit(1)

    # 결과 파일 확인
    if not os.path.exists(RESULTS_FILE):
        print(f"[!] {RESULTS_FILE} 파일이 존재하지 않습니다.")
        sys.exit(1)

    # 2단계: 취약점 스캐너 실행 (비동기)
    await run_vulnerability_scanners(RESULTS_FILE, headers, cookies)

    print("\n[+] 모든 스캔 완료!")

    # 3단계: Wapiti 결과 필터링
    print("\n[+] Wapiti 결과 필터링 시작...")
    try:
        processed_count = filter_dir(
            input_dir="wapiti_results"
        )
        if processed_count > 0:
            print(f"[+] Wapiti 필터링 완료: {processed_count}개 파일 처리됨")
        else:
            print("[!] 필터링할 Wapiti 결과가 없습니다.")
    except Exception as e:
        print(f"[!] Wapiti 필터링 중 오류 발생: {e}")

    # 3단계: Nuclei 결과 필터링
    print("\n[+] Nuclei 결과 필터링 시작...")
    try:
        processed_count = filter_nuclei_results(
            input_dir="nuclei_results",
            output_dir="filtered",
            pretty=True
        )
        if processed_count > 0:
            print(f"[+] Nuclei 필터링 완료: {processed_count}개 파일 처리됨")
        else:
            print("[!] 필터링할 Nuclei 결과가 없습니다.")
    except Exception as e:
        print(f"[!] Nuclei 필터링 중 오류 발생: {e}")


def main():
    try:
        args = parse_arguments()
        
        if args.url:
            if not validate_url(args.url):
                print("오류: 올바른 URL 형식이 아닙니다.")
                sys.exit(1)
            
            asyncio.run(main_async(
                url = args.url,
                cookies = args.cookies,
                headers = args.headers
            ))
        else:
            asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] 사용자에 의해 중단되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] 예상치 못한 오류: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
