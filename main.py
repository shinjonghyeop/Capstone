#!/usr/bin/env python3
"""
FFUF + Wapiti + Nuclei 통합 취약점 스캐너

웹 애플리케이션에 대해 디렉토리 스캔(FFUF) 후,
발견된 URL들을 대상으로 취약점 스캔(Wapiti, Nuclei)을 동기 실행합니다.
"""

import asyncio
import os
import sys
import argparse
import shutil
import time
from typing import Optional, Tuple
from scanners.wapiti_scanner import run_scan as wapiti_scan
from scanners.nuclei_scanner import run_scan as nuclei_scan
from crawlers.discover_urls import run_discovery_stage, RESULTS_FILE
from utils.nuclei_filter import filter_nuclei_results
from utils.wapiti_filter import filter_wapiti_results
from utils.merge_scan_results import merge_filtered_results


# 상수 정의
WAPITI_RESULTS_DIR = "wapiti_results"
NUCLEI_RESULTS_DIR = "nuclei_results"
FILTERED_RESULTS_DIR = "filtered"
MERGED_RESULTS_DIR = "merged_results"
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

STATUS_FILE = os.getenv("SCAN_STATUS_FILE")
CURRENT_TARGET = None


def update_status(phase: str, step: str, message: str) -> None:
    if not STATUS_FILE:
        return
    payload = {
        "phase": phase,
        "step": step,
        "message": message,
        "updatedAt": int(time.time())
    }
    if CURRENT_TARGET:
        payload["target"] = CURRENT_TARGET
    try:
        with open(STATUS_FILE, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False)
    except Exception:
        pass

def validate_url(url: str) -> bool:
    """URL 형식이 올바른지 검증"""
    if not url:
        return False
    return url.startswith(("http://", "https://"))

# 테스트용 배포 시 해당 함수 삭제 
def get_user_input() -> Optional[Tuple[str, str, str]]:
    """
    사용자로부터 스캔 대상 정보를 입력받습니다.

    Returns:
        (url, cookies, headers) 튜플 또는 취소 시 None
    """
    print(BANNER)
    print()

    # URL 입력
    url = input("URL 입력 (예: http://localhost:8080/index.html): ").strip()
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

def parse_arguments() -> argparse.Namespace:
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

async def run_vulnerability_scanners_sync(headers: str, cookies: str) -> None:
    """
    Wapiti와 Nuclei 스캐너를 순차적으로 실행합니다.

    Args:
        url_file: 스캔 대상 URL 목록이 저장된 파일 경로
        headers: HTTP 헤더 문자열
        cookies: 쿠키 문자열
    """
    print(f"\n[+] 취약점 스캐너 순차 실행 시작: {RESULTS_FILE}")

    # 1. Wapiti 스캔 실행
    update_status("scanning", "wapiti", "Wapiti 스캔 시작")
    print("\n[+] Wapiti 스캔 시작...")
    try:
        wapiti_scan(
            RESULTS_FILE,
            cookies=cookies,
            headers=headers if headers else None
        )
        print("[+] Wapiti 스캔 완료.")
    except Exception as e:
        print(f"[!] Wapiti 실행 중 오류: {e}")

    # 2. Nuclei 스캔 실행
    update_status("scanning", "nuclei", "Nuclei 스캔 시작")
    print("\n[+] Nuclei 스캔 시작...")
    try:
        # nuclei_scan은 동기 함수이므로 asyncio.to_thread로 감싸기
        await asyncio.to_thread(
            nuclei_scan,
            RESULTS_FILE,
            headers=headers,
            cookies=cookies
        )
        print("[+] Nuclei 스캔 완료.")
    except Exception as e:
        print(f"[!] Nuclei 실행 중 오류: {e}")

    print("[+] 모든 취약점 스캐너 실행 완료.")


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

    global CURRENT_TARGET
    CURRENT_TARGET = url
    update_status("scanning", "discovery", "Discovery 단계 시작")

    # 1단계: Discovery (FFUF + 크롤러 병렬 실행)
    # if not await run_discovery_stage(url, cookies, headers):
    #     print("[!] Discovery 단계 실패. 프로그램을 종료합니다.")
    #     update_status("error", "discovery", "Discovery 단계 실패")
    #     sys.exit(1)

    # urls.txt 파일 확인
    if not os.path.exists(RESULTS_FILE):
        print(f"[!] {RESULTS_FILE} 파일이 존재하지 않습니다.")
        update_status("error", "discovery", "Discovery 결과 파일 없음")
        sys.exit(1)

    # 2단계: 취약점 스캐너 실행 (순차 실행)
    await run_vulnerability_scanners_sync(headers, cookies)

    print("\n[+] 모든 스캔 완료!")

    # 3단계: Wapiti 결과 필터링
    update_status("scanning", "filter_wapiti", "Wapiti 결과 필터링")
    print("\n[+] Wapiti 결과 필터링 시작...")
    if os.path.isdir(WAPITI_RESULTS_DIR):
        try:
            wapiti_processed = filter_wapiti_results(
                input_dir=WAPITI_RESULTS_DIR,
                output_dir=FILTERED_RESULTS_DIR
            )
            if wapiti_processed and len(wapiti_processed) > 0:
                print(f"[+] Wapiti 필터링 완료: {len(wapiti_processed)}개 파일 처리됨")
            else:
                print("[!] 필터링할 Wapiti 결과가 없습니다.")
        except Exception as e:
            print(f"[!] Wapiti 필터링 중 오류 발생: {e}")
    else:
        print(f"[!] Wapiti 결과 디렉토리가 없습니다: {WAPITI_RESULTS_DIR}")

    # 4단계: Nuclei 결과 필터링
    update_status("scanning", "filter_nuclei", "Nuclei 결과 필터링")
    print("\n[+] Nuclei 결과 필터링 시작...")
    if os.path.isdir(NUCLEI_RESULTS_DIR):
        try:
            nuclei_processed = filter_nuclei_results(
                input_dir=NUCLEI_RESULTS_DIR,
                output_dir=FILTERED_RESULTS_DIR,
                pretty=True
            )
            if nuclei_processed > 0:
                print(f"[+] Nuclei 필터링 완료: {nuclei_processed}개 파일 처리됨")
            else:
                print("[!] 필터링할 Nuclei 결과가 없습니다.")
        except Exception as e:
            print(f"[!] Nuclei 필터링 중 오류 발생: {e}")
    else:
        print(f"[!] Nuclei 결과 디렉토리가 없습니다: {NUCLEI_RESULTS_DIR}")

    # 5단계: 스캔 결과 병합 (Domain-level)
    update_status("scanning", "merge", "스캔 결과 병합")
    print("\n[+] 5단계: 스캔 결과 병합 시작...")
    if os.path.isdir(FILTERED_RESULTS_DIR):
        try:
            merged_count = merge_filtered_results(
                input_dir=FILTERED_RESULTS_DIR,
                output_dir=MERGED_RESULTS_DIR
            )
            if merged_count > 0:
                print(f"[+] 스캔 결과 병합 완료: {merged_count}개 도메인 파일 생성됨")
            else:
                print("[!] 병합할 결과가 없습니다.")
        except Exception as e:
            print(f"[!] 결과 병합 중 오류 발생: {e}")
    else:
        print(f"[!] 병합할 결과가 없습니다: {FILTERED_RESULTS_DIR}")

    # 임시 결과 정리 (merged_results는 유지)
    update_status("scanning", "cleanup", "임시 결과 정리")
    for path in [FILTERED_RESULTS_DIR, WAPITI_RESULTS_DIR, NUCLEI_RESULTS_DIR]:
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                print(f"[+] 정리 완료: {path}")
            except Exception as e:
                print(f"[!] 정리 실패: {path} - {e}")

    if os.path.exists(RESULTS_FILE):
        try:
            os.remove(RESULTS_FILE)
            print(f"[+] 정리 완료: {RESULTS_FILE}")
        except Exception as e:
            print(f"[!] 정리 실패: {RESULTS_FILE} - {e}")

    update_status("done", "complete", "스캔 완료")


def main() -> None:
    """메인 진입점"""
    try:
        args = parse_arguments()

        if args.url:
            if not validate_url(args.url):
                print("[!] 오류: 올바른 URL 형식이 아닙니다.")
                sys.exit(1)

            asyncio.run(main_async(
                url=args.url,
                cookies=args.cookies,
                headers=args.headers
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
