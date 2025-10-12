#!/usr/bin/env python3
# main.py

import asyncio
import os
from scanners import wapiti_scanner, ffuf_scanner, nuclei_scanner


async def async_run_scanners(url_file: str, headers: dict, cookies: dict):
    """
    /temp/url.txt 파일을 인자로 받아 wapiti_scan, nuclei_scan 을 비동기로 동시에 실행.
    """
    print(f"\n[+] 스캐너 실행 시작: {url_file}")
    try:
        # 비동기 병렬 실행
        await asyncio.gather(
            asyncio.to_thread(wapiti_scanner, url_file, headers, cookies),
            asyncio.to_thread(nuclei_scanner, url_file, headers, cookies)
        )
        print("[+] 모든 스캐너 실행 완료.")
    except Exception as e:
        print(f"[!] 스캐너 실행 중 오류 발생: {e}")


def main():
    print("=== FFUF + Wapiti + Nuclei Launcher ===")
		    #  output 디렉터리 확인 및 생성
    
    url = input("URL 입력 (예: http://yc22469.iptime.org:9991/www/homepage.html): ").strip()
    cookies = input("쿠키 입력 (예: sess=abc; uid=1) [없으면 엔터]: ").strip()
    headers = input("헤더 입력 (예: User-Agent:curl/7.0; Accept:*/*) [없으면 엔터]: ").strip()

    print("\n[INFO] 입력값 확인")
    print(f"  URL     : {url}")
    print(f"  Headers : {headers}")
    print(f"  Cookies : {cookies}")

    confirm = input("\n이 값으로 실행하시겠습니까? (y/n): ").strip().lower()
    if confirm != "y":
        print("[INFO] 실행이 취소되었습니다.")
        return

    print(f"\n[+] run_ffuf 실행 중... ({url})")
    try:
        result = ffuf_scanner.run_ffuf(url, output_dir=ffuf_scanner.OUTPUT_DIR, cookies=cookies)
        print("[+] run_ffuf 완료.")
    except Exception as e:
        print(f"[!] run_ffuf 실행 중 오류 발생: {e}")
        return

    # ffuf 결과 파일 확인
    url_file = "scanners/url.txt"
    if not os.path.exists(url_file):
        print(f"[!] {url_file} 파일이 존재하지 않습니다. run_ffuf 출력 경로를 확인하세요.")
        return

    print(f"[+] FFUF 결과 파일 발견: {url_file}")

    # 비동기 스캐너 실행
    asyncio.run(async_run_scanners(url_file, headers, cookies))


if __name__ == "__main__":
    main()