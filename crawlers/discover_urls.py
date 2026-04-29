#!/usr/bin/env python3
"""
FFUF + 웹 크롤러를 병렬로 실행해 URL을 수집하고 urls.txt로 저장합니다.
"""

import asyncio
import os
from typing import List

from crawlers.ffuf_scanner import run_ffuf, OUTPUT_DIR
from crawlers.web_crawler import crawl_website

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
RESULTS_FILE = os.path.join(PROJECT_ROOT, "urls.txt")


def merge_and_deduplicate(ffuf_urls: List[str], crawler_urls: List[str]) -> List[str]:
    """
    FFUF와 크롤러 결과를 병합하고 중복 제거

    Args:
        ffuf_urls: FFUF에서 발견한 URL 리스트
        crawler_urls: 크롤러에서 발견한 URL 리스트

    Returns:
        중복 제거된 URL 리스트 (정렬됨)
    """
    unique_urls = set()

    if ffuf_urls:
        for url in ffuf_urls:
            unique_urls.add(url.strip())

    if crawler_urls:
        for url in crawler_urls:
            unique_urls.add(url.strip())

    return sorted(list(unique_urls))


async def run_discovery_stage(url: str, cookies: str, headers: str = "", rate: int = None) -> bool:
    """
    FFUF와 웹 크롤러를 병렬로 실행하여 URL을 발견하고 urls.txt로 저장합니다.

    Args:
        url: 스캔 대상 URL
        cookies: 인증용 쿠키 문자열
        headers: 인증용 헤더 문자열
        rate: 사용자가 지정한 초당 요청 수(없으면 기본 동작 유지)

    Returns:
        성공 여부
    """
    print(f"\n[+] 1단계: Discovery 시작... ({url})")
    print("[+] FFUF와 웹 크롤러를 병렬 실행합니다...")

    try:
        ffuf_urls, crawler_urls = await asyncio.gather(
            asyncio.to_thread(run_ffuf, url, OUTPUT_DIR, cookies, rate),
            asyncio.to_thread(crawl_website, url, cookies, headers),
            return_exceptions=True
        )

        if isinstance(ffuf_urls, Exception):
            print(f"[!] FFUF 실행 중 오류: {ffuf_urls}")
            ffuf_urls = []

        if isinstance(crawler_urls, Exception):
            print(f"[!] 크롤러 실행 중 오류: {crawler_urls}")
            crawler_urls = []

        all_urls = merge_and_deduplicate(ffuf_urls, crawler_urls)

        print(f"\n[+] Discovery 완료:")
        print(f"    FFUF: {len(ffuf_urls)}개 URL")
        print(f"    크롤러: {len(crawler_urls)}개 URL")
        print(f"    중복 제거 후: {len(all_urls)}개 URL")

        if all_urls:
            with open(RESULTS_FILE, 'w') as f:
                f.write('\n'.join(all_urls))
            print(f"[+] {RESULTS_FILE} 저장 완료")
            return True

        print("[!] 발견된 URL이 없습니다.")
        return False

    except FileNotFoundError:
        print("[!] ffuf 명령어를 찾을 수 없습니다. ffuf가 설치되어 있는지 확인하세요.")
        return False
    except Exception as e:
        print(f"[!] Discovery 단계 실행 중 오류 발생: {e}")
        return False

if __name__ == "__main__":
    target_url = "http://192.168.64.2:9991/www/homepage.html"
    target_cookies = ""
    target_headers = ""
    asyncio.run(run_discovery_stage(target_url, target_cookies, target_headers))
