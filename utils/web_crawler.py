#!/usr/bin/env python3
"""
웹 크롤러 모듈

같은 도메인 내의 모든 URL을 자동으로 탐색하여 수집합니다.
HTML, JavaScript에서 엔드포인트를 추출합니다.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import re
from typing import List, Set, Dict
from collections import deque
import warnings

# SSL 경고 무시
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# 정적 리소스 확장자 (취약점 스캔에서 제외)
STATIC_RESOURCE_EXTENSIONS = {
    # 이미지
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
    # 비디오/오디오
    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mp3', '.wav', '.ogg',
    # 폰트
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    # 스타일/스크립트 (정적 파일만 - .js는 제외하여 동적 엔드포인트 탐색)
    '.css', '.map', '.min.js',  # minified JS만 제외
    # 문서/압축
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.tar', '.gz',
    # 기타
    '.swf', '.xml', '.json', '.txt'
}


def _parse_cookies(cookie_str: str) -> Dict[str, str]:
    """
    쿠키 문자열을 딕셔너리로 변환

    Args:
        cookie_str: "name=value; name2=value2" 형식

    Returns:
        {"name": "value", "name2": "value2"}
    """
    if not cookie_str:
        return {}

    cookies = {}
    for item in cookie_str.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies


def _parse_headers(header_str: str) -> Dict[str, str]:
    """
    헤더 문자열을 딕셔너리로 변환

    Args:
        header_str: "Name:Value; Name2:Value2" 형식

    Returns:
        {"Name": "Value", "Name2": "Value2"}
    """
    if not header_str:
        return {}

    headers = {}
    for item in header_str.split(';'):
        item = item.strip()
        if ':' in item:
            key, value = item.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def _normalize_url(url: str) -> str:
    """
    URL 정규화 (중복 제거용)

    - Fragment 제거 (#section)
    - 쿼리스트링 보존
    - 슬래시 정규화

    Args:
        url: 원본 URL

    Returns:
        정규화된 URL
    """
    if not url:
        return ""

    parsed = urlparse(url)

    # Fragment 제거 (scheme, netloc, path, params, query만 유지)
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        ''  # fragment 제거
    ))

    return normalized


def _is_static_resource(url: str) -> bool:
    """
    URL이 정적 리소스인지 확인 (이미지, CSS, 폰트 등)

    Args:
        url: 확인할 URL

    Returns:
        정적 리소스면 True
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # 확장자 확인
    for ext in STATIC_RESOURCE_EXTENSIONS:
        if path.endswith(ext):
            return True

    return False


def _is_same_domain(url1: str, url2: str) -> bool:
    """
    두 URL이 같은 도메인인지 확인 (scheme, host, port 비교)

    Args:
        url1: 기준 URL
        url2: 비교할 URL

    Returns:
        같은 도메인이면 True
    """
    parsed1 = urlparse(url1)
    parsed2 = urlparse(url2)

    return (
        parsed1.scheme == parsed2.scheme and
        parsed1.netloc == parsed2.netloc
    )


def _extract_urls_from_html(html: str, base_url: str) -> Set[str]:
    """
    HTML에서 URL 추출

    추출 대상:
    - <a href>
    - <link href>
    - <form action>
    - <iframe src>, <img src>, <script src>

    Args:
        html: HTML 문자열
        base_url: 기준 URL (상대 경로 변환용)

    Returns:
        추출된 URL Set
    """
    urls = set()

    try:
        soup = BeautifulSoup(html, 'html.parser')

        # <a href>, <link href>
        for tag in soup.find_all(['a', 'link'], href=True):
            url = urljoin(base_url, tag['href'])
            urls.add(url)

        # <form action>
        for form in soup.find_all('form', action=True):
            url = urljoin(base_url, form['action'])
            urls.add(url)

        # <iframe src>, <img src>, <script src>
        for tag in soup.find_all(['iframe', 'img', 'script'], src=True):
            url = urljoin(base_url, tag['src'])
            urls.add(url)

    except Exception as e:
        print(f"[!] HTML 파싱 오류: {e}")

    return urls


def _extract_urls_from_js(js_content: str, base_url: str) -> Set[str]:
    """
    JavaScript 코드에서 URL/경로 추출

    패턴:
    - "/api/endpoint"
    - '/path/to/resource'
    - "api/users"
    - fetch("/data")
    - location.href='page.html'

    Args:
        js_content: JavaScript 코드
        base_url: 기준 URL

    Returns:
        추출된 URL Set
    """
    urls = set()

    # 정규식 패턴들
    patterns = [
        r'["\']([/][^"\'?\s]+(?:\?[^"\']*)?)["\']',  # "/path" 또는 "/path?query"
        r'["\']([a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)+)["\']',  # "api/endpoint"
        r'["\']([a-zA-Z0-9_\-]+\.(?:html|php|js|css|jsp|asp|aspx))["\']',  # "page.html"
        r'location\.href\s*=\s*["\']([^"\']+)["\']',  # location.href='...'
        r'window\.location\s*=\s*["\']([^"\']+)["\']',  # window.location='...'
    ]

    try:
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # 상대 경로를 절대 경로로 변환
                url = urljoin(base_url, match)
                urls.add(url)
    except Exception as e:
        print(f"[!] JavaScript 파싱 오류: {e}")

    return urls


def crawl_website(
    start_url: str,
    cookies: str = "",
    headers: str = ""
) -> List[str]:
    """
    같은 도메인 내 모든 URL을 BFS 방식으로 크롤링

    Args:
        start_url: 시작 URL (예: http://example.com/app)
        cookies: 쿠키 문자열 (예: "sess=abc; uid=1")
        headers: 헤더 문자열 (예: "User-Agent:curl/7.0")

    Returns:
        발견된 URL 리스트 (중복 제거됨)
    """
    print(f"[Crawler] 크롤링 시작: {start_url}")

    # 설정
    MAX_PAGES = 100
    TIMEOUT = 10

    # 상태 관리
    visited = set()  # 방문한 URL
    to_visit = deque([start_url])  # 방문할 URL 큐
    discovered_urls = set()  # 발견한 모든 URL

    # 쿠키/헤더 파싱
    cookie_dict = _parse_cookies(cookies)
    header_dict = _parse_headers(headers)

    # 기본 헤더 설정
    if 'User-Agent' not in header_dict:
        header_dict['User-Agent'] = 'Mozilla/5.0 (Hacklipse Web Crawler)'

    # BFS 크롤링
    page_count = 0

    while to_visit and page_count < MAX_PAGES:
        current_url = to_visit.popleft()

        # 정규화
        current_url = _normalize_url(current_url)

        # 이미 방문했으면 스킵
        if current_url in visited:
            continue

        # 같은 도메인이 아니면 스킵
        if not _is_same_domain(start_url, current_url):
            continue

        # 정적 리소스면 스킵
        if _is_static_resource(current_url):
            visited.add(current_url)  # 방문 기록은 남기되
            continue  # 크롤링은 하지 않음

        visited.add(current_url)
        discovered_urls.add(current_url)
        page_count += 1

        print(f"[Crawler] [{page_count}/{MAX_PAGES}] {current_url}")

        try:
            # HTTP 요청
            response = requests.get(
                current_url,
                cookies=cookie_dict,
                headers=header_dict,
                timeout=TIMEOUT,
                verify=False,  # SSL 검증 무시
                allow_redirects=True
            )

            # 성공한 경우만 처리
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()

                # 리다이렉트가 발생했으면 최종 URL을 base_url로 사용
                final_url = response.url if response.url else current_url

                # HTML 응답인 경우
                if 'text/html' in content_type:
                    # HTML에서 URL 추출 (최종 URL을 base로 사용)
                    html_urls = _extract_urls_from_html(response.text, final_url)

                    # HTML 내 JavaScript 코드에서도 URL 추출 (onclick 등)
                    js_urls_in_html = _extract_urls_from_js(response.text, final_url)
                    html_urls.update(js_urls_in_html)

                    for url in html_urls:
                        normalized = _normalize_url(url)
                        if normalized and normalized not in visited:
                            if _is_same_domain(start_url, normalized):
                                # 정적 리소스가 아닌 경우에만 추가
                                if not _is_static_resource(normalized):
                                    to_visit.append(normalized)
                                    discovered_urls.add(normalized)

                # JavaScript 응답인 경우
                elif 'javascript' in content_type or final_url.endswith('.js'):
                    # JavaScript에서 URL 추출 (최종 URL을 base로 사용)
                    js_urls = _extract_urls_from_js(response.text, final_url)

                    for url in js_urls:
                        normalized = _normalize_url(url)
                        if normalized and normalized not in visited:
                            if _is_same_domain(start_url, normalized):
                                # 정적 리소스가 아닌 경우에만 추가
                                if not _is_static_resource(normalized):
                                    to_visit.append(normalized)
                                    discovered_urls.add(normalized)

        except requests.exceptions.Timeout:
            print(f"[!] 타임아웃: {current_url}")
        except requests.exceptions.RequestException as e:
            print(f"[!] 요청 실패: {current_url} - {e}")
        except Exception as e:
            print(f"[!] 오류 발생: {current_url} - {e}")

    # 통계 출력
    print(f"\n[Crawler] 크롤링 완료")
    print(f"  총 방문: {len(visited)}개 URL")
    print(f"  발견된 엔드포인트: {len(discovered_urls)}개 URL")
    print(f"  필터링된 정적 리소스: {len(visited) - len(discovered_urls)}개")

    # 리스트로 변환하여 반환
    return sorted(list(discovered_urls))


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("사용법: python web_crawler.py <URL> [cookies] [headers]")
        sys.exit(1)

    url = sys.argv[1]
    cookies = sys.argv[2] if len(sys.argv) > 2 else ""
    headers = sys.argv[3] if len(sys.argv) > 3 else ""

    urls = crawl_website(url, cookies, headers)

    print(f"\n발견된 URL ({len(urls)}개):")
    for u in urls:
        print(f"  {u}")
