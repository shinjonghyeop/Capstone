import subprocess
import os
import shutil
from typing import List, Optional
from urllib.parse import urlparse
import re
import hashlib

# 기본 저장 디렉토리(이 파일 기준)
BASE_DIR = "wapiti_results"

def _load_urls_from_arg(args_list: List[str]) -> List[str]:
    """
    - 만약 args_list가 단일 항목이고 그 항목이 존재하는 파일이라면
      파일에서 URL들을 읽음 (빈 줄/주석 '#' 무시).
    - 아니면 args_list 자체를 URL 리스트로 반환.
    """
    if len(args_list) == 1 and os.path.isfile(args_list[0]):
        path = args_list[0]
        urls: List[str] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("#"):
                    continue
                urls.append(s)
        if not urls:
            raise SystemExit(f"[!] {path} 파일에서 유효한 URL을 찾을 수 없습니다.")
        return urls
    else:
        return args_list

def _normalize_headers(header_list: Optional[List[str]]) -> Optional[List[str]]:
    """
    입력: ["User-Agent: X", "Authorization: Bearer ..."] 또는 None
    반환: 동일한 리스트 (사용자 코드/외부 CLI에 따라 딕셔너리로 변환 가능)
    """
    if not header_list:
        return None
    # 간단 검증: ':' 포함하는지 확인
    normalized = []
    for h in header_list:
        if ":" not in h:
            print(f"[!] 경고: 헤더 포맷이 잘못되었습니다: {h} (예: 'Name: Value')")
            continue
        normalized.append(h.strip())
    return normalized if normalized else None

def _sanitize_host_for_filename(host: str) -> str:
    """
    파일명으로 안전하게 만들기: 영숫자, '-', '_'만 남기고 나머지는 '_'로 치환.
    (포트 포함이면 ':' -> '_' 처리)
    """
    # 빈값 처리
    if not host:
        return "unknown"
    # remove userinfo if present (user:pass@host)
    if "@" in host:
        host = host.split("@", 1)[-1]
    # replace non-alnum . : / 등
    return re.sub(r'[^A-Za-z0-9\-\_]', '_', host)

def _slug_from_url(parsed) -> str:
    """
    경로/쿼리에서 파일명에 쓸 수 있는 짧은 슬러그 생성.
    - 경로와 쿼리를 합쳐서 안전한 문자열로 변환
    - 완전히 비어있으면 URL 전체 해시 일부 사용
    """
    raw = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    slug = re.sub(r'[^A-Za-z0-9\-\_]', '_', raw).strip('_')
    if not slug:
        # 경로/쿼리가 거의 없으면 해시로 구분(고정 길이, 결정적)
        slug = hashlib.sha1((parsed.geturl()).encode("utf-8")).hexdigest()[:8]
    # 너무 길어지지 않도록 제한(윈도 경로 등 고려)
    return slug[:60]

def _unique_path(base_dir: str, stem: str, ext: str) -> str:
    """
    같은 파일명이 이미 있으면 -1, -2 ... 를 붙여 충돌 없이 경로 반환
    """
    path = os.path.join(base_dir, f"{stem}{ext}")
    if not os.path.exists(path):
        return path
    i = 1
    while True:
        candidate = os.path.join(base_dir, f"{stem}-{i}{ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1

def run_scan(
    targets: List[str],
    output_basename: str = "wapiti",   # 파일명 기본 (파일명만 — 디렉토리 아님)
    base_dir: str = BASE_DIR,          # 결과를 저장할 디렉토리
    cookies: Optional[str] = None,     # -C "name=value; ..."
    headers: Optional[List[str]] = None
) -> List[str]:
    """
    targets: URL 목록
    output_basename: 파일명 기본 (예: "wapiti") -> 결과: <base_dir>/<output_basename>_<host>.json
    base_dir: 결과 파일을 저장할 디렉토리 (없으면 생성)
    반환: 저장된 리포트 파일 경로들의 리스트 (파싱은 하지 않음)
    """
    if not targets:
        raise ValueError("targets는 빈 리스트일 수 없습니다.")

    # targets가 단일 파일명이라면 파일에서 URL 읽기
    if len(targets) == 1 and os.path.isfile(targets[0]):
        targets = _load_urls_from_arg(targets)

    if not shutil.which("wapiti"):
        raise FileNotFoundError("'wapiti' 명령을 찾을 수 없습니다. PATH를 확인하세요.")

    # 결과 디렉토리 생성
    os.makedirs(base_dir, exist_ok=True)

    saved_files: List[str] = []

    for url in targets:
        try:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path or "target"
        except Exception:
            host = "target"

        safe_host = _sanitize_host_for_filename(host)
        # 파일명: <basename>_<safe_host>.json
        slug = _slug_from_url(parsed)
        filename =f"{output_basename}_{safe_host}_{slug}"
        report_path = _unique_path(base_dir, filename, ".json")

        # Wapiti 명령 조립
        cmd = ["wapiti", "-u", url, "-f", "json", "-o", report_path]

        if cookies:
            cmd += ["-C", cookies]

        headers = _normalize_headers(headers)
        if headers:
            for h in headers:
                # 각 헤더를 -H "Name: Value" 형태로 추가
                cmd += ["-H", h]

        print("[*] 실행:", " ".join(cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout= None)
        except Exception as e:
            print(f"[!] 실행 오류: {e}")
            continue

        # 파일이 실제로 생성되었는지 확인
        if os.path.exists(report_path):
            saved_files.append(report_path)
            print(f"[+] 리포트 저장됨: {report_path}")
        else:
            # 파일이 없으면 stdout/stderr를 파일로 남기고 그 경로 반환할 수도 있음.
            # 여기서는 실패 로그 메시지 출력만 함.
            print(f"[!] 리포트 파일이 생성되지 않았습니다: {report_path}")
            if proc.stdout:
                print("[wapiti stdout]\n", proc.stdout.strip())
            if proc.stderr:
                print("[wapiti stderr]\n", proc.stderr.strip())

    return saved_files