"""
merged_results의 JSON을 대상으로 Gemini API로 취약점별 train 데이터셋 생성.
하드코딩 1회용 스크립트 (utils 모듈 미사용).
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

try:
    import google.generativeai as genai
except ImportError as e:
    print(f"[ERROR] 필수 패키지 누락: {e}")
    print("pip3 install google-generativeai 를 실행하세요.")
    raise


# ===== 하드코딩 설정 =====
GEMINI_API_KEY = "AIzaSyDuIOEAUsmsesLHpQ-8gBoEQMIpBDa6YKk"
MODEL_NAME = "gemini-3-flash-preview"
TEMPERATURE = 0.7
MAX_RETRIES = 3
RETRY_DELAY = 5
MIN_EVIDENCE_LENGTH = 6
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

LOCAL_INSTRUCTION = (
    "다음 입력으로 Markdown 블록을 생성하라.\n"
    "규칙: Markdown만, 헤딩은 ##만, 이모지/표 금지, 한 줄 불릿.\n"
    "코드/요청/응답/페이로드/curl/로그 등 코드성 텍스트는 반드시 코드블럭으로 감쌀 것.\n"
    "출력은 한국어로 작성.\n"
    "모든 항목(End-Point/영향/설명/근거/대응/조치)을 반드시 출력.\n"
    "근거는 증거/재현에서만 요약, 부족 시 '-' 사용.\n"
    "첫 줄은 반드시 '## {제목}' 형식으로 시작하고 서두 문장 금지.\n"
    "출력 형식:\n"
    "## {제목}\n"
    "- **End-Point**: \n"
    "- **영향**: \n"
    "- **설명**: \n"
    "- **근거**: \n"
    "- **대응**: \n"
    "- **조치**: \n"
)

BASE_DIR = Path(__file__).resolve().parents[1]
INPUT_DIR = BASE_DIR / "merged_results"
OUTPUT_ROOT = BASE_DIR / "train"
INCLUDE_LOW = True
SKIP_EXISTING = True


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _extract_timestamp_from_filename(path: str) -> str | None:
    name = os.path.basename(path)
    match = re.search(r"_(\d{8}_\d{6})\.json$", name)
    if match:
        return match.group(1)
    return None


def _safe_target(target: str) -> str:
    return target.replace(":", "_").replace("/", "_").replace("\\", "_")


def is_verified_finding(finding: dict) -> bool:
    evidence = _normalize_text(finding.get("evidence"))
    curl_command = _normalize_text(finding.get("curlCommand"))
    response = _normalize_text(finding.get("response"))
    request = _normalize_text(finding.get("request"))
    return bool(
        curl_command
        or response
        or request
        or (len(evidence) >= MIN_EVIDENCE_LENGTH)
    )


def filter_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    verified = []
    excluded = []
    for finding in findings:
        if is_verified_finding(finding):
            verified.append(finding)
        else:
            excluded.append(finding)
    return verified, excluded


def _severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: _severity_rank(_normalize_text(f.get("severity", "info")).lower())
    )


def _format_endpoints(endpoints: list[str], max_items: int = 2) -> str:
    cleaned = []
    seen = set()
    for endpoint in endpoints:
        value = _normalize_text(endpoint)
        if not value or value in seen:
            continue
        seen.add(value)
        cleaned.append(value)

    if not cleaned:
        return "N/A"
    if len(cleaned) <= max_items:
        return ", ".join(cleaned)
    return f"{cleaned[0]}, {cleaned[1]} 외 {len(cleaned) - max_items}개"


def group_findings(findings: list[dict]) -> list[dict]:
    grouped = {}
    for finding in findings:
        title = _normalize_text(finding.get("title", "Unknown"))
        severity = _normalize_text(finding.get("severity", "info")).lower()
        cve = _normalize_text(finding.get("cve"))
        category = _normalize_text(finding.get("category"))
        tool = _normalize_text(finding.get("tool"))
        key = (tool, title, severity, cve, category)

        if key not in grouped:
            grouped[key] = {
                "tool": tool,
                "title": title,
                "severity": severity or "info",
                "cve": cve,
                "category": category,
                "description": _normalize_text(finding.get("description", "")),
                "impact": _normalize_text(finding.get("impact", "")),
                "recommendation": _normalize_text(finding.get("recommendation", "")),
                "evidence": _normalize_text(finding.get("evidence", "")),
                "curlCommand": _normalize_text(finding.get("curlCommand", "")),
                "endpoints": []
            }

        grouped[key]["endpoints"].append(
            _normalize_text(finding.get("endpoint")) or _normalize_text(finding.get("fullUrl"))
        )

        if not grouped[key]["evidence"]:
            grouped[key]["evidence"] = _normalize_text(finding.get("evidence", ""))
        if not grouped[key]["curlCommand"]:
            grouped[key]["curlCommand"] = _normalize_text(finding.get("curlCommand", ""))
        if not grouped[key]["description"]:
            grouped[key]["description"] = _normalize_text(finding.get("description", ""))
        if not grouped[key]["impact"]:
            grouped[key]["impact"] = _normalize_text(finding.get("impact", ""))
        if not grouped[key]["recommendation"]:
            grouped[key]["recommendation"] = _normalize_text(finding.get("recommendation", ""))

    return list(grouped.values())


def build_finding_input_block(finding: dict) -> str:
    title = _normalize_text(finding.get("title", "Unknown"))
    raw_severity = _normalize_text(finding.get("severity", "info")).lower()
    if raw_severity == "low":
        raw_severity = "medium"
    severity = raw_severity.upper()
    category = _normalize_text(finding.get("category", "N/A"))
    endpoints = _format_endpoints(finding.get("endpoints", []))
    cve = _normalize_text(finding.get("cve")) or "N/A"
    description = _normalize_text(finding.get("description", ""))
    impact = _normalize_text(finding.get("impact", ""))
    evidence = _normalize_text(finding.get("evidence", ""))
    curl_command = _normalize_text(finding.get("curlCommand", ""))
    recommendation = _normalize_text(finding.get("recommendation", ""))

    return (
        "입력:\n"
        f"제목: {title}\n"
        f"심각도: {severity}\n"
        f"카테고리: {category}\n"
        f"엔드포인트: {endpoints}\n"
        f"CVE: {cve}\n"
        f"설명: {description}\n"
        f"영향: {impact}\n"
        f"증거: {evidence}\n"
        f"재현: {curl_command}\n"
        f"대응/조치 힌트: {recommendation}\n"
    )


def create_finding_prompt(finding: dict) -> str:
    input_block = build_finding_input_block(finding)
    return f"{LOCAL_INSTRUCTION}\n{input_block}\n"


def call_gemini_api(prompt: str, api_key: str) -> str:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(MODEL_NAME)

    for attempt in range(MAX_RETRIES):
        try:
            print(f"[+] Gemini API 호출 중... (시도 {attempt + 1}/{MAX_RETRIES})")
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": TEMPERATURE,
                    "max_output_tokens": 16384,
                }
            )
            if not response.text:
                raise Exception("API 응답이 비어있습니다.")
            return response.text
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "quota" in error_msg.lower() or "rate" in error_msg.lower():
                if attempt < MAX_RETRIES - 1:
                    wait_time = RETRY_DELAY * (attempt + 1)
                    print(f"[!] Rate limit 발생. {wait_time}초 후 재시도...")
                    time.sleep(wait_time)
                    continue
                raise Exception(f"Rate limit 초과: {error_msg}")
            print(f"[ERROR] API 호출 실패: {error_msg}")
            raise Exception(f"Gemini API 오류: {error_msg}")

    raise Exception("최대 재시도 횟수 초과")


def load_scan_results(json_path: str) -> dict:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    required_keys = ["target", "findings"]
    for key in required_keys:
        if key not in data:
            raise ValueError(f"필수 키 누락: {key}")
    if not isinstance(data["findings"], list):
        raise ValueError("'findings'는 리스트여야 합니다.")
    return data


def _write_pair(input_path: Path, output_path: Path, finding: dict, output_text: str) -> None:
    input_text = build_finding_input_block(finding).strip()
    with open(input_path, "w", encoding="utf-8") as f:
        f.write(input_text)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output_text.strip())


def main() -> None:
    input_dir = OUTPUT_ROOT / "input"
    output_dir = OUTPUT_ROOT / "output"
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY 상수가 설정되지 않았습니다.")
    api_key = GEMINI_API_KEY
    json_files = sorted(INPUT_DIR.glob("*.json"))

    total_saved = 0
    for json_path in json_files:
        data = load_scan_results(str(json_path))
        verified_findings, _ = filter_findings(data.get("findings", []))
        filtered = [
            finding for finding in verified_findings
            if INCLUDE_LOW or _normalize_text(finding.get("severity", "info")).lower() != "low"
        ]
        grouped_findings = group_findings(sort_findings(filtered))
        if not grouped_findings:
            continue

        target = data.get("target", "unknown")
        safe_target = _safe_target(str(target or "unknown"))
        timestamp = _extract_timestamp_from_filename(str(json_path))
        if not timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for index, finding in enumerate(grouped_findings, start=1):
            pair_id = f"{safe_target}_{timestamp}_{index:03d}"
            input_dest = input_dir / f"{pair_id}.txt"
            output_dest = output_dir / f"{pair_id}.md"

            if SKIP_EXISTING and input_dest.exists() and output_dest.exists():
                continue

            prompt = create_finding_prompt(finding)
            output_text = call_gemini_api(prompt, api_key)
            _write_pair(input_dest, output_dest, finding, output_text)
            total_saved += 1

    print(f"[+] 생성 완료: {total_saved}쌍")


if __name__ == "__main__":
    main()
