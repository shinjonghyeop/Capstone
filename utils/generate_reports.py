"""
AI 보안 진단 보고서 생성 모듈

Google Gemini API를 활용하여 취약점 스캔 결과를 분석하고
마크다운 형식의 포괄적인 보안 진단 보고서를 생성합니다.
"""

import json
import os
import re
import shutil
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import time
from utils.local_model import generate_with_local_model

try:
    import google.generativeai as genai
    from dotenv import load_dotenv
except ImportError as e:
    print(f"[ERROR] 필수 패키지 누락: {e}")
    print("pip3 install google-generativeai python-dotenv 를 실행하세요.")
    raise


# 설정
TEMPERATURE = 0.7
MAX_RETRIES = 3
RETRY_DELAY = 5
MIN_EVIDENCE_LENGTH = 6
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
DEFAULT_PROVIDER = "Gemini"
ENV_PROVIDER = "AI_PROVIDER"
ENV_GEMINI_MODEL = "GEMINI_MODEL"
ENV_LOCAL_MODEL = "LOCAL_MODEL_NAME"


def get_api_key() -> str:
    """
    환경변수에서 GEMINI_API_KEY 로드

    Returns:
        str: API 키

    Raises:
        ValueError: API 키가 설정되지 않았거나 유효하지 않은 경우
    """
    load_dotenv()
    api_key = os.getenv('GEMINI_API_KEY')

    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY가 설정되지 않았습니다. "
            ".env 파일에 실제 API 키를 입력하세요. "
            "API 키 발급: https://makersuite.google.com/app/apikey"
        )

    return api_key


def get_provider() -> str:
    """환경변수에서 AI_PROVIDER 로드"""
    load_dotenv()
    provider = os.getenv(ENV_PROVIDER, DEFAULT_PROVIDER).strip().lower()
    if provider not in ("Gemini", "Hacklipse"):
        raise ValueError(f"AI_PROVIDER 값이 올바르지 않습니다: {provider}")
    return provider


def get_gemini_model_name() -> str:
    load_dotenv()
    return os.getenv(ENV_GEMINI_MODEL, MODEL_NAME).strip() or MODEL_NAME


def get_local_model_name() -> str:
    load_dotenv()
    model_name = os.getenv(ENV_LOCAL_MODEL, "").strip()
    if not model_name:
        raise ValueError("LOCAL_MODEL_NAME이 설정되지 않았습니다.")
    return model_name


def load_scan_results(json_path: str) -> Dict:
    """
    JSON 파일 로드 및 구조 검증

    Args:
        json_path: 스캔 결과 JSON 파일 경로

    Returns:
        Dict: 파싱된 스캔 결과

    Raises:
        ValueError: JSON 파일이 잘못되었거나 필수 키가 없는 경우
        FileNotFoundError: 파일이 존재하지 않는 경우
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 필수 키 검증
        required_keys = ['target', 'findings']
        for key in required_keys:
            if key not in data:
                raise ValueError(f"필수 키 누락: {key}")

        if not isinstance(data['findings'], list):
            raise ValueError("'findings'는 리스트여야 합니다.")

        return data

    except json.JSONDecodeError as e:
        raise ValueError(f"JSON 파싱 오류: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {json_path}")


def analyze_findings(findings: List[Dict]) -> Dict:
    """
    취약점 통계 분석

    Args:
        findings: 취약점 리스트

    Returns:
        Dict: 분석 결과 {
            "total_count": int,
            "by_severity": {"critical": N, ...},
            "by_category": {"XSS": N, ...},
            "by_endpoint": {"/path": N, ...},
            "critical_high_findings": List[Dict],
            "risk_score": float
        }
    """
    analysis = {
        "total_count": len(findings),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "by_category": {},
        "by_endpoint": {},
        "critical_high_findings": [],
        "risk_score": 0
    }

    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        category = finding.get('category', 'Unknown')
        endpoint = finding.get('endpoint', 'Unknown')

        # 심각도별 카운트
        if severity in analysis['by_severity']:
            analysis['by_severity'][severity] += 1

        # 카테고리별 카운트
        analysis['by_category'][category] = analysis['by_category'].get(category, 0) + 1

        # 엔드포인트별 카운트
        analysis['by_endpoint'][endpoint] = analysis['by_endpoint'].get(endpoint, 0) + 1

        # Critical/High 취약점 별도 저장
        if severity in ['critical', 'high']:
            analysis['critical_high_findings'].append(finding)

    # 위험 점수 계산: (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1)
    analysis['risk_score'] = (
        analysis['by_severity']['critical'] * 10 +
        analysis['by_severity']['high'] * 5 +
        analysis['by_severity']['medium'] * 2 +
        analysis['by_severity']['low'] * 1
    )

    return analysis


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def is_verified_finding(finding: Dict) -> bool:
    """
    보수적으로 근거가 있는 항목만 보고서에 포함한다.
    """
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


def filter_findings(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
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


def sort_findings(findings: List[Dict]) -> List[Dict]:
    return sorted(
        findings,
        key=lambda f: _severity_rank(_normalize_text(f.get("severity", "info")).lower())
    )


def _format_endpoints(endpoints: List[str], max_items: int = 2) -> str:
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


def group_findings(findings: List[Dict]) -> List[Dict]:
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


def _escape_table_cell(value: object) -> str:
    text = _normalize_text(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _extract_timestamp_from_filename(path: str) -> Optional[str]:
    name = os.path.basename(path)
    match = re.search(r'_(\d{8}_\d{6})\.json$', name)
    if match:
        return match.group(1)
    return None


def build_summary_table(findings: List[Dict]) -> str:
    lines = [
        "| 취약점 | 심각도 | 주요 엔드포인트 | 영향 | CVE |",
        "|---|---|---|---|---|",
    ]
    grouped = group_findings(findings)

    for finding in grouped:
        severity = _normalize_text(finding.get("severity", "info")).lower()
        severity_label = severity.capitalize() if severity else "Info"
        title = finding.get("title", "Unknown")
        endpoints = _format_endpoints(finding.get("endpoints", []))
        impact = _normalize_text(finding.get("impact"))
        impact = impact[:80] + "..." if len(impact) > 80 else impact
        cve = _normalize_text(finding.get("cve")) or "N/A"

        lines.append(
            "| {title} | {severity} | {endpoints} | {impact} | {cve} |".format(
                title=_escape_table_cell(title),
                severity=_escape_table_cell(severity_label),
                endpoints=_escape_table_cell(endpoints),
                impact=_escape_table_cell(impact or "N/A"),
                cve=_escape_table_cell(cve)
            )
        )

    return "\n".join(lines)


def build_category_table(category_counts: Dict[str, int], max_items: int = 10) -> str:
    lines = [
        "| 카테고리 | 개수 |",
        "|---|---|",
    ]
    items = sorted(
        category_counts.items(),
        key=lambda item: (-item[1], item[0])
    )
    for category, count in items[:max_items]:
        lines.append(f"| {_escape_table_cell(category)} | {count} |")
    if len(lines) == 2:
        lines.append("| 없음 | 0 |")
    return "\n".join(lines)


def build_endpoint_table(endpoint_counts: Dict[str, int], max_items: int = 10) -> str:
    lines = [
        "| 엔드포인트 | 개수 |",
        "|---|---|",
    ]
    items = sorted(
        endpoint_counts.items(),
        key=lambda item: (-item[1], item[0])
    )
    for endpoint, count in items[:max_items]:
        lines.append(f"| {_escape_table_cell(endpoint)} | {count} |")
    if len(lines) == 2:
        lines.append("| 없음 | 0 |")
    return "\n".join(lines)


def create_prompt(data: Dict, analysis: Dict) -> str:
    """
    Gemini API용 프롬프트 생성

    Args:
        data: 스캔 결과 데이터
        analysis: 분석 결과

    Returns:
        str: 프롬프트 문자열
    """
    target = data.get('target', 'Unknown')
    started_at = data.get('startedAt', 'Unknown')
    finished_at = data.get('finishedAt', 'Unknown')
    tools = ', '.join(data.get('tools', []))

    all_findings = data.get('findings', [])
    report_findings = [
        finding for finding in all_findings
        if _normalize_text(finding.get("severity", "info")).lower() != "low"
    ]
    report_analysis = analyze_findings(report_findings)
    full_analysis = analyze_findings(all_findings)

    total_count = report_analysis['total_count']
    by_severity = report_analysis['by_severity']

    # 주요 카테고리 (상위 5개)
    top_categories = sorted(
        report_analysis['by_category'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]
    top_categories_str = ', '.join([f"{cat} ({count}개)" for cat, count in top_categories])

    risk_score = report_analysis['risk_score']
    sorted_findings = sort_findings(report_findings)
    summary_table = build_summary_table(sorted_findings)
    grouped_findings = group_findings(sorted_findings)
    severity_items = []
    for level, label in [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("info", "Info")]:
        count = by_severity.get(level, 0)
        if count > 0:
            severity_items.append(f"{label}: {count}")
    severity_summary = ", ".join(severity_items) if severity_items else "없음"
    full_total_count = full_analysis['total_count']
    full_by_severity = full_analysis['by_severity']
    category_table = build_category_table(full_analysis['by_category'])
    endpoint_table = build_endpoint_table(full_analysis['by_endpoint'])
    severity_rows = []
    for level, label in [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info")
    ]:
        count = full_by_severity.get(level, 0)
        if count == 0:
            continue
        percent = round(count / max(full_total_count, 1) * 100, 1)
        severity_rows.append(f"| {label} | {count} | {percent}% |")
    if not severity_rows and full_total_count == 0:
        severity_rows.append("| Info | 0 | 0.0% |")
    severity_table = "\n".join(severity_rows)

    # 대용량 파일 처리: findings가 100개 이상이면 요약
    if len(grouped_findings) > 100:
        # Critical/High만 상세히
        critical_high = [
            f for f in grouped_findings
            if _normalize_text(f.get("severity", "")).lower() in ["critical", "high"]
        ]

        # Medium/Info는 카테고리별로 샘플만
        other_findings = [
            f for f in grouped_findings
            if _normalize_text(f.get("severity", "")).lower() not in ["critical", "high"]
        ]

        findings_detail = "Critical 및 High 위험 취약점 (전체)\n\n"
        for i, finding in enumerate(critical_high[:30], 1):  # 최대 30개
            findings_detail += f"{i}) [{finding.get('severity', 'unknown')}] {finding.get('title', 'Unknown')}\n"
            findings_detail += f"- 카테고리: {finding.get('category', 'N/A')}\n"
            findings_detail += f"- 엔드포인트: {_format_endpoints(finding.get('endpoints', []))}\n"
            findings_detail += f"- CVE: {finding.get('cve', 'N/A')}\n"
            findings_detail += f"- 설명: {finding.get('description', 'N/A')[:200]}...\n"
            findings_detail += f"- 영향: {finding.get('impact', 'N/A')[:200]}...\n"
            if finding.get('evidence'):
                findings_detail += f"- 증거: {str(finding.get('evidence', ''))[:200]}...\n"
            if finding.get('curlCommand'):
                findings_detail += f"- 재현: `{finding.get('curlCommand', '')[:200]}...`\n"
            findings_detail += "\n"

        findings_detail += f"\nMedium/Info 취약점 (카테고리별 요약, 총 {len(other_findings)}개)\n\n"

        # 카테고리별로 그룹화
        by_cat_samples = {}
        for finding in other_findings:
            cat = finding.get('category', 'Unknown')
            if cat not in by_cat_samples:
                by_cat_samples[cat] = []
            if len(by_cat_samples[cat]) < 3:  # 카테고리당 최대 3개 샘플
                by_cat_samples[cat].append(finding)

        for cat, samples in by_cat_samples.items():
            count = report_analysis['by_category'].get(cat, 0)
            findings_detail += f"{cat} ({count}개)\n"
            for sample in samples:
                findings_detail += f"- {sample.get('title', 'Unknown')} ({sample.get('severity', 'unknown')})\n"
            findings_detail += "\n"
    else:
        # 모든 findings 포함
        findings_detail = ""
        for i, finding in enumerate(grouped_findings, 1):
            findings_detail += f"{i}) [{finding.get('severity', 'unknown')}] {finding.get('title', 'Unknown')}\n"
            findings_detail += f"- 카테고리: {finding.get('category', 'N/A')}\n"
            findings_detail += f"- 엔드포인트: {_format_endpoints(finding.get('endpoints', []))}\n"
            findings_detail += f"- CVE: {finding.get('cve', 'N/A')}\n"
            findings_detail += f"- 설명: {finding.get('description', 'N/A')[:300]}...\n"
            findings_detail += f"- 영향: {finding.get('impact', 'N/A')[:300]}...\n"
            if finding.get('evidence'):
                findings_detail += f"- 증거: {str(finding.get('evidence', ''))[:200]}...\n"
            if finding.get('curlCommand'):
                findings_detail += f"- 재현: `{finding.get('curlCommand', '')[:200]}...`\n"
            findings_detail += "\n"

    prompt = f"""당신은 보안 전문가입니다. 아래 웹 취약점 스캔 결과를 분석하여 보고서를 작성해주세요.

# 스캔 정보
- 대상: {target}
- 스캔 시작: {started_at}
- 스캔 완료: {finished_at}
- 사용 도구: {tools}

# 통계 요약
- 총 취약점: {total_count}개
- 심각도 분포: {severity_summary}
- 주요 카테고리: {top_categories_str}
- 위험 점수: {risk_score}/100

# 상세 취약점 입력
{findings_detail}

---

작성 규칙:
- 출력은 Markdown만. HTML 금지.
- 헤딩은 #, ##만 사용. ### 금지.
- 이모지 금지.
- 긴 문단 금지, 모든 설명은 한 줄 불릿.
- 섹션당 최대 6개 불릿, 한 줄 90자 이하.
- 표 섹션은 유지하고 표 형식으로 작성.
- 입력에 없는 내용은 작성하지 말 것.
- 근거가 불충분하다고 판단되는 항목은 보고서에 포함하지 말 것.
- 근거는 입력된 "증거/재현" 내용에서만 요약해서 작성.
- 결과 요약 표는 아래 제공된 표를 그대로 출력하고 순서를 바꾸지 말 것.
- 심각도 그룹은 해당 항목이 있을 때만 출력할 것.
- 동일 취약점은 하나로 묶고 End-Point에 여러 엔드포인트를 쉼표로 나열할 것.
- 심각도 제목은 반드시 인라인 코드로 감쌀 것 (예: # `CRITICAL`).
- Low 취약점은 보고서에서 제외할 것.
- 통계 표는 아래 제공된 표를 그대로 출력하고 순서를 바꾸지 말 것.

형식(절대 변경 금지):

# 보안 진단 보고서

## 결과 요약
{summary_table}

## 주요 취약점
심각도별로 그룹화하여 작성 (해당 심각도에 항목이 있을 때만 표시).
형식 예시:
# `CRITICAL`
## [취약점명]
- **End-Point**: endpoint1, endpoint2 외 N개
- **영향**: 2줄 이하
- **설명**: 2줄 이하
- **근거**: 2줄 이하
- **대응**: 2줄 이하
- **조치**: 3줄 이하
(다른 심각도도 동일 형식으로 반복)

## 통계
| 심각도 | 개수 | 비율 |
|---|---|---|
{severity_table}

{category_table}

{endpoint_table}

"""

    return prompt


def call_gemini_api(prompt: str, api_key: str) -> str:
    """
    Google Gemini API 호출

    Args:
        prompt: API에 전송할 프롬프트
        api_key: Gemini API 키

    Returns:
        str: 생성된 마크다운 보고서

    Raises:
        Exception: API 호출 실패 시
    """
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(get_gemini_model_name())

    def _generate_with_retries(prompt_text: str) -> str:
        for attempt in range(MAX_RETRIES):
            try:
                print(f"[+] Gemini API 호출 중... (시도 {attempt + 1}/{MAX_RETRIES})")

                response = model.generate_content(
                    prompt_text,
                    generation_config={
                        'temperature': TEMPERATURE,
                        'max_output_tokens': 16384,
                    }
                )

                if not response.text:
                    raise Exception("API 응답이 비어있습니다.")

                return response.text

            except Exception as e:
                error_msg = str(e)

                # Rate limit 에러 처리
                if '429' in error_msg or 'quota' in error_msg.lower() or 'rate' in error_msg.lower():
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (attempt + 1)
                        print(f"[!] Rate limit 발생. {wait_time}초 후 재시도...")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"Rate limit 초과: {error_msg}")

                # 기타 에러
                print(f"[ERROR] API 호출 실패: {error_msg}")
                raise Exception(f"Gemini API 오류: {error_msg}")

        raise Exception("최대 재시도 횟수 초과")
    text = _generate_with_retries(prompt)
    print(f"[+] 보고서 생성 완료 ({len(text)} 문자)")
    return text


def call_local_model(prompt: str, model_name: str) -> str:
    """로컬 모델 호출"""
    text = generate_with_local_model(
        prompt=prompt,
        model_name=model_name,
        temperature=TEMPERATURE,
        max_new_tokens=16384
    )
    print(f"[+] 보고서 생성 완료 ({len(text)} 문자)")
    return text


def save_report(content: str, target: str, output_dir: str, timestamp: Optional[str] = None) -> str:
    """
    보고서를 파일로 저장

    Args:
        content: 마크다운 보고서 내용
        target: 스캔 대상 (파일명에 사용)
        output_dir: 출력 디렉토리

    Returns:
        str: 저장된 파일의 전체 경로
    """
    # reports 디렉토리 생성
    os.makedirs(output_dir, exist_ok=True)

    # 파일명 생성: {target}_report_{timestamp}.md
    # target에서 특수문자 제거 (파일명으로 사용 불가능한 문자)
    safe_target = target.replace(':', '_').replace('/', '_').replace('\\', '_')
    if not timestamp:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{safe_target}_report_{timestamp}.md"

    filepath = os.path.join(output_dir, filename)

    # 파일 저장
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[+] 보고서 저장: {filepath}")
    return filepath


def save_training_pair(
    input_json_path: str,
    markdown: str,
    target: str,
    timestamp: str,
    train_root: str = "train"
) -> Tuple[str, str]:
    input_dir = os.path.join(train_root, "input")
    output_dir = os.path.join(train_root, "output")
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    safe_target = target.replace(':', '_').replace('/', '_').replace('\\', '_')
    pair_id = f"{safe_target}_{timestamp}"
    input_dest = os.path.join(input_dir, f"{pair_id}_input.json")
    output_dest = os.path.join(output_dir, f"{pair_id}_output.md")

    shutil.copyfile(input_json_path, input_dest)
    with open(output_dest, "w", encoding="utf-8") as f:
        f.write(markdown)

    return input_dest, output_dest


def generate_report(json_file_path: str, output_dir: str = "reports") -> str:
    """
    JSON 파일로부터 AI 보고서 생성 (메인 함수)

    Args:
        json_file_path: 스캔 결과 JSON 파일 경로
        output_dir: 보고서 저장 디렉토리 (기본: "reports")

    Returns:
        str: 생성된 보고서 파일 경로

    Raises:
        ValueError: 입력 파일이 잘못되었거나 API 키가 없는 경우
        Exception: 보고서 생성 중 오류 발생 시
    """
    print(f"\n{'='*60}")
    print(f"AI 보안 진단 보고서 생성 시작")
    print(f"{'='*60}\n")

    try:
        # 1. 제공자 선택
        print("[1/6] AI 제공자 확인 중...")
        provider = get_provider()
        print(f"[+] AI 제공자: {provider}")

        # 2. JSON 파일 로드
        print(f"\n[2/6] 스캔 결과 로드 중... ({json_file_path})")
        data = load_scan_results(json_file_path)
        loaded_findings = data.get('findings', [])
        print(f"[+] {len(loaded_findings)}개 취약점 로드 완료")

        verified_findings, excluded_findings = filter_findings(loaded_findings)
        data['findings'] = verified_findings
        print(f"[+] 근거 기반 필터링 완료: 포함 {len(verified_findings)}개, 제외 {len(excluded_findings)}개")

        # 3. 통계 분석
        print("\n[3/6] 취약점 분석 중...")
        analysis = analyze_findings(data.get('findings', []))
        print(f"[+] 분석 완료:")
        print(f"    - 총 {analysis['total_count']}개 취약점")
        print(f"    - Critical: {analysis['by_severity']['critical']}, High: {analysis['by_severity']['high']}")
        print(f"    - 위험 점수: {analysis['risk_score']}/100")

        # 4. 프롬프트 생성
        print("\n[4/6] 프롬프트 생성 중...")
        prompt = create_prompt(data, analysis)
        print(f"[+] 프롬프트 생성 완료 ({len(prompt)} 문자)")

        # 5. AI 보고서 생성
        print("\n[5/6] AI 보고서 생성 중...")
        if provider == "Gemini":
            print("[*] Gemini API 사용")
            api_key = get_api_key()
            markdown = call_gemini_api(prompt, api_key)
        else:
            print("[*] 로컬 모델 사용")
            model_name = get_local_model_name()
            markdown = call_local_model(prompt, model_name)

        # 6. 파일 저장
        print("\n[6/6] 보고서 저장 중...")
        target = data.get('target', 'unknown')
        timestamp = _extract_timestamp_from_filename(json_file_path)
        if not timestamp:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = save_report(markdown, target, output_dir, timestamp=timestamp)
        try:
            train_input_path, train_output_path = save_training_pair(
                json_file_path,
                markdown,
                target,
                timestamp
            )
            print(f"[+] 훈련 데이터 저장: {train_input_path}")
            print(f"[+] 훈련 데이터 저장: {train_output_path}")
        except Exception as e:
            print(f"[!] 훈련 데이터 저장 실패: {e}")

        print(f"\n{'='*60}")
        print(f"[+] 보고서 생성 완료!")
        print(f"{'='*60}\n")

        return report_path

    except Exception as e:
        print(f"\n{'='*60}")
        print(f"[!] 오류 발생: {e}")
        print(f"{'='*60}\n")
        raise


# 테스트용 메인 함수
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("사용법: python generate_reports.py <json_file_path> [output_dir]")
        print("예: python generate_reports.py merged_results/localhost_9991.json reports")
        sys.exit(1)

    json_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "reports"

    try:
        report_path = generate_report(json_path, output_dir)
        print(f"\n생성된 보고서: {report_path}")
    except Exception as e:
        print(f"\n오류: {e}")
        sys.exit(1)
