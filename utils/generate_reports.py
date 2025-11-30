"""
AI 보안 진단 보고서 생성 모듈

Google Gemini API를 활용하여 취약점 스캔 결과를 분석하고
마크다운 형식의 포괄적인 보안 진단 보고서를 생성합니다.
"""

import json
import os
from datetime import datetime
from typing import Dict, List
import time

try:
    import google.generativeai as genai
    from dotenv import load_dotenv
except ImportError as e:
    print(f"[ERROR] 필수 패키지 누락: {e}")
    print("pip3 install google-generativeai python-dotenv 를 실행하세요.")
    raise


# 설정
MODEL_NAME = "gemini-2.5-flash"  # gemini-2.5-flash: 빠르고 효율적
TEMPERATURE = 0.7
MAX_RETRIES = 3
RETRY_DELAY = 5


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

    total_count = analysis['total_count']
    by_severity = analysis['by_severity']

    # 주요 카테고리 (상위 5개)
    top_categories = sorted(
        analysis['by_category'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]
    top_categories_str = ', '.join([f"{cat} ({count}개)" for cat, count in top_categories])

    risk_score = analysis['risk_score']

    # 대용량 파일 처리: findings가 100개 이상이면 요약
    if len(data['findings']) > 100:
        # Critical/High만 상세히
        critical_high = analysis['critical_high_findings']

        # Medium/Low/Info는 카테고리별로 샘플만
        other_findings = [f for f in data['findings'] if f.get('severity', '').lower() not in ['critical', 'high']]

        findings_detail = "## Critical 및 High 위험 취약점 (전체)\n\n"
        for i, finding in enumerate(critical_high[:30], 1):  # 최대 30개
            findings_detail += f"### {i}. [{finding.get('severity', 'unknown')}] {finding.get('title', 'Unknown')}\n"
            findings_detail += f"- ID: {finding.get('id', 'N/A')}\n"
            findings_detail += f"- 카테고리: {finding.get('category', 'N/A')}\n"
            findings_detail += f"- 엔드포인트: {finding.get('endpoint', 'N/A')}\n"
            findings_detail += f"- CVE: {finding.get('cve', 'N/A')}\n"
            findings_detail += f"- 설명: {finding.get('description', 'N/A')[:200]}...\n"
            findings_detail += f"- 영향: {finding.get('impact', 'N/A')[:200]}...\n\n"

        findings_detail += f"\n## Medium/Low/Info 취약점 (카테고리별 요약, 총 {len(other_findings)}개)\n\n"

        # 카테고리별로 그룹화
        by_cat_samples = {}
        for finding in other_findings:
            cat = finding.get('category', 'Unknown')
            if cat not in by_cat_samples:
                by_cat_samples[cat] = []
            if len(by_cat_samples[cat]) < 3:  # 카테고리당 최대 3개 샘플
                by_cat_samples[cat].append(finding)

        for cat, samples in by_cat_samples.items():
            count = analysis['by_category'].get(cat, 0)
            findings_detail += f"### {cat} ({count}개)\n"
            for sample in samples:
                findings_detail += f"- {sample.get('title', 'Unknown')} ({sample.get('severity', 'unknown')})\n"
            findings_detail += "\n"
    else:
        # 모든 findings 포함
        findings_detail = ""
        for i, finding in enumerate(data['findings'], 1):
            findings_detail += f"### {i}. [{finding.get('severity', 'unknown')}] {finding.get('title', 'Unknown')}\n"
            findings_detail += f"- ID: {finding.get('id', 'N/A')}\n"
            findings_detail += f"- 카테고리: {finding.get('category', 'N/A')}\n"
            findings_detail += f"- 엔드포인트: {finding.get('endpoint', 'N/A')}\n"
            findings_detail += f"- CVE: {finding.get('cve', 'N/A')}\n"
            findings_detail += f"- 설명: {finding.get('description', 'N/A')[:300]}...\n"
            findings_detail += f"- 영향: {finding.get('impact', 'N/A')[:300]}...\n"
            if finding.get('curlCommand'):
                findings_detail += f"- 재현: `{finding.get('curlCommand', '')[:200]}...`\n"
            findings_detail += "\n"

    prompt = f"""당신은 보안 전문가입니다. 아래 웹 취약점 스캔 결과를 분석하여 포괄적인 보안 진단 보고서를 작성해주세요.

# 스캔 정보
- 대상: {target}
- 스캔 시작: {started_at}
- 스캔 완료: {finished_at}
- 사용 도구: {tools}

# 통계 요약
- 총 취약점: {total_count}개
- Critical: {by_severity['critical']}, High: {by_severity['high']}, Medium: {by_severity['medium']}, Low: {by_severity['low']}, Info: {by_severity['info']}
- 주요 카테고리: {top_categories_str}
- 위험 점수: {risk_score}/100

# 상세 취약점 목록
{findings_detail}

---

아래 형식으로 마크다운 보고서를 작성해주세요:

# 보안 진단 보고서

## 1. 경영진 요약 (Executive Summary)

**목적**: 비기술직 경영진을 위한 핵심 요약

- **전체 보안 상태**: [안전함/주의/위험/심각] 중 하나 선택하고 근거 제시
- **발견 취약점 개수**: {total_count}개 (Critical: {by_severity['critical']}, High: {by_severity['high']}, Medium: {by_severity['medium']}, Low: {by_severity['low']}, Info: {by_severity['info']})
- **비즈니스 영향 분석**:
  - 데이터 유출 가능성 평가
  - 서비스 중단 위험 평가
  - 컴플라이언스 위반 가능성
- **우선순위 조치사항** (상위 3-5개):
  1. [🔴 긴급/🟡 중요/🟢 일반] 조치내용 (경영진이 이해할 수 있는 언어로)
- **예상 위험 시나리오**: 공격자가 악용 시 발생 가능한 상황 설명

**작성 가이드**:
- 기술 용어 최소화
- 비즈니스 영향 중심
- 200-300 단어

## 2. 기술적 상세 분석 (Technical Deep Dive)

### 2.1 Critical 및 High 위험 취약점

가장 심각한 취약점 5-10개를 선택하여 각각:

#### [severity] Title

- **취약점 ID**: id
- **카테고리**: category
- **위치**: endpoint
- **CVE**: cve (있는 경우)

**공격 시나리오**:
실제 공격자가 이를 어떻게 악용할 수 있는지 단계별 설명

**기술적 원인**:
코드/설정 레벨에서의 문제점 분석

**영향 범위**:
어떤 시스템/데이터가 영향받는지

**수정 방안**:
구체적인 코드 수정 예시 및 베스트 프랙티스

---

### 2.2 Medium 및 Low 위험 취약점

카테고리별로 그룹화하여 요약

### 2.3 정보성 발견사항 (Info)

보안 강화 권고사항

## 3. 통계 및 시각화 데이터

### 3.1 심각도별 분포

| 심각도 | 개수 | 비율 |
|--------|------|------|
| Critical | {by_severity['critical']} | {round(by_severity['critical']/max(total_count,1)*100, 1)}% |
| High | {by_severity['high']} | {round(by_severity['high']/max(total_count,1)*100, 1)}% |
| Medium | {by_severity['medium']} | {round(by_severity['medium']/max(total_count,1)*100, 1)}% |
| Low | {by_severity['low']} | {round(by_severity['low']/max(total_count,1)*100, 1)}% |
| Info | {by_severity['info']} | {round(by_severity['info']/max(total_count,1)*100, 1)}% |

### 3.2 카테고리별 취약점

주요 카테고리를 테이블로 작성

### 3.3 엔드포인트별 취약점 분포 (상위 10개)

상위 10개 엔드포인트 테이블 작성

### 3.4 위험 점수 산정

- **전체 위험 점수**: {risk_score}/100
- **산정 기준**: (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1)
- **평가**:
  - 0-20: 🟢 안전
  - 21-50: 🟡 주의
  - 51-80: 🟠 위험
  - 81-100: 🔴 심각

## 4. 조치 우선순위 로드맵

### 즉시 조치 (24시간 이내)
Critical 취약점 체크리스트

### 단기 조치 (1주일 이내)
High 취약점 체크리스트

### 중기 조치 (1개월 이내)
Medium 취약점 요약

### 장기 조치 (분기별)
Low/Info 개선사항

## 5. 재검증 권고사항

- 조치 완료 후 재스캔 필요 항목
- 정기 점검 주기 제안 (월 1회 권장)
- 모니터링 강화 필요 엔드포인트

---

**작성 요구사항**:
- 모든 섹션 완전 작성
- 마크다운 문법 준수 (테이블, 리스트, 코드블록)
- 한국어 작성 (기술 용어는 영문 병기)
- 구체적이고 실행 가능한 조치사항
- 불필요한 내용 없이 핵심만 간결하게
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
    model = genai.GenerativeModel(MODEL_NAME)

    for attempt in range(MAX_RETRIES):
        try:
            print(f"[+] Gemini API 호출 중... (시도 {attempt + 1}/{MAX_RETRIES})")

            response = model.generate_content(
                prompt,
                generation_config={
                    'temperature': TEMPERATURE,
                    'max_output_tokens': 8192,
                }
            )

            if not response.text:
                raise Exception("API 응답이 비어있습니다.")

            print(f"[+] 보고서 생성 완료 ({len(response.text)} 문자)")
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


def save_report(content: str, target: str, output_dir: str) -> str:
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
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{safe_target}_report_{timestamp}.md"

    filepath = os.path.join(output_dir, filename)

    # 파일 저장
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[+] 보고서 저장: {filepath}")
    return filepath


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
        # 1. API 키 로드
        print("[1/6] API 키 로드 중...")
        api_key = get_api_key()
        print("[+] API 키 확인 완료")

        # 2. JSON 파일 로드
        print(f"\n[2/6] 스캔 결과 로드 중... ({json_file_path})")
        data = load_scan_results(json_file_path)
        print(f"[+] {len(data.get('findings', []))}개 취약점 로드 완료")

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

        # 5. Gemini API 호출
        print("\n[5/6] AI 보고서 생성 중...")
        markdown = call_gemini_api(prompt, api_key)

        # 6. 파일 저장
        print("\n[6/6] 보고서 저장 중...")
        target = data.get('target', 'unknown')
        report_path = save_report(markdown, target, output_dir)

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
