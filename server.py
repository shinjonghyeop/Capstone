#!/usr/bin/env python3
"""
프론트엔드와 API를 한 번에 실행하는 통합 서버
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# Constants
MERGED_RESULTS_DIR = 'merged_results'
SCAN_TIMEOUT = None 
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
SCAN_STATUS_DIR = 'scan_status'
SCAN_STATE = {
    "status_file": None,
    "target": None,
    "started_at": None
}


def _write_scan_status(status_file: str, payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(status_file), exist_ok=True)
    with open(status_file, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)


def _init_scan_status(target_url: str) -> str:
    os.makedirs(SCAN_STATUS_DIR, exist_ok=True)
    safe_target = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
    filename = f"scan_{safe_target}_{int(time.time())}.json"
    status_file = os.path.join(os.getcwd(), SCAN_STATUS_DIR, filename)
    payload = {
        "phase": "scanning",
        "step": "queued",
        "message": "스캔 준비 중",
        "target": target_url,
        "updatedAt": int(time.time())
    }
    _write_scan_status(status_file, payload)
    return status_file

def _list_result_files(results_dir: str) -> List[Dict[str, Any]]:
    files = []
    if not os.path.exists(results_dir):
        return files

    for filename in os.listdir(results_dir):
        if not filename.endswith('.json'):
            continue
        filepath = os.path.join(results_dir, filename)
        if not os.path.isfile(filepath):
            continue
        stat = os.stat(filepath)
        files.append({
            "filename": filename,
            "path": filepath,
            "created": stat.st_ctime,
            "modified": stat.st_mtime
        })

    files.sort(key=lambda x: x['modified'], reverse=True)
    return files


def _expected_result_filename(target_url: str) -> Optional[str]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        return None
    if parsed.port:
        return f"{host}_{parsed.port}.json"
    return f"{host}.json"


def _select_result_file(
    files: List[Dict[str, Any]],
    existing_names: set,
    target_url: str,
    started_at: float
) -> Optional[Dict[str, Any]]:
    expected = _expected_result_filename(target_url)
    expected_prefix = None
    if expected and expected.endswith(".json"):
        expected_prefix = expected[:-5]
    new_files = [f for f in files if f["filename"] not in existing_names]

    if expected:
        for f in new_files:
            if f["filename"] == expected:
                return f
            if expected_prefix and f["filename"].startswith(f"{expected_prefix}_"):
                return f
    if new_files:
        return new_files[0]

    modified_files = [
        f for f in files
        if f["filename"] in existing_names and f["modified"] >= started_at
    ]
    if expected:
        for f in modified_files:
            if f["filename"] == expected:
                return f
            if expected_prefix and f["filename"].startswith(f"{expected_prefix}_"):
                return f
    if modified_files:
        return modified_files[0]

    if expected:
        for f in files:
            if f["filename"] == expected:
                return f

    return files[0] if files else None


def _load_result_data(filepath: str, filename: str) -> Dict[str, Any]:
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if isinstance(data, dict) and isinstance(data.get('findings'), list):
        if not data.get('target'):
            data = {**data, 'target': filename}
        return data

    return normalize_merged_results(data, filename)


@app.route('/api/scan', methods=['GET', 'POST'])
def scan():
    """스캔 API - main.py 실행"""
    try:
        # 요청 파라미터 추출
        if request.method == 'GET':
            url = request.args.get('url')
            cookies = request.args.get('cookies', '')
            headers = request.args.get('headers', '')
            rate_raw = request.args.get('rate')
        else:
            data = request.get_json() or {}
            url = data.get('url')
            cookies = data.get('cookies', '')
            headers = data.get('headers', '')
            rate_raw = data.get('rate')

        if not url:
            return jsonify({"error": "URL이 필요합니다"}), 400

        # rate 검증 (선택값, 1~500 정수)
        rate = None
        if rate_raw not in (None, "", "null"):
            try:
                rate = int(rate_raw)
            except (TypeError, ValueError):
                return jsonify({"error": "rate는 정수여야 합니다"}), 400
            if not (1 <= rate <= 500):
                return jsonify({"error": "rate는 1~500 사이여야 합니다"}), 400
        
        print(f"\n{'='*60}")
        print(f" 스캔 시작: {url}")
        print(f"{'='*60}")
        
        results_dir = os.path.join(os.getcwd(), MERGED_RESULTS_DIR)
        existing_files = {f["filename"] for f in _list_result_files(results_dir)}
        started_at = time.time()
        status_file = _init_scan_status(url)
        SCAN_STATE.update({
            "status_file": status_file,
            "target": url,
            "started_at": started_at
        })

        # main.py 실행 (test_main.py가 아니라 main.py!)
        cmd = ['python3', 'main.py', '--url', url]
        if cookies:
            cmd.extend(['--cookies', cookies])
        if headers:
            cmd.extend(['--headers', headers])
        if rate is not None:
            cmd.extend(['--rate', str(rate)])
        
        print(f"[명령어] {' '.join(cmd)}")
        print(f"[작업 디렉토리] {os.getcwd()}")
        print(f"\n{'='*60}")
        print("main.py 실행 중... (실시간 로그)")
        print(f"{'='*60}\n")
        
        # main.py 실행 - 실시간 로그 출력
        env = os.environ.copy()
        env["SCAN_STATUS_FILE"] = status_file
        result = subprocess.run(
            cmd,
            timeout=SCAN_TIMEOUT,
            # capture_output=True 대신 stdout/stderr를 상속받아서 실시간 출력
            env=env
        )
        
        print(f"\n{'='*60}")
        print(f"[Return Code] {result.returncode}")
        print(f"{'='*60}\n")
        
        # 에러 체크
        if result.returncode != 0:
            _write_scan_status(status_file, {
                "phase": "error",
                "step": "failed",
                "message": "스캔 실행 실패",
                "target": url,
                "updatedAt": int(time.time())
            })
            return jsonify({
                "error": "main.py 실행 실패",
                "returncode": result.returncode
            }), 500
        
        files = _list_result_files(results_dir)
        selected = _select_result_file(files, existing_files, url, started_at)

        if selected:
            payload = _load_result_data(selected["path"], selected["filename"])
            payload["resultFile"] = selected["filename"]
            _write_scan_status(status_file, {
                "phase": "done",
                "step": "complete",
                "message": "스캔 완료",
                "target": url,
                "updatedAt": int(time.time()),
                "resultFile": selected["filename"]
            })
            return jsonify(payload), 200

        _write_scan_status(status_file, {
            "phase": "done",
            "step": "complete",
            "message": "스캔 완료",
            "target": url,
            "updatedAt": int(time.time())
        })
        return jsonify({
            "message": "스캔 완료",
            "target": url,
            "findings": [],
            "tools": []
        }), 200
        
    except subprocess.TimeoutExpired:
        if SCAN_STATE.get("status_file"):
            _write_scan_status(SCAN_STATE["status_file"], {
                "phase": "error",
                "step": "timeout",
                "message": "스캔 타임아웃",
                "target": url,
                "updatedAt": int(time.time())
            })
        return jsonify({"error": "타임아웃 (10분 초과)"}), 500
    except Exception as e:
        print(f"\n[ERROR] {e}\n")
        import traceback
        traceback.print_exc()
        if SCAN_STATE.get("status_file"):
            _write_scan_status(SCAN_STATE["status_file"], {
                "phase": "error",
                "step": "failed",
                "message": "스캔 처리 중 오류",
                "target": SCAN_STATE.get("target"),
                "updatedAt": int(time.time())
            })
        return jsonify({"error": str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    status_file = SCAN_STATE.get("status_file")
    if not status_file or not os.path.exists(status_file):
        return jsonify({"phase": "idle"}), 200
    try:
        with open(status_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"phase": "error", "message": str(e)}), 500


@app.route('/api/results', methods=['GET'])
def list_results():
    """merged_results/ 디렉토리의 JSON 파일 목록 반환"""
    try:
        results_dir = os.path.join(os.getcwd(), MERGED_RESULTS_DIR)

        if not os.path.exists(results_dir):
            return jsonify({"results": []}), 200

        files = []
        for filename in os.listdir(results_dir):
            if not filename.endswith('.json'):
                continue

            filepath = os.path.join(results_dir, filename)
            if not os.path.isfile(filepath):
                continue

            stat = os.stat(filepath)
            files.append({
                "filename": filename,
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime
            })

        # 최신순으로 정렬
        files.sort(key=lambda x: x['modified'], reverse=True)

        return jsonify({"results": files}), 200

    except Exception as e:
        print(f"\n[ERROR] list_results: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/results/<filename>', methods=['GET'])
def get_result(filename: str):
    """특정 JSON 파일의 내용을 반환"""
    try:
        # 보안: 디렉토리 탐색 방지
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({"error": "잘못된 파일명"}), 400

        results_dir = os.path.join(os.getcwd(), MERGED_RESULTS_DIR)
        filepath = os.path.join(results_dir, filename)

        if not os.path.exists(filepath):
            return jsonify({"error": "파일을 찾을 수 없습니다"}), 404

        # JSON 파일 읽기
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 이미 프론트 포맷으로 저장된 경우 그대로 사용
        if isinstance(data, dict) and isinstance(data.get('findings'), list):
            normalized = data if data.get('target') else {**data, 'target': filename}
        else:
            # merged_results 포맷을 프론트엔드 친화적으로 변환
            normalized = normalize_merged_results(data, filename)

        return jsonify(normalized), 200

    except json.JSONDecodeError as e:
        return jsonify({"error": f"JSON 파싱 오류: {str(e)}"}), 500
    except Exception as e:
        print(f"\n[ERROR] get_result: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def normalize_endpoint(url: Optional[str]) -> str:
    """URL에서 쿼리 파라미터와 프래그먼트를 제거하여 base endpoint만 추출"""
    if not url:
        return url or ""
    return url.split('?')[0].split('#')[0]


def normalize_merged_results(merged_data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """merged_results 포맷을 프론트엔드용으로 정규화"""
    findings = []
    tools = set()

    # 각 엔드포인트별로 순회
    for endpoint_key, scan_data in merged_data.items():
        # 엔드포인트 이름 복원 (언더스코어를 슬래시로)
        base_endpoint = endpoint_key.replace('_', '/').replace(' ', '_')
        base_endpoint = normalize_endpoint(base_endpoint)

        # Nuclei 결과 처리
        if 'nuclei' in scan_data and scan_data['nuclei']:
            tools.add('nuclei')
            for category in ['xss', 'sql', 'cve']:
                if category in scan_data['nuclei']:
                    for finding in scan_data['nuclei'][category]:
                        info = finding.get('info', {})
                        classification = info.get('classification', {})
                        cve_ids = classification.get('cve-id', [])
                        cve_str = ', '.join(cve_ids) if cve_ids else None

                        matched_url = finding.get('matched-at', base_endpoint)

                        findings.append({
                            'id': f"nuclei-{category}-{len(findings)}",
                            'tool': 'nuclei',
                            'category': category.upper(),
                            'severity': info.get('severity', 'info').lower(),
                            'title': info.get('name', 'Nuclei Finding'),
                            'description': info.get('description', ''),
                            'impact': info.get('impact', 'N/A'),
                            'endpoint': normalize_endpoint(matched_url),
                            'fullUrl': matched_url,  # 전체 URL (페이로드 포함) 저장
                            'method': extract_method(finding.get('request', '')),
                            'cve': cve_str,
                            'evidence': finding.get('matcher-name', 'See request/response'),
                            'request': finding.get('request'),
                            'response': finding.get('response'),
                            'curlCommand': finding.get('curl-command'),
                            'ip': finding.get('ip'),
                            'references': info.get('reference', []) if isinstance(info.get('reference'), list) else ([info.get('reference')] if info.get('reference') else [])
                        })

        # Wapiti 결과 처리
        if 'wapiti' in scan_data and scan_data['wapiti']:
            tools.add('wapiti')
            for category, findings_array in scan_data['wapiti'].items():
                if findings_array:
                    for finding in findings_array:
                        wstg = finding.get('wstg', [])
                        path = finding.get('path', base_endpoint)

                        findings.append({
                            'id': f"wapiti-{category}-{len(findings)}",
                            'tool': 'wapiti',
                            'category': category,
                            'severity': infer_wapiti_severity(category),
                            'title': category,
                            'description': finding.get('info', ''),
                            'endpoint': normalize_endpoint(path),
                            'fullUrl': path,  # 전체 URL 저장
                            'parameter': finding.get('parameter'),
                            'curlCommand': finding.get('curl_command'),
                            'wstg': wstg,
                            'references': [f"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/{tag}" for tag in wstg]
                        })

    # 심각도 순으로 정렬
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f['severity']) if f['severity'] in SEVERITY_ORDER else 999)

    return {
        'target': filename,
        'startedAt': None,
        'finishedAt': None,
        'tools': list(tools),
        'findings': findings
    }


def extract_method(request: Optional[str]) -> str:
    """HTTP 요청에서 메소드 추출"""
    if not request:
        return 'GET'

    lines = request.split('\n')
    if not lines:
        return 'GET'

    first_line = lines[0]
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

    for method in http_methods:
        if first_line.startswith(method):
            return method

    return 'GET'


def infer_wapiti_severity(category: str) -> str:
    """Wapiti 카테고리로부터 심각도 추론"""
    severity_map = {
        'high': ['Reflected Cross Site Scripting', 'SQL Injection', 'File Handling Vulnerability'],
        'medium': ['Clickjacking Protection', 'Content Security Policy', 'CSRF Protection'],
        'low': ['MIME Type Confusion', 'Unencrypted Channels', 'HTTP Security Headers']
    }

    for severity, keywords in severity_map.items():
        if any(keyword in category for keyword in keywords):
            return severity

    return 'info'


# ========================================================================
# AI 보고서 생성 API
# ========================================================================

@app.route('/api/generate-report/<filename>', methods=['POST'])
def generate_ai_report(filename: str):
    """
    특정 JSON 파일에 대한 AI 보고서 생성

    POST /api/generate-report/localhost_9991.json

    Response:
    {
        "success": true,
        "report_path": "reports/localhost_9991_report_20251130_183045.md",
        "markdown": "# 보고서 내용..."
    }
    """
    try:
        # 보안: 디렉토리 트래버설 방지
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({"error": "Invalid filename"}), 400

        # JSON 파일 존재 확인
        merged_path = os.path.join(MERGED_RESULTS_DIR, filename)
        if not os.path.exists(merged_path):
            return jsonify({"error": "Merged result not found"}), 404

        payload = request.get_json(silent=True) or {}
        provider = None
        if isinstance(payload, dict):
            provider = payload.get("provider")
        if provider is not None:
            provider = str(provider).strip().lower()
            if provider not in ("gemini", "hacklipse"):
                return jsonify({"error": "Invalid provider"}), 400

        # 보고서 생성
        from utils.generate_reports import generate_report

        report_path = generate_report(
            json_file_path=merged_path,
            output_dir='reports',
            provider_override=provider
        )

        # 생성된 마크다운 읽기
        with open(report_path, 'r', encoding='utf-8') as f:
            markdown_content = f.read()

        return jsonify({
            "success": True,
            "report_path": report_path,
            "markdown": markdown_content
        }), 200

    except Exception as e:
        print(f"\n[ERROR] generate_ai_report: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports', methods=['GET'])
def list_reports():
    """
    생성된 모든 AI 보고서 목록

    Response:
    {
        "reports": [
            {
                "filename": "localhost_9991_report_20251130_183045.md",
                "size": 12345,
                "created": timestamp,
                "target": "localhost_9991"
            }
        ]
    }
    """
    try:
        reports_dir = 'reports'

        if not os.path.exists(reports_dir):
            return jsonify({"reports": []}), 200

        reports = []
        for filename in os.listdir(reports_dir):
            if not filename.endswith('.md'):
                continue

            filepath = os.path.join(reports_dir, filename)
            if not os.path.isfile(filepath):
                continue

            stat = os.stat(filepath)

            # 파일명에서 target 추출
            # 형식: {target}_report_{timestamp}.md
            target = filename.replace('_report_', '|||').split('|||')[0]

            reports.append({
                "filename": filename,
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "target": target
            })

        # 최신순 정렬
        reports.sort(key=lambda x: x['modified'], reverse=True)

        return jsonify({"reports": reports}), 200

    except Exception as e:
        print(f"\n[ERROR] list_reports: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/<filename>', methods=['GET'])
def get_report(filename: str):
    """
    특정 보고서의 마크다운 내용 조회

    Response:
    {
        "filename": "...",
        "markdown": "# 보고서...",
        "target": "localhost_9991",
        "created": timestamp
    }
    """
    try:
        # 보안: 디렉토리 트래버설 방지
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({"error": "Invalid filename"}), 400

        filepath = os.path.join('reports', filename)

        if not os.path.exists(filepath):
            return jsonify({"error": "Report not found"}), 404

        with open(filepath, 'r', encoding='utf-8') as f:
            markdown = f.read()

        stat = os.stat(filepath)
        target = filename.replace('_report_', '|||').split('|||')[0]

        return jsonify({
            "filename": filename,
            "markdown": markdown,
            "target": target,
            "created": stat.st_ctime,
            "modified": stat.st_mtime
        }), 200

    except Exception as e:
        print(f"\n[ERROR] get_report: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║                                                        ║
    ║                   HACKLIPSE SCANNER                    ║
    ║                                                        ║
    ║          API Server: http://localhost:3000             ║
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=3000, debug=True)
