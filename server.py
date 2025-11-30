#!/usr/bin/env python3
"""
프론트엔드와 API를 한 번에 실행하는 통합 서버
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
from typing import Dict, List, Any, Optional

app = Flask(__name__)
CORS(app)

# Constants
MERGED_RESULTS_DIR = 'merged_results'
SCAN_TIMEOUT = 600  # 10 minutes
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

@app.route('/api/scan', methods=['GET', 'POST'])
def scan():
    """스캔 API - main.py 실행"""
    try:
        # 요청 파라미터 추출
        if request.method == 'GET':
            url = request.args.get('url')
            cookies = request.args.get('cookies', '')
            headers = request.args.get('headers', '')
        else:
            data = request.get_json() or {}
            url = data.get('url')
            cookies = data.get('cookies', '')
            headers = data.get('headers', '')
        
        if not url:
            return jsonify({"error": "URL이 필요합니다"}), 400
        
        print(f"\n{'='*60}")
        print(f" 스캔 시작: {url}")
        print(f"{'='*60}")
        
        # main.py 실행 (test_main.py가 아니라 main.py!)
        cmd = ['python3', 'main.py', '--url', url]
        if cookies:
            cmd.extend(['--cookies', cookies])
        if headers:
            cmd.extend(['--headers', headers])
        
        print(f"[명령어] {' '.join(cmd)}")
        print(f"[작업 디렉토리] {os.getcwd()}")
        print(f"\n{'='*60}")
        print("main.py 실행 중... (실시간 로그)")
        print(f"{'='*60}\n")
        
        # main.py 실행 - 실시간 로그 출력
        result = subprocess.run(
            cmd,
            timeout=SCAN_TIMEOUT,
            # capture_output=True 대신 stdout/stderr를 상속받아서 실시간 출력
        )
        
        print(f"\n{'='*60}")
        print(f"[Return Code] {result.returncode}")
        print(f"{'='*60}\n")
        
        # 에러 체크
        if result.returncode != 0:
            return jsonify({
                "error": "main.py 실행 실패",
                "returncode": result.returncode
            }), 500
        
        # 성공
        return jsonify({
            "message": "스캔 완료",
            "target": url
        }), 200
        
    except subprocess.TimeoutExpired:
        return jsonify({"error": "타임아웃 (10분 초과)"}), 500
    except Exception as e:
        print(f"\n[ERROR] {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200


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
