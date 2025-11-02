#!/usr/bin/env python3
"""
프론트엔드와 API를 한 번에 실행하는 통합 서버

사용법:
  python3 run.py

브라우저에서 http://localhost:3000 접속
"""

from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os

app = Flask(__name__, static_folder='front', static_url_path='')
CORS(app)

@app.route('/')
def index():
    """프론트엔드 제공"""
    return send_from_directory('front', 'index.html')

@app.route('/api/scan', methods=['GET', 'POST'])
def scan():
    """스캔 API - main.py 실행"""
    try:
        if request.method == 'GET':
            url = request.args.get('url')
            cookies = request.args.get('cookies', '')
            headers = request.args.get('headers', '')
        else:
            data = request.get_json()
            url = data.get('url')
            cookies = data.get('cookies', '')
            headers = data.get('headers', '')
        
        if not url:
            return jsonify({"error": "URL이 필요합니다"}), 400
        
        print(f"\n{'='*60}")
        print(f"🔍 스캔 시작: {url}")
        print(f"{'='*60}\n")
        
        # main.py 실행
        cmd = ['python3', 'test_main.py', '--url', url, '--json']
        if cookies:
            cmd.extend(['--cookies', cookies])
        if headers:
            cmd.extend(['--headers', headers])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # JSON 결과 파싱
        output = result.stdout
        json_start = output.rfind('{')
        
        if json_start != -1:
            json_str = output[json_start:]
            scan_results = json.loads(json_str)
            
            response = {
                "target": url,
                "startedAt": "",
                "finishedAt": "",
                "tools": ["ffuf", "wapiti", "nuclei"],
                "findings": scan_results.get("findings", [])
            }
            
            print(f"\n✅ 스캔 완료! 발견된 이슈: {len(response['findings'])}개\n")
            return jsonify(response), 200
        else:
            return jsonify({"error": "결과 파싱 실패", "output": output}), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({"error": "스캔 타임아웃"}), 500
    except Exception as e:
        print(f"\n 오류: {e}\n")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║                                                        ║
    ║              🚀 HACKLIPSE SCANNER 🚀                  ║
    ║                                                        ║
    ║   브라우저에서 접속하세요:                               ║
    ║   👉 http://localhost:3000                            ║
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=3000, debug=False)