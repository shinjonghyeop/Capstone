#!/usr/bin/env python3
"""
프론트엔드와 API를 한 번에 실행하는 통합 서버
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os

app = Flask(__name__)
CORS(app)

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
            timeout=600,
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


if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║                                                        ║
    ║              🚀 HACKLIPSE SCANNER 🚀                  ║
    ║                                                        ║
    ║   API Server: http://localhost:3000                   ║
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=3000, debug=True)