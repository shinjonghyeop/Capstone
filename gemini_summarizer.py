import os
from google import genai
from google.genai.errors import APIError
from google.genai import types

# --- 설정 영역 ---
# 1. API 키를 환경 변수에서 불러옵니다.
# ** 키 값 노출 금지 ** ** 키 값 노출 금지 ** ** 키 값 노출 금지 ** ** 키 값 노출 금지 ** ** 키 값 노출 금지 **
API_KEY = os.getenv("AIzaSyC5V95QNVfyp_km7nEvSWEy4BOJCsgobps")

# 2. 요약할 파일의 경로와 MIME 타입(파일 형식)을 지정합니다.
# 예시: "my_paper.pdf", "report.txt", "image.png"
FILE_PATH = "wapiti_ex.json" 
MIME_TYPE = "text/plain" #application/json으로 하면 500오류 발생

# 3. AI Studio에서 작성했던 '시스템 명령'을 여기에 넣어줍니다.
SYSTEM_INSTRUCTIONS = """
당신은 보안 취약점 분석가입니다. 제공된 JSON 형식의 취약점 스캔 보고서를 분석하여 개발팀이 즉시 조치할 수 있도록 명확하고 실행 가능한 보고서를 생성해야 합니다.

[주요 규칙]:
1. **전문성 유지:** 모든 용어(CVE, CVSS, Exploit 등)는 보안 업계 표준에 맞게 사용합니다.
2. **분류:** 취약점을 '심각도(Severity)'에 따라 분류하여 정리합니다. (Critical, High, Medium, Low)
3. **핵심 정보 추출:** 각 취약점 항목에서 '취약점 이름(Title)', '심각도(Severity)', '영향을 받는 파일/경로(Affected Path)', '조치 방안(Remediation)'을 필수적으로 추출합니다.
4. **한국어 보고서:** 최종 응답은 간결하고 전문적인 한국어로 작성합니다.
"""

# 4. 모델에게 구체적으로 시킬 '사용자 프롬프트'를 작성합니다.
USER_PROMPT = """
우선 이 json에 대해서 요약 부탁드릴게요.
"""
# -----------------

        #------오류코드 주석처리-------- Python SDK가 버전마다 파일 관련 인수 받는 법이 다름
        #uploaded_file = client.files.upload(
        #    file=file_path, 
        #    mime_type=mime_type
        #)

        #------config 수정 코드--------
        
        upload_config = types.UploadFileConfig(
            mime_type=mime_type # mime_type을 config 객체 안에 넣어서 전달
        )

        uploaded_file = client.files.upload(
            file=file_path,
            config=upload_config  # config 인수로 통째로 전달
        )

        print(f"   업로드 완료. 파일 이름: {uploaded_file.name}")
        
        # 3. 콘텐츠 생성 요청
        # contents 리스트에 파일 객체(uploaded_file)와 사용자 프롬프트를 함께 넣어 요청합니다.
        # System Instructions는 별도의 config로 전달됩니다.
        print("2. Gemini 모델(gemini-2.5-flash)에 요약 요청 중...")
        
        response = client.models.generate_content(
            model='gemini-2.5-flash', # 파일 처리에 적합하고 빠른 모델
            contents=[

        system_instructions=SYSTEM_INSTRUCTIONS,
        user_prompt=USER_PROMPT
    )