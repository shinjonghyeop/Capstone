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

def summarize_document(file_path: str, mime_type: str, system_instructions: str, user_prompt: str):
    """
    파일을 Gemini API에 업로드하고, 시스템 명령 및 사용자 프롬프트와 함께 요약을 요청합니다.
    """
    if not API_KEY:
        print("오류: GEMINI_API_KEY 환경 변수가 설정되지 않았습니다.")
        return

    try:
        # 1. Gemini Client 초기화
        client = genai.Client(api_key=API_KEY)

        print(f"1. {os.path.basename(test)} 파일 업로드 중...")
        
        # 2. Files API를 사용하여 파일 업로드
        # 이 단계에서 파일은 Gemini 서버에 임시로 저장되며, 파일 객체가 반환됩니다.

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

        print("전은진")
        
        # 3. 콘텐츠 생성 요청
        # contents 리스트에 파일 객체(uploaded_file)와 사용자 프롬프트를 함께 넣어 요청합니다.
        # System Instructions는 별도의 config로 전달됩니다.
        print("2. Gemini 모델(gemini-2.5-flash)에 요약 요청 중...")
        
        response = client.models.generate_content(
            model='gemini-2.5-flash', # 파일 처리에 적합하고 빠른 모델
            contents=[
                uploaded_file, # 업로드된 파일 자체를 콘텐츠로 포함
                user_prompt    # 사용자 프롬프트 
            ],
            config=genai.types.GenerateContentConfig(
                system_instruction=system_instructions
            )
        )
        
        # 4. 결과 출력
        print("\n--- [ 요약 결과 ] ---")
        print(response.text)
        print("---------------------\n")

    except FileNotFoundError:
        print(f"오류: 지정된 파일 경로를 찾을 수 없습니다. 경로를 확인해 주세요: {FILE_PATH}")
    except APIError as e:
        print(f"API 오류가 발생했습니다: {e}")
    except Exception as e:
        print(f"알 수 없는 오류 발생: {e}")
    finally:
        # 5. 사용이 끝난 파일 삭제 (선택 사항이지만 권장)
        # 파일을 서버에 계속 남겨두면 비용이 발생할 수 있으므로, 처리가 끝나면 삭제합니다.
        if 'uploaded_file' in locals() and uploaded_file:
            print(f"3. 임시 파일 삭제 중... ({uploaded_file.name})")
            client.files.delete(name=uploaded_file.name)
            print("   삭제 완료.")


if __name__ == "__main__":
    summarize_document(
        file_path=FILE_PATH,
        mime_type=MIME_TYPE,
        system_instructions=SYSTEM_INSTRUCTIONS,
        user_prompt=USER_PROMPT
    )