## Unencrypted Channels
- **End-Point**: `/`, `/ping`
- **영향**: 네트워크 트래픽 스니핑을 통해 사용자의 세션 쿠키나 자격 증명 등 민감한 정보가 노출될 수 있는 중간자 공격(MitM)에 취약함.
- **설명**: 해당 호스트에 HTTPS 리다이렉션이 구성되어 있지 않아 모든 HTTP 요청과 응답이 암호화되지 않은 평문 상태로 전송됨.
- **근거**: `curl "http://host8.dreamhack.games:20315/"` 실행 시 HTTP 프로토콜을 통한 통신이 허용됨을 확인.
- **대응**: 모든 HTTP 요청을 HTTPS로 강제 리다이렉션하고 HSTS(HTTP Strict Transport Security) 설정을 적용함.
- **조치**: 웹 서버 설정 파일에서 80 포트 요청에 대해 301 Redirect를 사용하여 HTTPS 포트로 연결되도록 수정하고 SSL/TLS 인증서를 적용함.