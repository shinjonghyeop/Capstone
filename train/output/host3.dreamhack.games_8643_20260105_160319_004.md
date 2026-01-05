## Unencrypted Channels
- **End-Point**: `/`, `//ping`
- **영향**: 암호화되지 않은 HTTP 통신을 사용함에 따라 네트워크 스니핑 및 중간자 공격(MITM)을 통해 사용자의 민감한 데이터나 세션 정보가 탈취될 위험이 있음.
- **설명**: 해당 호스트에 HTTPS 리다이렉션 정책이 적용되어 있지 않아 모든 HTTP 요청이 암호화되지 않은 평문(Clear Text) 상태로 전송됨.
- **근거**: `curl "http://host3.dreamhack.games:8643/"` 명령 실행 시 HTTPS로의 자동 전환 없이 HTTP 평문 통신이 유지됨을 확인.
- **대응**: 모든 HTTP 요청을 HTTPS 보안 채널로 강제 리다이렉트하고, 브라우저가 항상 보안 연결을 사용하도록 HSTS(HTTP Strict Transport Security) 설정을 적용해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 설정 파일에서 HTTP(80 포트 등) 요청에 대해 `301 Moved Permanently`를 사용하여 HTTPS로 리다이렉트하도록 구성하고 SSL/TLS 인증서를 설치함.