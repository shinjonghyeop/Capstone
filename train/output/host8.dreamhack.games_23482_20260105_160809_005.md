## Unencrypted Channels
- **End-Point**: `/ping`, `/text/css` 외 2개
- **영향**: 암호화되지 않은 통신 채널을 통해 데이터가 전송되어 네트워크 도청 및 중간자 공격(MITM) 시 민감한 정보가 노출될 수 있음.
- **설명**: 해당 호스트에 HTTPS 리다이렉션 설정이 적용되어 있지 않아 모든 HTTP 요청이 암호화되지 않은 평문으로 처리되고 있음.
- **근거**: `curl "http://host8.dreamhack.games:23482/ping"` 명령을 통해 HTTP 프로토콜로 직접 접근이 가능함을 확인.
- **대응**: 모든 HTTP 요청을 HTTPS로 강제 리다이렉트하고 HSTS(HTTP Strict Transport Security) 설정을 적용하여 보안을 강화해야 함.
- **조치**: 웹 서버 설정 파일에서 80번 포트 요청을 443번 포트로 리다이렉트하도록 구성하고 유효한 SSL/TLS 인증서를 설치하여 암호화 통신을 강제함.