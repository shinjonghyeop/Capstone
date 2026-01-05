## Unencrypted Channels
- **End-Point**: `/`, `/ping` 외 1개
- **영향**: 암호화되지 않은 통신 채널을 통해 데이터가 전송되므로 중간자 공격(MitM)에 의한 패킷 도청 및 민감 정보 유출 위험이 있음.
- **설명**: 해당 호스트에 HTTPS 리다이렉션이 설정되어 있지 않아 모든 HTTP 요청이 평문(Clear Text)으로 처리됨.
- **근거**: `curl "http://host3.dreamhack.games:21995/"` 명령을 실행하여 암호화되지 않은 HTTP 요청이 정상적으로 응답됨을 확인.
- **대응**: 모든 HTTP 요청을 HTTPS로 강제 리다이렉트하고, HSTS(HTTP Strict Transport Security) 헤더를 설정하여 보안 통신을 강제함.
- **조치**: 웹 서버 설정에서 80번 포트(HTTP)로 들어오는 연결을 443번 포트(HTTPS)로 전달하도록 구성하고 유효한 SSL/TLS 인증서를 적용함.