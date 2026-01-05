## Unencrypted Channels
- **End-Point**: `/intro`, `/`
- **영향**: 암호화되지 않은 평문 통신을 통해 데이터가 전송되므로 네트워크 스니핑에 의한 정보 유출 및 중간자 공격(MITM)을 통한 데이터 변조 위험이 있음.
- **설명**: 해당 호스트에 HTTPS 리다이렉션 설정이 존재하지 않아 모든 HTTP 요청이 암호화되지 않은 상태로 처리됨.
- **근거**: `curl "http://host8.dreamhack.games:19373/intro"` 명령 실행 시 HTTPS로의 전환 없이 평문 HTTP 통신이 수행됨을 확인.
- **대응**: 서버 측에서 모든 HTTP 요청을 HTTPS 프로토콜로 강제 리다이렉트하도록 설정하고 HSTS(HTTP Strict Transport Security) 헤더를 적용해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 설정에서 80 포트 접근 시 443 포트로 리다이렉트하는 규칙을 추가하고 유효한 SSL/TLS 인증서를 적용함.