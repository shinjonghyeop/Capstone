## Unencrypted Channels
- **End-Point**: `/`
- **영향**: 통신 데이터가 암호화되지 않은 평문으로 전송되어 중간자 공격(MITM)을 통한 세션 하이재킹 및 민감 정보 유출이 발생할 수 있음.
- **설명**: 해당 호스트에 HTTPS 리다이렉션 설정이 되어 있지 않아 모든 HTTP 요청이 암호화되지 않은 상태로 서비스됨.
- **근거**: `curl "http://host8.dreamhack.games:14330/"` 명령을 통해 HTTP 요청 시 HTTPS로의 강제 전환 없이 평문 응답이 반환됨을 확인.
- **대응**: 모든 HTTP 요청을 HTTPS로 강제 리다이렉트하고 HSTS(HTTP Strict Transport Security) 보안 헤더를 적용함.
- **조치**: 웹 서버 설정에서 80 포트로 인입되는 트래픽을 443 포트로 리다이렉트하도록 구성하고 SSL/TLS 인증서를 설치 및 적용함.