## Unencrypted Channels
- **End-Point**: `/`, `/r` 외 2개
- **영향**: 데이터가 암호화되지 않은 평문으로 전송되어 중간자 공격(MITM)을 통한 세션 하이재킹 및 민감 정보 유출 위험이 있음.
- **설명**: 해당 호스트에 HTTPS 리다이렉션이 설정되어 있지 않아 모든 HTTP 요청이 암호화되지 않은 상태로 처리됨.
- **근거**: `curl "http://host8.dreamhack.games:10872/"` 명령 수행 시 HTTPS로의 리다이렉션 없이 HTTP 응답이 그대로 반환됨을 확인.
- **대응**: 서버 설정을 통해 모든 HTTP 요청을 HTTPS로 강제 리다이렉션하고 HSTS(HTTP Strict Transport Security) 헤더를 적용해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 설정에서 80번 포트로 들어오는 요청에 대해 `301 Moved Permanently`를 사용하여 HTTPS 포트로 전환하도록 구성함.