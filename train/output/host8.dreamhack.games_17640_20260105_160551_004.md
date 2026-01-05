## Unencrypted Channels
- **End-Point**: `//ping`, `/`
- **영향**: 암호화되지 않은 통신 채널을 통해 데이터가 평문으로 전송되어 중간자 공격(MitM)에 의한 정보 유출 및 데이터 변조 위험이 발생합니다.
- **설명**: 해당 호스트에 HTTPS 리다이렉션 설정이 존재하지 않아 모든 HTTP 요청이 암호화되지 않은 상태로 처리됩니다.
- **근거**: `curl "http://host8.dreamhack.games:17640//ping"` 명령을 통해 HTTP 요청이 정상적으로 처리됨을 확인하였습니다.
- **대응**: 모든 HTTP 요청을 HTTPS로 강제 리다이렉션하고 HSTS(HTTP Strict Transport Security) 헤더를 적용하여 보안을 강화해야 합니다.
- **조치**: 웹 서버 설정에서 80번 포트의 모든 트래픽을 443번 포트로 리다이렉트하도록 구성하고 유효한 SSL/TLS 인증서를 설치합니다.