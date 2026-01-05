## MIME Type Confusion
- **End-Point**: `/`, `//ping`
- **영향**: 브라우저가 응답 본문의 MIME 타입을 잘못 추측(MIME Sniffing)하여 악성 스크립트를 실행하거나 보안 정책을 우회할 위험이 있음.
- **설명**: 응답 헤더에 `X-Content-Type-Options`가 설정되어 있지 않아 브라우저가 리소스의 내용을 분석하여 임의로 타입을 결정할 수 있는 상태임.
- **근거**: `curl "http://host3.dreamhack.games:8643/"` 실행 결과 응답 헤더에서 `X-Content-Type-Options` 설정을 확인할 수 없음.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저의 MIME Sniffing 동작을 방지해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 환경 설정 또는 애플리케이션 코드에서 전역적으로 보안 헤더를 적용함.