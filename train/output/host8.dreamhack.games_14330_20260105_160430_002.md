## Clickjacking Protection
- **End-Point**: `/`
- **영향**: 공격자가 웹 페이지를 투명한 프레임으로 씌워 사용자가 의도하지 않은 클릭을 유도함으로써, 계정 설정 변경이나 데이터 삭제 등 민감한 동작을 강제로 수행하게 할 수 있음.
- **설명**: 웹 서버 응답 헤더에 `X-Frame-Options` 또는 `Content-Security-Policy`의 `frame-ancestors` 설정이 누락되어 있어, 해당 페이지가 타 사이트의 `<iframe>` 등 프레임 내부에 삽입될 수 있는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:14330/"` 명령을 통한 응답 확인 시 클릭재킹 방지를 위한 보안 헤더가 부재함.
- **대응**: 모든 웹 페이지 응답 시 브라우저가 프레임 렌더링 여부를 결정할 수 있도록 적절한 보안 헤더를 전송해야 함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 `X-Frame-Options: SAMEORIGIN` 헤더를 추가하고, 최신 브라우저 지원을 위해 `Content-Security-Policy: frame-ancestors 'self'` 설정을 병행할 것을 권고함.