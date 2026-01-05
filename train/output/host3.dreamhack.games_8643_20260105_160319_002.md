## Clickjacking Protection
- **End-Point**: `/`, `//ping`
- **영향**: 공격자가 웹 사이트를 투명한 프레임으로 씌워 사용자가 의도하지 않은 클릭을 유도함으로써 민감한 기능을 실행하거나 정보를 노출시킬 수 있음.
- **설명**: 응답 헤더에 `X-Frame-Options` 설정이 누락되어 웹 페이지가 다른 사이트의 `iframe` 내에서 렌더링될 수 있는 취약점임.
- **근거**: `curl "http://host3.dreamhack.games:8643/"` 명령어를 통해 응답 헤더를 확인한 결과 클릭재킹 방지 헤더가 존재하지 않음.
- **대응**: 모든 HTTP 응답 헤더에 `X-Frame-Options`를 설정하거나 `Content-Security-Policy`의 `frame-ancestors` 지시문을 사용하여 프레임 삽입 권한을 제한해야 함.
- **조치**: 웹 서버 또는 애플리케이션 설정에서 `X-Frame-Options: DENY` 또는 `X-Frame-Options: SAMEORIGIN` 헤더를 적용함.