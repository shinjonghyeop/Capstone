## Clickjacking Protection
- **End-Point**: `/`
- **영향**: 공격자가 의도적으로 구성한 투명 프레임에 대상 페이지를 삽입하여 사용자가 인지하지 못한 상태에서 민감한 기능을 클릭하게 만드는 클릭재킹 공격을 수행할 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Frame-Options` 설정이 누락되어 있어, 해당 웹 페이지가 다른 사이트의 `<iframe>`, `<frame>`, `<object>` 태그 내에 삽입되어 렌더링될 수 있는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:21070/"` 명령을 통한 응답 확인 시 `X-Frame-Options` 헤더가 존재하지 않음을 확인.
- **대응**: 웹 서버 설정 또는 애플리케이션 응답 로직에서 프레임 렌더링 정책을 정의하는 보안 헤더를 추가해야 함.
- **조치**: HTTP 응답 헤더에 `X-Frame-Options: DENY` 또는 `X-Frame-Options: SAMEORIGIN` 설정을 적용하여 외부 사이트에서의 프레임 삽입을 차단함.