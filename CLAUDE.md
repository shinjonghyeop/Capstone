# Hacklipse - AI 기반 자동 취약점 탐지 프레임워크

**2025년 인공지능빅데이터센터 산하 연구과제**  
*"AI를 활용한 자동 취약점 탐지 프레임워크 개발"*

---

##  프로젝트 개요

### 연구 배경 및 필요성
국내 교육·공공기관의 디지털 행정 전환 가속화로 개인정보·민감 데이터의 대규모 저장·관리가 증가하고 있습니다. 특히 웹 기반 서비스와 내부 시스템(DBMS 등)의 확산으로 공격 표면이 급격히 확대되었으며, 최근 전국적인 대형 해킹 사고가 연속 발생하고 있습니다. 

현재 수작업 위주의 보안점검은 한계가 있어, **최신 AI/자동화 기반 위협 탐지 시스템 도입이 시급**한 상황입니다.

### 연구 목표
**OSINT(Open Source Intelligence)로 수집한 공개정보를 기반으로 잠재 취약점을 AI가 자동 분석·리포트하는 프레임워크 개발**

- 공개정보(서비스 버전, 메타데이터 등)만으로 공격 가능성이 높은 취약점 사전 식별
- 보안 전문가의 수작업 최소화를 통한 자동화 기반 선제적 진단 체계 구축
- 실제 모의해킹을 통한 수집정보-취약점 상관관계 학습

### 팀 구성
**Hacklipse** - 해킹/보안 동아리 (웹/시스템/리버싱 세부팀 운영)

- **OSINT/모의해킹 팀**: 정보수집, 모의해킹 실험, 데이터 라벨링
- **AI/데이터팀**: 모델 설계, 파인튜닝, 평가, 코드 작성  
- **통합 개발팀**: 파이프라인 자동화, UI/CLI 도구 제작

---

## 시스템 아키텍처

Hacklipse는 **방어적 보안 연구**를 위한 종합 사이버보안 테스팅 플랫폼으로, 다음 3개 핵심 컴포넌트로 구성됩니다:

### 1. SecLists 워드리스트 컬렉션
공격 벡터별로 분류된 광범위한 보안 워드리스트 및 페이로드 모음
- `Discovery/Web-Content/`: 디렉토리 및 파일 퍼징 워드리스트
- `Passwords/`: 브루트포스 테스팅용 패스워드 리스트
- `Fuzzing/`: 입력 검증 및 인젝션 페이로드
- `Usernames/`: 일반적인 사용자명 리스트

### 2. 취약점 테스팅 환경 (Victim Environment)
Docker 기반 다중 서비스 취약점 테스팅 플랫폼

#### 웹 서비스 계층
- **Apache + PHP**: SQL 인젝션, 파일 업로드, 명령어 인젝션 취약점
- **Nginx**: 디렉토리 리스팅 및 백업 파일 노출
- **WordPress 4.7.1**: CVE-2017-1001000 REST API 취약점
- **Drupal 7.67**: CVE-2018-7600 Drupalgeddon2 취약점
- **커스텀 Python 서버**: 경로 순회 취약점

#### 데이터베이스 계층
- **MySQL 5.7**: 약한 인증, 원격 접근 허용
- **PostgreSQL 9.6**: 레거시 버전 취약점

#### 네트워크 서비스
- **SSH**: root 로그인 활성화, 약한 패스워드
- **FTP**: 익명 접근, 쓰기 권한 허용
- **Redis**: 인증 없음
- **SNMP**: 기본 커뮤니티 스트링

### 3. OSINT 자동화 파이프라인
2단계 자동화 정찰 시스템으로 AI 학습용 데이터 생성

#### Stage 1: 발견 및 열거
- **nmap**: 포트 스캐닝 및 서비스 탐지
- **배너 그래빙**: 버전 식별
- **웹 서비스 URL 열거**
- **커스텀 스크립트를 통한 서비스 핑거프린팅**

#### Stage 2: 전문화된 스캐닝
- **ffuf**: 5단계 디렉토리/파일 브루트포싱
  1. 재귀적 디렉토리 퍼징
  2. 일반 파일 퍼징  
  3. 확장자 퍼징
  4. API 엔드포인트 퍼징
  5. 백업/설정 파일 퍼징
- **whatweb**: 기술 스택 식별
- **nikto**: 웹 취약점 스캐닝
- **nuclei**: 템플릿 기반 취약점 탐지
- **서비스별 도구**: ssh-audit, enum4linux 등

#### 결과 처리 및 AI 학습 데이터 생성
- **구조화된 JSON 출력**: 프로그래밍 방식 분석용
- **자연어 보고서**: LLM 분석용
- **도구 간 발견사항 자동 상관관계 분석**
- **임시 파일 정리 및 리소스 관리**

---

##  사용법

### 환경 설정 및 관리

```bash
# 초기 취약점 환경 설정
./setup.sh

# 모든 취약점 서비스 시작
cd hacklipse-victim-complete/
./run-all.sh

# 서비스 연결성 테스트
./test-connectivity.sh

# 모든 서비스 정지 및 정리
./stop-all.sh
```

### OSINT 스캐닝 실행

```bash
# 종합 OSINT 파이프라인 실행 (권장)
python3 pipe_annotated.py -t localhost
python3 pipe_annotated.py -t 192.168.1.100 --verbose

# 결과를 특정 디렉토리에 저장
python3 pipe_annotated.py -t localhost -o ./scan_results

# 타임아웃 설정 (초 단위)
python3 pipe_annotated.py -t localhost --timeout 600
```

### Docker 컨테이너 관리

```bash
# 서비스 시작/정지
docker compose up -d          # 백그라운드에서 서비스 시작
docker compose down -v        # 서비스 정지 및 볼륨 제거
docker compose ps             # 컨테이너 상태 확인
docker compose logs victim-main # 로그 확인

# 모니터링 대시보드 접근
curl http://localhost:8084    # 상태 확인
```

### 서비스 접근 포인트

| 서비스 | URL/주소 | 인증정보 | 취약점 유형 |
|--------|----------|----------|-------------|
| Apache (취약점) | http://localhost:8080 | - | SQL injection, File upload |
| Nginx (보조) | http://localhost:8081 | - | Directory listing |
| WordPress 4.7.1 | http://localhost:8082 | admin/admin | CVE-2017-1001000 |
| Drupal 7.67 | http://localhost:8083 | admin/admin | CVE-2018-7600 |
| 커스텀 서버 | http://localhost:9999 | - | Path traversal |
| MySQL | localhost:3306 | admin/admin | Weak auth |
| SSH | localhost:2222 | admin/admin123 | Weak passwords |
| FTP | localhost:2121 | anonymous | Anonymous access |
| Redis | localhost:6379 | (인증없음) | No authentication |

---

##  데이터 플로우

```
1. 대상 지정 → nmap 발견
2. 서비스 열거 → 도구 선택  
3. 병렬 전문화 스캐닝
4. 결과 집계 및 상관관계 분석
5. 보고서 생성 (JSON + Markdown)
6. 정리 및 리소스 관리
```

### 생성되는 출력 파일

- **JSON 결과**: `osint_results_[target]_[timestamp].json`
- **자연어 보고서**: `security_report_[target]_[timestamp].md`
- **도구별 상세 결과**: nmap, nikto, nuclei 개별 출력 파일

---

##  개발 환경

### 필수 도구 및 의존성

**보안 도구**:
- `nmap` - 네트워크 발견 및 포트 스캐닝
- `whatweb` - 웹 기술 식별
- `nikto` - 웹 취약점 스캐너  
- `nuclei` - 템플릿 기반 취약점 스캐너
- `ffuf` - 웹 퍼저 (SecLists 필요)
- `docker` & `docker-compose` - 컨테이너 관리

**Python 환경**:
- **메인 스크립트**: `pipe_annotated.py` (한국어 주석 버전)
- **의존성**: asyncio, subprocess, json, re 라이브러리
- **아키텍처**: 동시 도구 실행을 위한 Async/await 패턴
- **에러 처리**: 타임아웃 관리, 우아한 성능 저하, 자동 정리

### 테스팅 워크플로우

1. `./run-all.sh`로 취약점 환경 시작
2. `./test-connectivity.sh`로 서비스 초기화 대기
3. localhost 서비스에 대해 OSINT 도구 실행  
4. 생성된 JSON/markdown 보고서에서 결과 확인
5. `./stop-all.sh`로 환경 정지

### 보안 고려사항

- **localhost 전용 설계**: 모든 스캐닝은 로컬호스트에서만 수행
- **의도적 약한 인증**: 테스팅용으로 의도적으로 약한 자격증명 사용
- **의도적 취약점 포함**: 환경에 의도적 취약점(CVE) 포함
- **공개 네트워크 배포 금지**: 취약점 환경을 공개 네트워크에 배포하지 않음
- **정기적 정리**: 스캔 결과 및 임시 파일의 정기적 정리

---

##  연구 일정 및 마일스톤

### Phase 1: 데이터 수집 (5-6월)
- OSINT 정보 수집 자동화
- 다양한 환경에서의 데이터 수집

### Phase 2: 모의해킹 및 분류 (7-8월)  
- 실제 취약점 발굴 및 익스플로잇
- 취약점 유형별 분류 체계 구축

### Phase 3: 데이터셋 구축 (9-10월)
- AI 학습용 데이터셋 구조화
- 데이터 라벨링 및 검증

### Phase 4: AI 모델 개발 (11-12월)
- LLM 파인튜닝 또는 커스텀 분류모델 설계
- 모델 학습 및 평가

### Phase 5: 시스템 통합 (1-2월)
- 자동화 시스템 통합
- UI/CLI 도구 개발

### Phase 6: 테스트 및 시연 (3-4월)
- 실제 환경에서의 테스트
- 연구 결과 발표 및 시연

---

##  Claude AI와의 협업 가이드라인

### Claude의 역할

1. **컨설팅**
   - OSINT 수집 자동화 스크립트 설계
   - 모의해킹 결과 라벨링 기준 제안
   - AI 학습용 데이터셋 설계 지원
   - 모델 구조 제안 (LLM, 클러스터링, 분류기 등)

2. **아이디어 브레인스토밍**
   - 자동화된 취약점 탐지 방법 논의
   - 오픈소스 도구 활용 방안 제안
   - AI 모델 성능 평가 지표 제안

3. **코드 작성**
   - 데이터 크롤러 예제 코드
   - AI 모델 학습 파이프라인 예제
   - FastAPI/Flask 결과 리포트 서버 구축

4. **문서화 지원**
   - 국문/영문 보고서 초안
   - 발표 슬라이드 목차 제안
   - 연구계획서 정리

5. **윤리적 고려사항**
   - AI 보안 진단의 법적 윤리적 가이드라인
   - 데이터 프라이버시 고려사항

### 협업 방식
- 구체적이고 구조화된 응답 제공
- 실제 연구회의에서 활용 가능한 수준의 결과물 생성
- 적극적인 질문을 통한 상호작용
- 코드, 아키텍처, 문서 초안의 즉시 생성

---

##  현재 개발 상태 및 향후 개선사항

### 현재 구현된 기능
-  2단계 OSINT 파이프라인 (`pipe_annotated.py`)
-  Docker 기반 취약점 환경 (`hacklipse-victim-complete/`)
-  비동기 병렬 스캐닝
-  AI 학습용 자연어 보고서 생성
-  SecLists 자동 탐지 및 활용

### 개선 예정 사항
- **로직 추가**
  - 도메인/IP 자동 감지 및 /etc/hosts 매핑
  - nuclei 에러 해결 및 안정화
  - ffuf 워드리스트 최적화

- **확장 계획**
  - HTB, THM 등 추가 LAB 환경 지원
  - 더 다양한 취약점 시나리오 추가
  - 실시간 모니터링 및 알림 시스템

---

##  결과 분석 및 활용

OSINT 도구들이 생성하는 종합 보고서는 다음을 포함합니다:

- **포트 스캔 결과**: 서비스 버전 정보
- **웹 기술 스택 식별**: 사용된 프레임워크 및 라이브러리
- **발견된 디렉토리 및 파일**: 숨겨진 리소스
- **취약점 스캔 결과**: 알려진 취약점 매칭
- **공격 표면 분석**: 잠재적 진입점 평가
- **자연어 보안 평가**: AI 학습용 구조화된 분석

생성된 보고서를 통해 공격 벡터를 이해하고 방어 역량을 개선하는 데 활용합니다.

---

** 중요**: 이 프로젝트는 방어적 보안 연구를 위한 것입니다. 모든 도구와 환경은 localhost 테스팅용으로만 설계되었으며, 절대 인터넷에 노출해서는 안 됩니다.

---

*Hacklipse Team - 2025 AI-based Automated Vulnerability Detection Framework*