# Python ASM Framework (Discovery + Mapping, No Exploitation)

이 프로젝트는 Attack Surface Management(ASM) 관점에서 다음을 자동화합니다.

- Technical Attack Surface: 포트/서비스/버전 식별(nmap -sV), HTTP 헤더 기반 정체 보강
- Functional Attack Surface: Swagger(OpenAPI) 기반 API 구조 파악 + Selenium(관찰-only) 기반 UI 기능 목록화
- Vulnerability Knowledge Mapping: Vulners / NVD를 통한 CVE "지식 매핑"(공격/재현 없음)
- Risk Scoring: 노출/구성/기능 구조/지식 매핑을 합친 점수화
- Report: result.json + report.md 자동 생성

> ⚠️ 본 도구는 공격(Exploit), 인증 우회, 데이터 변조 기능을 포함하지 않습니다.
> 반드시 본인이 소유/관리하는 자산 또는 명시적으로 허가된 실습 환경에서만 사용하세요.

---

## 🎯 프로젝트 목표 (Project Goals)

- 단순 취약점 스캔을 넘어선 **ASM 사고 흐름(Workflow) 구현**
- "무엇이 열려 있는가"에서 나아가 **"왜 공격 표면이 되는가"**를 설명 가능하도록 모델링
- **직접적인 공격 없이** 리스크를 정량적·정성적으로 평가하는 구조 설계

---

## 🧠 핵심 개념 (Key Concepts)

이 프레임워크의 범위와 한계를 명확히 정의합니다.

### ✅ 이 프로젝트가 수행하는 것 (IS)
- **공격 표면 식별 (Discovery)**: 자산의 노출된 지점 파악
- **기술적/기능적 모델링**: 시스템 구조 및 기능적 접점 분석
- **CVE 지식 매핑**: Vulners / NVD 등 공개 DB 연동
- **노출 기반 리스크 스코어링**: 발견된 정보에 기반한 위험도 산정
- **보안 리포트 자동화**: 분석 결과 리포트 생성

### ❌ 이 프로젝트가 수행하지 않는 것 (IS NOT)
- **공격 프레임워크 아님**: Exploitation 수행 불가
- **인증 우회 시도 안 함**: Authentication bypass 기능 없음
- **악성 페이로드 전송 안 함**: Payload delivery 기능 없음
- **취약점 증명(PoC) 안 함**: 실제 공격 가능 여부 테스트 안 함
- **침투 테스트 도구 아님**: 시스템에 영향을 주는 침해 행위 없음

---

## 🧱 아키텍처 개요 (Architecture Overview)

```text
Target Asset (대상 자산)
│
├─ Technical Attack Surface (기술적 공격 표면)
│   ├─ Port / Service / Version (nmap -sV 활용)
│   ├─ OS Guessing (운영체제 추정)
│   ├─ HTTP Header & Config Observation (설정 관찰)
│   └─ NSE (safe, discovery 카테고리 한정)
│
├─ Functional Attack Surface (기능적 공격 표면)
│   ├─ Swagger(OpenAPI) API Structure Parsing
│   └─ UI Function Observation (Selenium 활용, 관찰 전용)
│
├─ Vulnerability Knowledge Mapping (취약점 지식 매핑)
│   ├─ Vulners API (CVE 연결)
│   └─ NVD API (공식 레퍼런스 정보 보강)
│
└─ Risk Scoring & Reporting (위험도 평가 및 보고)

```

---

## 🔍 주요 기능 (Features)

### 1. 기술적 공격 표면 식별 (Technical Discovery)

* 전체 TCP 포트 디스커버리
* 서비스 및 버전 정보 식별
* OS 핑거프린팅 (최선 노력 방식)
* HTTP 보안 헤더 관찰 및 분석
* **Nmap NSE 스크립트는 `safe` 및 `discovery` 카테고리로 엄격히 제한**

### 2. 기능적 공격 표면 매핑 (Functional Mapping)

* Swagger / OpenAPI 파싱 (API 구조 분석)
* Selenium 기반의 UI **단순 관찰 (Observation)**
* *클릭, 입력, 인증 시도, 상태 변경 행위 없음*



### 3. 취약점 지식 매핑 (Knowledge Mapping)

* Vulners를 통한 CVE 조회 (문자열 기반 매핑)
* NVD를 통한 정보 보강 (공식 CVE 상세 내용)
* **실제 Exploit 코드는 실행하지 않음**

### 4. 리스크 스코어링 엔진 (Risk Scoring Engine)

* 노출도(Exposure) 기반 점수 산정
* 설정(Configuration) 기반 점수 산정
* 기능적 표면(Functional surface) 가중치 적용
* CVSS 기반의 지식 스코어링
* 자산 단위의 리스크 통합 산출

### 5. 리포트 자동 생성 (Auto-generated Reports)

* 정규화된 데이터 포맷: JSON (`result.json`)
* 가독성 높은 보고서: Markdown (`report.md`)

---

## 📁 프로젝트 구조 (Project Structure)

```bash
python-asm-framework/
├─ asm.py               # 메인 실행 파일
├─ config.yaml          # 설정 파일
├─ requirements.txt     # 의존성 라이브러리 목록
├─ core/                # 핵심 로직
├─ scanner/             # 스캔 모듈 (Nmap, Selenium 등)
├─ parser/              # 데이터 파싱 모듈
├─ vuln/                # 취약점 DB 연동 모듈
├─ risk/                # 리스크 계산 엔진
├─ report/              # 리포트 생성 모듈
└─ output/              # 결과물 저장 경로

```

---

## 🚀 빠른 시작 (Quick Start)

### 1. 요구 사항 (Requirements)

* Python 3.10 이상
* Nmap 설치 및 PATH 환경변수 등록 필수
* (선택) Selenium 관찰 기능을 위한 Google Chrome 브라우저

### 2. 의존성 설치

```bash
pip install -r requirements.txt

```

### 3. 대상 설정

`config.yaml` 파일을 수정하여 분석 대상을 설정합니다.

```yaml
target:
  ip: 127.0.0.1
  base_url: http://127.0.0.1:3000
  swagger_path: /api-docs/swagger.yaml
```

**필드 설명:**

| 필드 | 설명 | 예시 |
|------|------|------|
| `ip` | **nmap으로 포트를 자동 스캔할 대상 IP** (포트를 미리 알 필요 없음) | `192.168.1.100`, `10.0.0.50`, `54.123.45.67` (EC2) |
| `base_url` | **HTTP 서비스가 실제로 돌아가는 주소** (프로토콜+호스트+포트) → HTTP 헤더 분석, Swagger 조회, Selenium UI 수집에 사용 | `http://localhost:3000`, `http://192.168.1.100:8080`, `http://54.123.45.67:5000` |
| `swagger_path` | Swagger/OpenAPI 문서의 상대 경로 (base_url에 추가됨) | `/api-docs/swagger.yaml`, `/openapi.json`, `/v3/api-docs` |

**`ip` vs `base_url` 차이:**
- **`ip` (필수)**: nmap이 자동으로 모든 열린 포트를 찾는다 → 포트를 미리 알 필요 없음
- **`base_url` (필수)**: 실제 웹 서비스가 돌아가는 주소 → 보안 헤더, Swagger, UI 등을 프로빙함

**예시:**
- **로컬 테스트:** 
  - `ip: 127.0.0.1` (nmap이 자동으로 포트 찾음)
  - `base_url: http://127.0.0.1:3000` (알려진 포트에서 HTTP 프로빙)
  
- **내부망 서버:**
  - `ip: 192.168.1.50` (nmap이 자동으로 열린 포트 찾음)
  - `base_url: http://192.168.1.50:8080` (해당 포트의 웹 서비스 분석)
  
- **EC2 배포 (포트 미리 모를 때):**
  - `ip: 54.123.45.67` (nmap이 자동으로 모든 열린 포트 검색)
  - `base_url: http://54.123.45.67:3000` (EC2에서 실제 실행 중인 포트)

> **💡 TIP:** EC2에 배포한 경우, 포트를 미리 모르면 `base_url`은 임시로 `http://54.123.45.67:80`으로 설정해도 됨. nmap이 자동으로 실제 열린 포트들을 찾아주니까! (Swagger/UI 수집은 설정한 base_url에서만 시도)

```

### 4. 실행

```bash
python asm.py

```

### 5. 결과 확인

* 데이터: `output/result.json`
* 보고서: `output/report.md`

---

## 🧪 권장 테스트 환경

이 프로젝트는 의도적으로 취약하게 구성된 환경이나 본인 소유의 환경에서 테스트하는 것을 권장합니다.

* 로컬 테스트 서버
* 개인 실습용 VM
* **OWASP Juice Shop** (로컬 Docker 배포 권장)

**Example (Juice Shop 실행):**

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop

```

---

## ⚠️ 법적 및 윤리적 고지 (Legal & Ethical Notice)

**이 프로젝트는 교육 및 연구 목적으로만 사용되어야 합니다.**

* ✔ **허용:** 탐색(Discovery), 관찰(Observation), 지식 매핑(Knowledge mapping)
* ❌ **금지:** 익스플로잇(Exploitation), 인증 우회, 데이터 변조, 침습적 테스트

**반드시 본인이 소유하거나 분석 허가를 명확히 받은 시스템에 대해서만 도구를 사용하십시오.** 도구의 오용이나 불법적인 활동으로 인한 책임은 전적으로 사용자에게 있습니다.

---

## 🧩 왜 중요한가? (ASM Perspective)

> "취약점(Vulnerability) 그 자체가 침해(Breach)는 아닙니다.
> **노출(Exposure) + 맥락(Context) + 능력(Capability)**이 결합될 때 진짜 리스크가 됩니다."

이 프레임워크는 다음을 목표로 합니다:

1. 자산이 **왜** 위험해질 수 있는지 이해
2. 실제 공격 이전에 공격 표면을 **모델링**
3. 보안 설계, 강화(Hardening), 우선순위 산정을 위한 근거 마련

---

## 📌 예상 사용자 (Intended Audience)

* 정보보안 전공 학생 및 교육생
* Blue Team / Purple Team 엔지니어
* ASM / 자산 관리 실무자
* 공격 없이 공격자의 사고방식을 배우고 싶은 연구자

---

## 📄 라이선스 (License)

본 프로젝트는 교육용으로 배포됩니다. 상업적 이용이나 공격적인 목적으로의 사용을 지양합니다.

---

## 🧠 마치며 (Final Note)

이 저장소는 해킹 능력이 아닌 **보안 성숙도(Security Maturity)**를 보여주기 위함입니다.

**"어떻게 공격하는가"를 아는 것만큼, "어디서 멈춰야 하는가"를 아는 것이 중요합니다.**

```

```