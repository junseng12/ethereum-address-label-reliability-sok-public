# Ethereum Address Label Reliability — Replication Package

이 저장소는 **Same Address, Different Truth: How Labeling Paradigms Shape Ground Truth in Ethereum Anomaly Detection Datasets** 연구의 비공개 협업용 재현 패키지입니다.

15개 Ethereum 주소 데이터셋에서 실제 분석에 사용한 입력 파일, 분석 코드, 최종 결과와 방법론 문서를 함께 제공합니다. 원본 라벨을 보존한 상태에서 주소를 정규화하고, 동일 주소의 모든 데이터셋 조합을 비교하여 라벨 관계·원천 출처·수집 시점 차이를 분석했습니다.

## 핵심 결과

- Address 기반 데이터셋: 15개
- 2개 이상 데이터셋에 등장한 고유 주소: 24,495개
- Address–Dataset Pair: 104,673개
- Taxonomy Conflict: 10,512 pairs / 2,183 addresses
- Strong Conflict: 6 pairs / 5 addresses
- Root Source 관계 평가 대상: 86,395 pairs
- `Phishing ↔ Scam`: 엄격 기준에 따라 `Taxonomy Conflict`

## 파일 구조

```text
├─ code/                         분석 및 검증 코드
│  ├─ phase1/                    최초 주소·라벨 추출 및 중복 분석
│  ├─ phase3/                    추가 데이터셋 반영 및 신뢰성 전처리
│  ├─ phase4/                    계정 유형 검증·최종 재표준화
│  └─ verify_manifest.py         입력 파일 SHA-256 검증
├─ data/
│  ├─ used_inputs/               15개 데이터셋에서 실제 사용한 파일만 수록
│  ├─ dataset_manifest.csv       출처·버전·라이선스·공유 조건
│  └─ file_manifest.csv          입력 파일별 크기·SHA-256
├─ results/                      최종 분석 결과 00–07 및 보고서
├─ docs/                         발표자료와 연구 참고 문서
├─ third_party_licenses/         확인된 원 데이터셋 라이선스
└─ DATA_AVAILABILITY.md          공개·재배포 시 주의사항
```

## 결과 파일 순서

1. `00_주소_계정유형_검증.csv` — EOA, Delegated EOA, Conventional Contract 검증
2. `01_전처리_주소라벨_통합표.csv` — 15개 데이터셋의 정규화된 주소·원본 라벨 통합
3. `02_라벨_속성_정의.csv` — 원본 라벨의 확실성·축·표준 유형 매핑
4. `03_중복주소_데이터셋교집합.csv` — 중복 주소별 데이터셋 교집합
5. `04_중복주소_데이터셋Pair비교.csv` — 동일 주소의 모든 Dataset Pair 비교
6. `05_충돌주소_원인분석.csv` — 비동일 라벨 Pair의 Root·Label·Temporal 3축 분석
7. `06_관계및최종원인_7분류_요약.csv` — 관계 및 원인 분류 요약
8. `07_주요충돌_개별검증_최종해석.csv` — 주요 충돌과 개별 검증 상태
9. `ANALYSIS_REPORT.md` — 방법론·수치·해석을 정리한 최종 보고서

## 재현 순서

```text
code/verify_manifest.py
code/phase1/run_address_label_agreement.py
code/phase3/run_analysis.py
code/phase4/audit_account_types.py
code/phase4/restandardize_label_analysis.py
```

스크립트에는 기존 Windows 연구 환경의 경로가 남아 있으므로 다른 환경에서 실행할 때 기준 경로를 수정해야 합니다. 계정 유형 검증에는 Ethereum JSON-RPC 접속이 필요합니다.

## 분석 기준

- `Abnormal`, `Normal`, `Uncertain`은 라벨 확실성을 나타냅니다.
- `Phishing`, `Scam`, `Hack/Exploit`, `Ponzi`, `Rug Pull`, `Wash Trading` 등은 Behavior 속성입니다.
- `Sanctioned`는 공격 행위가 아니라 Status 속성입니다.
- unlabeled, non-seed, random-sampled 주소는 자동으로 Normal로 간주하지 않습니다.
- 동일 Root Source는 데이터셋의 독립성을 약화할 수 있지만 주소별 직접 계보를 증명하지는 않습니다.

## Git LFS 및 공개 범위

대용량 입력·결과 4개는 Git LFS로 관리합니다.

- `data/used_inputs/BERT4ETH/Data/normal_trans.zip`
- `data/used_inputs/XBlock/Ethereum_Phishing_Transaction_Network/MulDiGraph.pkl`
- `results/01_전처리_주소라벨_통합표.csv`
- `results/05_충돌주소_원인분석.csv`

```bash
git lfs install
git lfs pull
```

명시적 재배포 라이선스를 확인하지 못한 원자료가 포함되어 있어 현재 저장소는 **비공개 연구 협업용**입니다. 공개 전에는 `DATA_AVAILABILITY.md`와 `data/dataset_manifest.csv`에 따라 원자료별 공유 가능 여부를 다시 확인해야 합니다.
