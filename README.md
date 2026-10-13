# Ethereum Address Label Reliability

15개 Ethereum 주소 데이터셋의 실제 입력 파일과 동일 주소 라벨 비교 결과를 정리한 공개 연구 재현 패키지입니다.

## 핵심 결과

- 중복 고유 주소: 24,495개
- Address–Dataset Pair: 104,673개
- Taxonomy Conflict: 10,512 pairs / 2,183 addresses
- Strong Conflict: 6 pairs / 5 addresses
- `Phishing ↔ Scam`은 엄격 기준의 `Taxonomy Conflict`

## Root와 Non-Root

| 구분 | 15개 분석 데이터셋 내 구성 | 의미 |
|---|---|---|
| Root 데이터셋 (2) | EtherScamDB, OFAC Ethereum Addresses | 자체 Registry 또는 공식 지정 목록을 직접 제공 |
| Non-Root 데이터셋 (13) | BERT4ETH, Farrugia, EthereumHeist, FDGNN, Forta, Trans2Vec, Real-CATS, RiskProp, XBlock, scamsonethereum, DA-HGNN, EX-Graph, Cryptocurrency Exchange Scams | Etherscan, EtherScamDB 등 기존 원천을 가공하거나 표본·그래프·라벨을 재구성 |

15개는 모두 동일하게 주소 비교에 포함했습니다. Root/Non-Root 구분은 분석 대상을 제외하기 위한 기준이 아니라, 같은 주소와 라벨이 여러 데이터셋에서 발견됐을 때 **서로 독립적인 확인인지 동일 원천의 재사용인지** 해석하기 위한 메타정보입니다.

여기서 `Root 데이터셋`과 `Root Source`는 완전히 같은 말이 아닙니다. 예를 들어 Etherscan은 여러 데이터셋의 Root Source이지만 이번 15개 분석에서 독립된 데이터셋 하나로 직접 포함되지는 않았습니다. 전체 계보는 `results/Root_Source_Set_정규화.csv`에서 확인할 수 있습니다.

## 파일 구조

```text
├─ code/                    분석·재현 코드
├─ data/
│  ├─ used_inputs/          15개 데이터셋에서 실제 사용한 파일
│  ├─ dataset_manifest.csv  출처·버전·공유 조건
│  └─ file_manifest.csv     파일 크기·SHA-256
├─ results/                 최종 결과 00–08 및 분석 보고서
├─ docs/                    발표·참고 문서
├─ third_party_licenses/    확인된 원자료 라이선스
└─ DATA_AVAILABILITY.md     공개·재배포 주의사항
```

## 결과 파일 안내

`results/`는 계정 유형 검증과 전처리부터 동일 주소 비교, 충돌 해석 및 후속 분석까지 순서대로 구성되어 있습니다.

| 파일 | 역할 |
|---|---|
| `00_주소_계정유형_검증.csv` | 분석 주소를 EOA, Delegated EOA, Conventional Contract로 확인한 기본 유형 검증 결과입니다. 본 주소 분석에서는 Conventional Contract를 제외합니다. |
| `01_전처리_주소라벨_통합표.csv` | 15개 데이터셋에서 주소와 Original Label을 추출하고 주소 형식, 라벨 확실성, 표준 유형 등을 통합한 공통 전처리 결과입니다. |
| `02_라벨_속성_정의.csv` | Original Label을 `Abnormal·Normal·Uncertain`, `Behavior·Status` 및 Phishing, Scam, Hack/Exploit 등의 표준 유형으로 매핑한 전처리 기준표입니다. |
| `03_중복주소_데이터셋교집합.csv` | 2개 이상의 데이터셋에 등장한 동일 주소와 데이터셋별 표준 유형을 가로형 교집합 표로 정리합니다. |
| `04_중복주소_데이터셋Pair비교.csv` | 동일 주소가 존재하는 모든 Dataset A–Dataset B 조합을 생성하여 라벨 관계, Root Source 관계 및 시간 정보를 비교합니다. |
| `05_충돌주소_원인분석.csv` | 충돌 Pair를 라벨 속성, Root Source, Temporal Information의 세 축으로 해석한 결과입니다. |
| `06_관계및최종원인_7분류_요약.csv` | 주소 충돌을 Multi-behavior, Taxonomy Difference, Coverage/Granularity Difference 등 최종 원인 체계로 심화 분석한 요약입니다. |
| `07_주요충돌_개별검증_최종해석.csv` | Taxonomy Conflict와 Strong Conflict의 개별검증 상태, 근거 및 최종 해석을 정리합니다. |
| `08_라벨링패러다임_Research_vs_Community_분석.csv` | `03`, `04`, `05` 결과를 활용하여 Research-based와 Community-based 데이터셋의 주소·표준 유형 충돌률과 Root Source 영향을 비교합니다. |
| `Root_Source_Set_정규화.csv` | 데이터셋별 원천 출처를 정규화된 Root Source Set으로 정리한 메타데이터입니다. |
| `ANALYSIS_REPORT.md` | 전체 방법론, 핵심 수치, 결과 해석과 한계를 설명하는 최종 보고서입니다. |

전체 흐름은 `00 기본 유형 검증 → 01·02 전처리 → 03 교집합 → 04 Pair 비교 → 05 충돌 원인 3축 분석 → 06·07 심화 분석 → 08 라벨링 패러다임 분석`입니다.

## 내려받기

대용량 파일 4개는 Git LFS로 저장되어 있습니다.

```bash
git lfs install
git clone https://github.com/junseng12/ethereum-address-label-reliability-sok-public.git
cd ethereum-address-label-reliability-sok-public
git lfs pull
```

- `git lfs install`: 해당 컴퓨터의 Git이 LFS 파일을 처리하도록 한 번 설정합니다.
- `git lfs pull`: GitHub에 별도로 저장된 대용량 파일의 실제 내용을 내려받습니다. 실행하지 않으면 일부 파일이 작은 LFS pointer로만 보일 수 있습니다.

Git LFS가 이미 정상 설정된 컴퓨터에서는 `git clone` 과정에서 대용량 파일까지 자동으로 내려받을 수 있지만, `git lfs pull`을 한 번 실행하면 누락 여부를 확실히 확인할 수 있습니다.

## 주의사항

- `Abnormal`, `Normal`, `Uncertain`은 라벨 확실성입니다.
- Phishing, Scam, Hack/Exploit 등은 Behavior 속성입니다.
- Sanctioned는 Behavior가 아니라 Status 속성입니다.
- unlabeled·non-seed·random-sampled 주소를 자동으로 Normal로 간주하지 않습니다.
- Root 관계는 Dataset-level 계보이며 개별 주소의 직접 유입 경로를 증명하지 않습니다.
- 일부 제3자 원자료는 명시적인 재배포 라이선스를 확인하지 못했으므로, 재사용 전 `DATA_AVAILABILITY.md`와 각 원 출처의 최신 이용 조건을 확인해야 합니다.
