# Ethereum Address Label Reliability

15개 Ethereum 주소 데이터셋의 실제 입력 파일과 동일 주소 라벨 비교 결과를 정리한 비공개 연구 재현 패키지입니다.

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
| Non-Root 데이터셋 (13) | 나머지 13개 데이터셋 | Etherscan, EtherScamDB 등 기존 원천을 가공하거나 표본·그래프·라벨을 재구성 |

15개는 모두 동일하게 주소 비교에 포함했습니다. Root/Non-Root 구분은 분석 대상을 제외하기 위한 기준이 아니라, 같은 주소와 라벨이 여러 데이터셋에서 발견됐을 때 **서로 독립적인 확인인지 동일 원천의 재사용인지** 해석하기 위한 메타정보입니다.

여기서 `Root 데이터셋`과 `Root Source`는 완전히 같은 말이 아닙니다. 예를 들어 Etherscan은 여러 데이터셋의 Root Source이지만 이번 15개 분석에서 독립된 데이터셋 하나로 직접 포함되지는 않았습니다. 전체 계보는 `results/Root_Source_Set_정규화.csv`에서 확인할 수 있습니다.

## 파일 구조

```text
├─ code/                    분석·재현 코드
├─ data/
│  ├─ used_inputs/          15개 데이터셋에서 실제 사용한 파일
│  ├─ dataset_manifest.csv  출처·버전·공유 조건
│  └─ file_manifest.csv     파일 크기·SHA-256
├─ results/                 최종 결과 00–07 및 분석 보고서
├─ docs/                    발표·참고 문서
├─ third_party_licenses/    확인된 원자료 라이선스
└─ DATA_AVAILABILITY.md     공개·재배포 주의사항
```

`results/`의 흐름은 다음과 같습니다.

```text
00 계정 유형 검증
01 주소·원본 라벨 통합
02 라벨 속성 정의
03 중복 주소 교집합
04 Dataset Pair 비교
05 충돌 원인 3축 분석
06 관계·원인 요약
07 주요 충돌 개별 검증
ANALYSIS_REPORT.md 최종 방법론과 해석
```

## 내려받기

대용량 파일 4개는 Git LFS로 저장되어 있습니다.

```bash
git lfs install
git clone https://github.com/goneii/Anomaly-Detection.git
cd Anomaly-Detection
git lfs pull
```

- `git lfs install`: 해당 컴퓨터의 Git이 LFS 파일을 처리하도록 한 번 설정합니다.
- `git lfs pull`: GitHub에 별도로 저장된 대용량 파일의 실제 내용을 내려받습니다. 실행하지 않으면 일부 파일이 작은 LFS pointer로만 보일 수 있습니다.

Git LFS가 이미 정상 설정된 컴퓨터에서는 `git clone` 과정에서 대용량 파일까지 자동으로 내려받을 수 있지만, `git lfs pull`을 한 번 실행하면 누락 여부를 확실히 확인할 수 있습니다.

## 공동연구자 공유

저장소가 Private이므로 먼저 공동연구자를 초대해야 합니다.

1. GitHub 저장소의 `Settings` → `Collaborators`로 이동합니다.
2. `Add people`에서 선배님의 GitHub 계정 또는 이메일을 입력합니다.
3. 초대 수락 후 아래 주소를 전달합니다.

`https://github.com/goneii/Anomaly-Detection`

웹에서 결과만 확인할 수 있지만, 전체 입력 파일까지 내려받으려면 위의 Git LFS 명령을 사용해야 합니다.

## 주의사항

- `Abnormal`, `Normal`, `Uncertain`은 라벨 확실성입니다.
- Phishing, Scam, Hack/Exploit 등은 Behavior 속성입니다.
- Sanctioned는 Behavior가 아니라 Status 속성입니다.
- unlabeled·non-seed·random-sampled 주소를 자동으로 Normal로 간주하지 않습니다.
- Root 관계는 Dataset-level 계보이며 개별 주소의 직접 유입 경로를 증명하지 않습니다.
- 명시적 재배포 라이선스를 확인하지 못한 원자료가 있어 현재 저장소는 Private으로 유지해야 합니다.
