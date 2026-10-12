# Ethereum 동일 주소 라벨 충돌 분석 — 엄격 기준 최종 보고서

## 1. 최종 결론

15개 Ethereum Address/Account 데이터셋에서 중복 주소 24,495개와 Dataset Pair 104,673건을 비교했다. `Phishing ↔ Scam` 특별 호환 규칙을 제거한 엄격한 세부유형 기준에서 주요 충돌은 **10,518 Pair / 2,188개 고유 주소**다.

| 주요 충돌 유형 | Pair-Address | 고유 주소 | 주요 충돌 내 비율 | 의미 |
|---|---:|---:|---:|---:|
| Taxonomy Conflict | 10,512 | 2,183 | 99.942955% | 같은 Behavior 축의 구체 Abnormal 유형 차이 |
| Strong Conflict | 6 | 5 | 0.057045% | Abnormal과 명시적 Normal의 직접 모순 |
| 합계 | 10,518 | 2,188 | 100% | 개별검증 대상 |

엄격 기준으로 기존 Compatible Label 중 **10,485 Pair / 2,169주소**가 Taxonomy Conflict로 이동했다. 기존 Taxonomy 27 Pair / 14주소와 합쳐 최종 Taxonomy는 **10,512 Pair / 2,183주소**다. Strong Conflict는 **6 Pair / 5주소**로 변하지 않았다.

## 2. 분석 흐름과 검증 상태

```text
00 계정유형 검증
  ↓
01 주소·Original Label 통합 및 의미 보존 전처리
  ↓
02 Label Character × Label Axis × Standard Type × 구체성 정의
  ↓
03 동일 주소 데이터셋 교집합
  ↓
04 전체 Dataset Pair의 엄격 라벨 관계 판정
  ↓
05 Same Label 제외 Pair의 Dataset-level Root Source Set × Label × Time 3축 분석
  ↓
06 관계 분포·개별검증 현황 요약
  ↓
07 주요 충돌 전체 목록: 기존 33건 검증 완료 + 신규 10,485건 검증 필요
```

00~03의 주소·계정유형·표준 라벨은 변경하지 않았다. 이번 변경은 Pair 관계 판정과 그 후속 결과에만 적용했다.

## 3. 라벨 표준화 핵심 원칙

- 주소는 소문자 `0x` + 40자리 16진수로 통일한다.
- Label Character는 `Abnormal`, `Normal`, `Uncertain`으로 구분하며, unlabeled를 Normal로 간주하지 않는다.
- Label Axis는 `Behavior`, `Status`, `Role`, `Technical Attribute`로 분리한다.
- `Unspecified Abnormal`은 악성은 확인됐지만 세부 Behavior가 불명인 포괄 라벨이다.
- `phish-hack`은 `Phishing OR Hack/Exploit` 복합 의미로 보존한다.
- Conventional Contract는 제외하고 EOA와 Delegated EOA만 03~05 비교에 포함한다.
- Original Label은 수정하지 않고 표준 비교용 Claim을 별도로 둔다.

## 4. 엄격 Pair 판정 규칙

1. 양쪽 모두 Uncertain이면 `Uncertain Comparison`, 한쪽만 Uncertain이면 `Label Coverage Difference`다.
2. 공통 Label Axis가 없으면 `Status–Behavior Relation` 또는 `Axis Difference`이며 Behavior 충돌로 세지 않는다.
3. 공통 축의 명시적 Abnormal ↔ Normal만 `Strong Conflict`다.
4. 포괄·세부유형미상 ↔ 구체적은 `Granularity Difference`다.
5. OR 복합 라벨과 상대 라벨에 공통 구성요소가 있으면 `Compatible Label`이다.
6. 같은 축의 구체 Abnormal 유형 집합에 공통 구성요소가 없으면 `Taxonomy Conflict`다.
7. 엄격 기준에서 `Phishing ↔ Scam`과 `Phishing | Hack/Exploit ↔ Scam`은 `Taxonomy Conflict`다.

`Taxonomy Conflict`는 자동으로 한쪽 라벨이 틀렸다는 의미가 아니다. 복수 행위, taxonomy 정의, GT 구성, processing, 시간 변화 및 label error를 구분하기 위한 검증 후보이다.

## 5. Pair 관계 7분류 결과

| 관계 | Pair-Address | 전체 비율 | 고유 주소 | 해석 |
|---|---:|---:|---:|---:|
| Same Label | 18,278 | 17.462001% | 5,817 | 동일한 의미의 구조화 Claim |
| Compatible Label | 17,571 | 16.786564% | 5,861 | 공통 구성요소 또는 병존 가능한 추가 속성 |
| Granularity Difference | 36,008 | 34.400466% | 6,565 | 포괄·구체 라벨의 정보량 차이 |
| Uncertain / Coverage Difference | 22,289 | 21.293934% | 18,530 | 미확인 또는 한쪽만 명시적 판정 |
| Axis Difference | 9 | 0.008598% | 6 | 서로 다른 의미축의 정보 |
| Taxonomy Conflict | 10,512 | 10.042704% | 2,183 | 같은 Behavior 축의 구체 유형 불일치 |
| Strong Conflict | 6 | 0.005732% | 5 | Abnormal과 명시적 Normal의 직접 모순 |

전체 Pair 수는 변경 전후 동일하다. 특별 호환 규칙 제거로 `Compatible Label`이 28,056에서 **17,571**로 감소하고 `Taxonomy Conflict`가 27에서 **10,512**로 증가했다. 나머지 관계 수는 변하지 않았다.

## 6. Taxonomy Conflict 세부 내용

| Label 조합 | Pair | 고유 주소 | Taxonomy 내 비율 | 주요 충돌 내 비율 |
|---|---:|---:|---:|---:|
| Phishing ↔ Scam | 7,162 | 2,160 | 68.131659% | 68.092793% |
| Hack/Exploit \| Phishing ↔ Scam | 3,323 | 1,809 | 31.611492% | 31.593459% |
| Hack/Exploit ↔ Phishing | 12 | 9 | 0.114155% | 0.114090% |
| Phishing ↔ Wash Trading | 8 | 3 | 0.076104% | 0.076060% |
| Hack/Exploit \| Phishing ↔ Wash Trading | 3 | 3 | 0.028539% | 0.028523% |
| Hack/Exploit ↔ Wallet Drainer | 2 | 1 | 0.019026% | 0.019015% |
| Phishing ↔ Wallet Drainer | 2 | 1 | 0.019026% | 0.019015% |

- 새 엄격 기준의 두 조합이 Taxonomy Conflict의 **99.743151%**를 차지한다.
- `Phishing ↔ Scam` 2,160주소와 복합형 `Phishing | Hack/Exploit ↔ Scam` 1,809주소 중 1,800주소가 겹치며, 두 조합의 합집합은 2,169주소다.
- 조합별 고유 주소는 동일 주소가 여러 Dataset Pair와 Label 조합을 만들 수 있으므로 단순 합산하지 않는다.

### Taxonomy Conflict가 많이 발생한 Dataset Pair

| Dataset Pair | Pair | 고유 주소 | Taxonomy 내 비율 |
|---|---:|---:|---:|
| Forta Labelled Datasets ↔ Real-CATS | 1,995 | 1,995 | 18.978311% |
| BERT4ETH ↔ Real-CATS | 1,701 | 1,701 | 16.181507% |
| EtherScamDB ↔ Forta Labelled Datasets | 1,466 | 1,466 | 13.945967% |
| BERT4ETH ↔ EtherScamDB | 1,458 | 1,458 | 13.869863% |
| EtherScamDB ↔ FDGNN Fraud Address Dataset | 723 | 723 | 6.877854% |
| FDGNN Fraud Address Dataset ↔ Real-CATS | 655 | 655 | 6.230974% |
| EtherScamDB ↔ XBlock Ethereum Phishing Transaction Network | 480 | 480 | 4.566210% |
| Real-CATS ↔ XBlock Ethereum Phishing Transaction Network | 448 | 448 | 4.261796% |
| EtherScamDB ↔ Phishing Detection on Ethereum (Trans2Vec) | 434 | 434 | 4.128615% |
| Phishing Detection on Ethereum (Trans2Vec) ↔ Real-CATS | 405 | 405 | 3.852740% |
| EtherScamDB ↔ Real-CATS | 149 | 149 | 1.417428% |
| BERT4ETH ↔ Cryptocurrency Exchange Scams - Ethereum subset | 109 | 109 | 1.036910% |
| Cryptocurrency Exchange Scams - Ethereum subset ↔ Forta Labelled Datasets | 109 | 109 | 1.036910% |
| EtherScamDB ↔ RiskProp | 101 | 101 | 0.960807% |
| Real-CATS ↔ RiskProp | 93 | 93 | 0.884703% |

Dataset Pair 집중도는 데이터셋 규모·공유 주소 수·Root Source의 영향을 함께 받으므로 사건 발생 빈도로 해석하지 않는다.

## 7. Strong Conflict 세부 내용

| Label 조합 | Pair | 조합 내 고유 주소 | Strong 내 비율 |
|---|---:|---:|---:|
| Benign ↔ Wash Trading | 4 | 4 | 66.666667% |
| Benign ↔ Illicit/Criminal | 1 | 1 | 16.666667% |
| Benign ↔ Unspecified Abnormal | 1 | 1 | 16.666667% |

- `Benign ↔ Wash Trading` 4 Pair는 모두 Real-CATS ↔ EX-Graph에서 발생했다.
- 나머지 2 Pair는 동일 주소에서 RiskProp의 `ico / Benign`이 Farrugia의 `Illicit/Criminal`, scamsonethereum의 `Unspecified Abnormal`과 각각 충돌한 결과다.
- 한 주소가 2개 Dataset Pair를 만들기 때문에 Strong은 6 Pair지만 5개 고유 주소다.
- 엄격 기준은 Abnormal 내부의 세부 유형만 변경하므로 Strong Conflict 수는 변하지 않았다.

<!-- ROOT_SOURCE_SET_ANALYSIS_START -->
## 8. Dataset-level Root Source Set 분석

### 목적과 판정 단위

Root Source는 개별 주소 Label의 실제 단일 origin이 아니라 **각 Dataset이 Label 구축에 사용한 것으로 확인되는 Root Source들의 집합**으로 정의했다. 목적은 두 Dataset의 라벨 구축 원천이 얼마나 공유되는지 보조적으로 분석하는 것이다. Root 관계는 Label Relationship을 결정하지 않는다.

### Root Source normalization

| Dataset | Raw Source | Normalized Root Source Set | Completeness | 비고 |
|---|---:|---:|---:|---:|
| BERT4ETH | Etherscan phish-hack; Ethereum random EOA sampling | Etherscan | Complete | random EOA sampling은 Negative 구성 방법이며 label Root Source Set과 분리 |
| EtherScamDB | EtherScamDB Community Registry | EtherScamDB | Complete | community registry 자체를 Root로 유지 |
| Ethereum Illicit Accounts (Farrugia et al.) | EtherScamDB historical snapshot; Ethereum active-account random sample | EtherScamDB | Complete | active-account sampling은 Negative 구성 방법이며 label Root Source Set과 분리 |
| EthereumHeist | Etherscan heist/name-tag | Etherscan | Complete | Etherscan canonicalization |
| FDGNN Fraud Address Dataset | XBlock; Etherscan; CryptoScamDB; prior Ponzi dataset | CryptoScamDB \| Etherscan \| Prior Ponzi Dataset | Partial | XBlock은 Etherscan leaf Root로 resolve; prior Ponzi dataset의 로컬 원천명이 포괄적 |
| Forta Labelled Datasets | Etherscan phish-hack/exploit/heist lists | Etherscan | Complete | Etherscan 목록명을 canonicalization |
| OFAC Ethereum Addresses | OFAC Enhanced SDN | OFAC | Complete | 공식 OFAC SDN |
| Phishing Detection on Ethereum (Trans2Vec) | EtherScamDB; Etherscan | EtherScamDB \| Etherscan | Complete | 두 확인 원천 보존 |
| Real-CATS | Chainabuse; WalletExplorer; Etherscan; Real-CATS supplemental source | Chainabuse \| Etherscan \| Real-CATS Supplemental Source (Unspecified) \| WalletExplorer | Partial | supplemental source의 세부 원천이 공개 파일에서 특정되지 않음 |
| RiskProp | Etherscan labels | Etherscan | Complete | Etherscan canonicalization |
| XBlock Ethereum Phishing Transaction Network | Etherscan phish-hack; Etherscan 2-hop crawl | Etherscan | Complete | 2-hop crawl은 graph 구성 방식이며 label Root는 Etherscan |
| scamsonethereum | Mixed 14 blacklists; prior research; Etherscan | Etherscan \| Multiple Blacklists \| Prior Research | Partial | 14개 blacklist와 prior research의 세부 이름이 모두 보존되지 않음 |
| DA-HGNN Phishing Detection Dataset | Etherscan phishing labels | Etherscan | Complete | Etherscan canonicalization |
| EX-Graph – Wash-Trading | Dune Analytics wash-trading identification | Dune Analytics | Complete | Dune detection result |
| Cryptocurrency Exchange Scams - Ethereum subset | EtherScamDB; CryptoScamDB; typosquatting search | CryptoScamDB \| EtherScamDB \| Typosquatting Search | Complete | 공개 연구의 upstream report와 typosquatting construction을 leaf 수준으로 보존 |

`Complete/Partial`은 Source Set 정보의 완전성이고 Root Relation과 별도다. Negative sampling 및 graph crawl은 구축 방법으로 기록하되 label provenance Root와 혼합하지 않았다. FDGNN의 XBlock 의존성은 확인 가능한 leaf인 Etherscan으로 resolve했다.

### Root Relation 변경 전후

| 관계 | 변경 전 | 변경 후 |
|---|---:|---:|
| 동일 | 11,242 | 27,986 |
| 일부 공유 | 2,953 | 40,271 |
| 서로 다름 | 38,407 | 18,138 |
| 확인 불가 | 33,793 | 0 |
| 합계 | 86,395 | 86,395 |

변경 후 분포는 **동일 27,986 / 일부 공유 40,271 / 서로 다름 18,138**, 합계 86,395 Pair다. `확인 불가`는 남지 않는다.

### 전체 관계 전환

| 기존 관계 | 새 관계 | Pair |
|---|---:|---:|
| 확인 불가 | 일부 공유 | 27,681 |
| 서로 다름 | 동일 | 16,743 |
| 서로 다름 | 서로 다름 | 12,021 |
| 동일 | 동일 | 11,237 |
| 서로 다름 | 일부 공유 | 9,643 |
| 확인 불가 | 서로 다름 | 6,112 |
| 일부 공유 | 일부 공유 | 2,947 |
| 일부 공유 | 동일 | 6 |
| 동일 | 서로 다름 | 5 |

주소별 provenance에서 Dataset-level Source Set으로 분석 단위를 바꿨으므로 기존 Unknown뿐 아니라 일부 Same/Different도 재분류됐다.

### 기존 Unknown 33,793건 재배정

| 새 관계 | Pair | 기존 Unknown 내 비율 |
|---|---:|---:|
| 동일 | 0 | 0.000000% |
| 일부 공유 | 27,681 | 81.913414% |
| 서로 다름 | 6,112 | 18.086586% |

Unknown을 임의로 덮어쓴 것이 아니라, 모든 Pair를 Dataset-level Source Set 정의로 처음부터 재계산했다.

### 동일 대표 Pair

| Address | Dataset A | Dataset B | Set A | Set B |
|---|---:|---:|---:|---:|
| 0x000000000532b45f47779fce440748893b257865 | BERT4ETH | Forta Labelled Datasets | Etherscan | Etherscan |
| 0x000001f568875f378bf6d170b790967fe429c81a | BERT4ETH | XBlock Ethereum Phishing Transaction Network | Etherscan | Etherscan |
| 0x00192fb10df37c9fb26829eb2cc623cd1bf599e8 | RiskProp | XBlock Ethereum Phishing Transaction Network | Etherscan | Etherscan |

### 일부 공유 대표 Pair

| Address | Dataset A | Dataset B | Set A | Set B |
|---|---:|---:|---:|---:|
| 0x000000000000000000000000000000000000dead | Real-CATS | XBlock Ethereum Phishing Transaction Network | Chainabuse \| Etherscan \| Real-CATS Supplemental Source (Unspecified) \| WalletExplorer | Etherscan |
| 0x000000000532b45f47779fce440748893b257865 | BERT4ETH | scamsonethereum | Etherscan | Etherscan \| Multiple Blacklists \| Prior Research |
| 0x000000000532b45f47779fce440748893b257865 | Forta Labelled Datasets | Real-CATS | Etherscan | Chainabuse \| Etherscan \| Real-CATS Supplemental Source (Unspecified) \| WalletExplorer |

### 서로 다름 대표 Pair

| Address | Dataset A | Dataset B | Set A | Set B |
|---|---:|---:|---:|---:|
| 0x00009277775ac7d0d59eaad8fee3d10ac6c805e8 | Ethereum Illicit Accounts (Farrugia et al.) | XBlock Ethereum Phishing Transaction Network | EtherScamDB | Etherscan |
| 0x0002b44ddb1476db43c868bd494422ee4c136fed | BERT4ETH | Ethereum Illicit Accounts (Farrugia et al.) | Etherscan | EtherScamDB |
| 0x0020731604c882cf7bf8c444be97d17b19ea4316 | BERT4ETH | EtherScamDB | Etherscan | EtherScamDB |

### 기존 개별검증 완료 33 Pair 영향

- Root Relation이 변경된 Pair: **13 / 33**
- 변경되지 않은 Pair: **20 / 33**
- 기존 Unknown에서 새 관계로 이동한 검증 완료 Pair: **3건**
- 최종 Case Cause 변경: **0건**

| Address | Dataset A | Dataset B | 기존 Root | 새 Root | 기존 최종 원인 | 영향 |
|---|---:|---:|---:|---:|---:|---:|
| 0x079667f4f7a0b440ad35ebd780efd216751f0758 | BERT4ETH | Real-CATS | 서로 다름 | 일부 공유 | Processing Difference | 최종 원인 유지 |
| 0x255f2007426f9f24bfa09e51ca41f8509865dbba | Real-CATS | EX-Graph – Wash-Trading | 확인 불가 | 서로 다름 | Coverage / GT Construction Difference | 최종 원인 유지 |
| 0x26a76f4fe7a21160274d060acb209f515f35429c | EthereumHeist | Real-CATS | 서로 다름 | 일부 공유 | GT / Label Error | 최종 원인 유지 |
| 0x26a76f4fe7a21160274d060acb209f515f35429c | Forta Labelled Datasets | Real-CATS | 서로 다름 | 일부 공유 | GT / Label Error | 최종 원인 유지 |
| 0x5ebc7d1ff1687a75f76c3edfabcde89d1c09cd5f | EthereumHeist | Real-CATS | 서로 다름 | 일부 공유 | GT / Label Error | 최종 원인 유지 |
| 0x6a164122d5cf7c840d26e829b46dcc4ed6c0ae48 | RiskProp | scamsonethereum | 확인 불가 | 일부 공유 | GT / Label Error | 최종 원인 유지 |
| 0x6d2d9533637b004fa31ed388e908d064e5bbbc34 | Forta Labelled Datasets | Real-CATS | 서로 다름 | 일부 공유 | Coverage / GT Construction Difference | 최종 원인 유지 |
| 0x6d2d9533637b004fa31ed388e908d064e5bbbc34 | Real-CATS | DA-HGNN Phishing Detection Dataset | 서로 다름 | 일부 공유 | Coverage / GT Construction Difference | 최종 원인 유지 |
| 0x718a085f6d45a955395881bceff30ec97ffb1013 | Real-CATS | EX-Graph – Wash-Trading | 확인 불가 | 서로 다름 | GT / Label Error | 최종 원인 유지 |
| 0x9f26ae5cd245bfeeb5926d61497550f79d9c6c1c | BERT4ETH | Real-CATS | 서로 다름 | 일부 공유 | Processing Difference | 최종 원인 유지 |
| 0xeda5066780de29d00dfb54581a707ef6f52d8113 | BERT4ETH | Real-CATS | 서로 다름 | 일부 공유 | Processing Difference | 최종 원인 유지 |
| 0xf6884686a999f5ae6c1af03db92bab9c6d7dc8de | EthereumHeist | Real-CATS | 서로 다름 | 일부 공유 | Taxonomy Difference | 최종 원인 유지 |
| 0xf850380c7e9a11e5a1ee65a4c24947de2286524f | Forta Labelled Datasets | Real-CATS | 서로 다름 | 일부 공유 | Taxonomy Difference | 최종 원인 유지 |

Root 변화는 Dataset-level 정보 계보 context를 보완하지만 개별 주소 origin을 새로 입증하지 않는다. 기존 33건의 최종 원인은 원자료·GT 구축 방식·외부 사건 근거를 함께 사용해 정했으므로 자동 변경하지 않았다. 변경된 13건은 07에서 `재검토 완료—최종 원인 유지`로 표시했다.

### 한계

> Root Source 관계는 Dataset-level로 확인 가능한 Label construction source를 기준으로 하며, 개별 주소가 실제로 어느 Source에서 유입되었는지를 직접 증명하지 않는다.

`서로 다름`은 현재 확인 가능한 Source Set에서 공통 Root가 확인되지 않았다는 뜻이며 완전한 정보 독립성을 의미하지 않는다. 특히 `Partial` Dataset이 포함된 Pair는 공개되지 않은 원천이 추가로 공유될 가능성을 배제할 수 없다. Temporal Relation은 기존 값을 그대로 유지했다.
<!-- ROOT_SOURCE_SET_ANALYSIS_END -->

## 9. 개별검증 현황과 해석 한계

| 검증 상태 | Pair | 고유 주소 | 주요 충돌 내 비율 |
|---|---:|---:|---:|
| 기존 개별검증 완료 | 33 | 19 | 0.313748% |
| 엄격 기준 신규 검증 필요 | 10,485 | 2,169 | 99.686252% |
| 합계 | **10,518** | **2,188** | **100%** |

기존 33 Pair의 개별검증 최종 원인은 Coverage/GT Construction 15, Processing 9, GT/Label Error 6, Taxonomy Difference 2, Unresolved 1이었다. 이 결과는 새로 추가된 10,485 Pair에 자동으로 일반화하지 않는다.

새 후보는 우선 고유 주소 단위로 묶고, `Label 조합 × Dataset Pair × Root 관계 × 시간 정보`로 층화한 뒤 대표 사례를 검증해야 한다. 특히 반복되는 Dataset Pair의 동일한 Original Label 변환은 주소마다 처음부터 재조사하기보다 공통 processing 규칙을 먼저 확인한다.

## 10. 산출물

- `00_주소_계정유형_검증.csv`: 변경 없음
- `01_전처리_주소라벨_통합표.csv`: 변경 없음
- `02_라벨_속성_정의.csv`: 변경 없음
- `03_중복주소_데이터셋교집합.csv`: 변경 없음
- `04_중복주소_데이터셋Pair비교.csv`: 엄격 기준 관계 판정 반영
- `05_충돌주소_원인분석.csv`: 변경된 Taxonomy의 Root×Label×Time 해석 반영
- `06_관계및최종원인_7분류_요약.csv`: 엄격 관계 분포와 검증 현황 반영
- `07_주요충돌_개별검증_최종해석.csv`: 10,518개 주요 Pair 전체와 Root 변화·검증 상태 수록
- `08_라벨링패러다임_Research_vs_Community_분석.csv`: Research/Community 패러다임별 구체 Behavior 충돌률과 Root Source 교차 결과
- `Root_Source_Set_정규화.csv`: 15개 Dataset의 Raw Source·정규화 Source Set·완전성
- `ANALYSIS_REPORT.md`: 엄격 기준 최종 결과와 한계 정리

## 11. 검증 결과

- 전체 Pair는 104,673개이며 각 Pair는 하나의 최종 관계에만 배정됐다.
- Taxonomy Conflict는 10,512 Pair / 2,183주소다.
- Strong Conflict는 6 Pair / 5주소다.
- 주요 충돌 합집합은 10,518 Pair / 2,188주소다.
- strict 전환 대상은 정확히 10,485 Pair / 2,169주소다.
- 07은 기존 개별검증 완료 33 Pair와 신규 검증 필요 10,485 Pair를 구분한다.

- Root 분석 86,395 Pair는 동일 27,986 / 일부 공유 40,271 / 서로 다름 18,138이며 Unknown은 0이다.
- Root 변경 전후 Label Relationship 및 Temporal Relation 분포는 동일하다.

## 12. Research-based vs Community-based 라벨링 패러다임

### 분석 정의

- **Research-based (8개)**: BERT4ETH, XBlock, Trans2Vec, RiskProp, DA-HGNN, EthereumHeist, Forta Labelled, FDGNN
- **Community-based (5개)**: scamsonethereum, EtherScamDB, Farrugia, Cryptocurrency Exchange Scams, Real-CATS
- **분류 제외 (2개)**: EX-Graph는 Dune 기반 wash-trading 행위 탐지이고, OFAC는 Behavior가 아닌 Status 지정이므로 이 비교에서 제외했다.
- 비교 단위는 동일 주소에 함께 존재하는 `Dataset A–Dataset B`의 **Pair-Address**이다. 양쪽 모두 `Abnormal`, `Behavior`, 구체 표준 유형인 경우만 비교했으며, 두 표준 유형 구성요소에 교집합이 없으면 유형 충돌로 판정했다.

### 패러다임별 충돌률

| 비교 관계 | 비교 Pair-Address | 유형 충돌 | 충돌률 |
|---|---:|---:|---:|
| Research–Research | 18,331 | 6 | 0.03% |
| Community–Community | 2,232 | 172 | 7.71% |
| Research–Community | 23,780 | 10,323 | 43.41% |

Research 내부에서는 거의 동일한 유형을 재현하지만, Research와 Community를 교차하면 충돌률이 크게 상승한다. 이는 동일 주소의 실제 상태가 자주 반전됐다는 뜻이라기보다, Research 데이터셋이 주로 `Phishing`을 계승하는 반면 Community 데이터셋은 같은 주소를 더 넓은 `Scam` 분류로 기록하는 **taxonomy 선택 차이**가 크다는 뜻이다.

### Root Source를 함께 고려한 결과

| 비교 관계 | Root Source 관계 | 비교 Pair-Address | 유형 충돌 | 충돌률 |
|---|---|---:|---:|---:|
| Research–Research | 공유됨 | 18,331 | 6 | 0.03% |
| Community–Community | 공유됨 | 100 | 10 | 10.00% |
| Community–Community | 공유 안 됨 | 2,132 | 162 | 7.60% |
| Research–Community | 공유됨 | 17,599 | 5,849 | 33.23% |
| Research–Community | 공유 안 됨 | 6,181 | 4,474 | 72.38% |

Research–Community Pair에서는 Root Source를 공유하지 않을 때 충돌률이 72.38%로 더 높다. 다만 Source를 일부라도 공유하는 경우에도 33.23%이므로, 충돌은 원천 독립성만으로 설명되지 않고 **같은 원천을 서로 다른 분류 체계로 재가공한 영향**도 함께 존재한다.

### 라벨 구성과 핵심 해석

- Research 8개 데이터셋의 Abnormal Dataset-Address 17,288건 중 16,974건(98.18%)은 표준 유형에 `Phishing`을 포함한다.
- Cross-paradigm 유형 충돌 10,323건 중 `Scam ↔ Phishing`은 6,990건, `Scam ↔ Hack/Exploit | Phishing`은 3,323건이다.
- 두 유형을 합치면 **10,313건(99.90%)**으로, 교차 패러다임 충돌의 거의 전부가 Community의 `Scam`과 Research의 `Phishing` 포함 라벨 사이에서 발생한다.

따라서 이 결과의 핵심은 “어느 패러다임이 더 정확한가”가 아니다. 동일 주소를 Research 계열은 탐지·seed의 구체 행위인 `Phishing` 중심으로, Community 계열은 신고·registry의 포괄 범주인 `Scam` 중심으로 표현한다는 점이다. 이 차이를 Ground Truth의 독립적인 행위 모순으로 바로 해석하면 충돌을 과대평가할 수 있으므로, 통합 라벨에서는 원본 라벨과 표준 유형을 함께 보존해야 한다.

### 한계

Research/Community는 Dataset-level 구축 방식에 따른 분류이며 개별 주소별 provenance를 뜻하지 않는다. 또한 유형 충돌은 공개 라벨 간 taxonomy 불일치이지, 해당 주소의 실제 on-chain 행위를 개별 검증한 최종 판정은 아니다. 세부 수치와 재현 기준은 `08_라벨링패러다임_Research_vs_Community_분석.csv`에 정리했다.
