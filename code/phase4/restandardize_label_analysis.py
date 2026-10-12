from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


UNKNOWN = "확인 불가"
NA = "해당 없음"

ABNORMAL = "Abnormal"
NORMAL = "Normal"
UNCERTAIN = "Uncertain"

BEHAVIOR = "Behavior"
STATUS = "Status"
ROLE = "Role"
TECHNICAL = "Technical Attribute"
NOT_APPLICABLE = "Not Applicable"

SPECIFIC = "구체적"
BROAD = "포괄적"
COMPOSITE = "복합"
UNSPECIFIED = "세부유형미상"

ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

DATASETS = [
    "BERT4ETH",
    "EtherScamDB",
    "Ethereum Illicit Accounts (Farrugia et al.)",
    "EthereumHeist",
    "FDGNN Fraud Address Dataset",
    "Forta Labelled Datasets",
    "OFAC Ethereum Addresses",
    "Phishing Detection on Ethereum (Trans2Vec)",
    "Real-CATS",
    "RiskProp",
    "XBlock Ethereum Phishing Transaction Network",
    "scamsonethereum",
    "DA-HGNN Phishing Detection Dataset",
    "EX-Graph – Wash-Trading",
    "Cryptocurrency Exchange Scams - Ethereum subset",
]
DATASET_ORDER = {dataset: index for index, dataset in enumerate(DATASETS)}

MAIN_OUTPUTS = [
    "01_전처리_주소라벨_통합표.csv",
    "02_라벨_속성_정의.csv",
    "03_중복주소_데이터셋교집합.csv",
    "04_중복주소_데이터셋Pair비교.csv",
    "05_충돌주소_원인분석.csv",
    "ANALYSIS_REPORT.md",
]

COMPARISON_DIRNAME = "재표준화_전후비교"
COMPARISON_OUTPUTS = [
    "01_재표준화_변경규칙.csv",
    "02_관계유형_전후비교.csv",
    "03_관계전환_상세.csv",
    "04_OriginalLabel_영향.csv",
    "05_DatasetPair_영향.csv",
    "06_대표_변화사례.csv",
]

FAKE_UNSPECIFIED_LABELS = {
    "Fake: AVA Token Sale",
    "FAKE: DaoCasino",
    "Fake: Dfinity Token Sale",
    "Fake: Enigma Presale",
    "FAKE: FundYourselfNow",
    "Fake: Hardfork",
    "Fake: Hero Token Sale",
    "Fake: Hero Token Sale 3",
    "FAKE: Insurex",
    "Fake: Metadium Presale",
    "FAKE: OmiseGo",
    "FAKE: Santiment Crowdsale",
    "FAKE: Santiment Crowdsale 2",
    "FAKE: Starbase Crowdsale",
    "Fake: Starbase Token Sale",
    "FAKE: Status.im 1",
    "FAKE: Status.im 2",
    "FAKE: Status.im 4",
    "FAKE: TenX",
    "FAKE: TenX 2",
    "FAKE: TenX 3",
    "FAKE: TenX 4",
    "FAKE: TenX 5",
    "FAKE: TenX 6",
    "FAKE: TenX 7",
    "FAKE: TenX 8",
}

SCAM_EXPLICIT_LABELS = {
    "Scam: Edgeless Token",
    *(f"Scam: RHOC Token {number}" for number in range(1, 12)),
}

DATASET_ROOT_SOURCE_METADATA = {
    "BERT4ETH": {
        "raw": "Etherscan phish-hack; Ethereum random EOA sampling",
        "sources": {"Etherscan"},
        "completeness": "Complete",
    },
    "EtherScamDB": {
        "raw": "EtherScamDB Community Registry",
        "sources": {"EtherScamDB"},
        "completeness": "Complete",
    },
    "Ethereum Illicit Accounts (Farrugia et al.)": {
        "raw": "EtherScamDB historical snapshot; Ethereum active-account random sample",
        "sources": {"EtherScamDB"},
        "completeness": "Complete",
    },
    "EthereumHeist": {
        "raw": "Etherscan heist/name-tag",
        "sources": {"Etherscan"},
        "completeness": "Complete",
    },
    "FDGNN Fraud Address Dataset": {
        "raw": "XBlock; Etherscan; CryptoScamDB; prior Ponzi dataset",
        "sources": {"Etherscan", "CryptoScamDB", "Prior Ponzi Dataset"},
        "completeness": "Partial",
    },
    "Forta Labelled Datasets": {
        "raw": "Etherscan phish-hack/exploit/heist lists",
        "sources": {"Etherscan"},
        "completeness": "Complete",
    },
    "OFAC Ethereum Addresses": {
        "raw": "OFAC Enhanced SDN",
        "sources": {"OFAC"},
        "completeness": "Complete",
    },
    "Phishing Detection on Ethereum (Trans2Vec)": {
        "raw": "EtherScamDB; Etherscan",
        "sources": {"EtherScamDB", "Etherscan"},
        "completeness": "Complete",
    },
    "Real-CATS": {
        "raw": "Chainabuse; WalletExplorer; Etherscan; Real-CATS supplemental source",
        "sources": {"Chainabuse", "Etherscan", "WalletExplorer", "Real-CATS Supplemental Source (Unspecified)"},
        "completeness": "Partial",
    },
    "RiskProp": {
        "raw": "Etherscan labels",
        "sources": {"Etherscan"},
        "completeness": "Complete",
    },
    "XBlock Ethereum Phishing Transaction Network": {
        "raw": "Etherscan phish-hack; Etherscan 2-hop crawl",
        "sources": {"Etherscan"},
        "completeness": "Complete",
    },
    "scamsonethereum": {
        "raw": "Mixed 14 blacklists; prior research; Etherscan",
        "sources": {"Etherscan", "Multiple Blacklists", "Prior Research"},
        "completeness": "Partial",
    },
    "DA-HGNN Phishing Detection Dataset": {
        "raw": "Etherscan phishing labels",
        "sources": {"Etherscan"},
        "completeness": "Complete",
    },
    "EX-Graph – Wash-Trading": {
        "raw": "Dune Analytics wash-trading identification",
        "sources": {"Dune Analytics"},
        "completeness": "Complete",
    },
    "Cryptocurrency Exchange Scams - Ethereum subset": {
        "raw": "EtherScamDB; CryptoScamDB; typosquatting search",
        "sources": {"EtherScamDB", "CryptoScamDB", "Typosquatting Search"},
        "completeness": "Complete",
    },
}

RELATION_ORDER = [
    "Same Label",
    "Compatible Label",
    "Granularity Difference",
    "Uncertain Comparison",
    "Label Coverage Difference",
    "Status–Behavior Relation",
    "Axis Difference",
    "Normal Attribute Difference",
    "Taxonomy Conflict",
    "Strong Conflict",
]

MAJOR_CONFLICTS = {"Taxonomy Conflict", "Strong Conflict"}


def clean(value: object, fallback: str = "") -> str:
    text = "" if value is None else str(value).strip()
    return text if text else fallback


def joined(values: Iterable[str], separator: str = " | ", fallback: str = UNKNOWN) -> str:
    items = sorted({clean(value) for value in values if clean(value)})
    return separator.join(items) if items else fallback


def json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def components_text(values: Iterable[str]) -> str:
    return ";".join(sorted(set(values)))


def normalized_old_axis(value: str, character: str, old_type: str) -> str:
    axis = clean(value)
    if axis in {"행위 유형", "포괄적 이상 분류", BEHAVIOR}:
        return BEHAVIOR
    if axis in {"상태", STATUS} or old_type == "Sanctioned":
        return STATUS
    if axis in {ROLE, TECHNICAL}:
        return axis
    if character in {NORMAL, UNCERTAIN}:
        return NOT_APPLICABLE
    return axis or NOT_APPLICABLE


@dataclass(frozen=True)
class Claim:
    axis: str
    values: tuple[str, ...]
    operator: str
    specificity: str

    @classmethod
    def single(cls, axis: str, value: str, specificity: str = SPECIFIC) -> "Claim":
        return cls(axis, (value,), "SINGLE", specificity)

    @classmethod
    def alternatives(
        cls, axis: str, values: Iterable[str], specificity: str = COMPOSITE
    ) -> "Claim":
        return cls(axis, tuple(sorted(set(values))), "OR", specificity)

    def canonical(self) -> tuple[str, tuple[str, ...], str, str]:
        return self.axis, self.values, self.operator, self.specificity

    def semantic_canonical(self) -> tuple[str, tuple[str, ...], str]:
        return self.axis, self.values, self.operator

    def as_dict(self) -> dict[str, object]:
        return {
            "axis": self.axis,
            "operator": self.operator,
            "values": list(self.values),
            "specificity": self.specificity,
        }


@dataclass(frozen=True)
class Mapping:
    character: str
    claims: tuple[Claim, ...]
    display_type: str
    specificity: str
    reason: str
    note: str
    validation: str

    @property
    def axes(self) -> tuple[str, ...]:
        axes = tuple(sorted({claim.axis for claim in self.claims}))
        return axes or (NOT_APPLICABLE,)

    @property
    def axis_text(self) -> str:
        return " | ".join(self.axes)

    @property
    def components(self) -> tuple[str, ...]:
        return tuple(sorted({value for claim in self.claims for value in claim.values}))

    @property
    def components_text(self) -> str:
        return components_text(self.components) if self.components else self.display_type

    @property
    def structure_text(self) -> str:
        return json_text([claim.as_dict() for claim in self.claims])


def simple_mapping(
    character: str,
    axis: str,
    standard_type: str,
    specificity: str,
    reason: str,
    note: str = "",
    validation: str = "아니오",
) -> Mapping:
    claims: tuple[Claim, ...]
    if character == UNCERTAIN:
        claims = ()
    else:
        claims = (Claim.single(axis, standard_type, specificity),)
    return Mapping(character, claims, standard_type, specificity, reason, note, validation)


def composite_mapping(
    values: Iterable[str], reason: str, note: str = "", validation: str = "아니오"
) -> Mapping:
    values_tuple = tuple(values)
    return Mapping(
        ABNORMAL,
        (Claim.alternatives(BEHAVIOR, values_tuple),),
        " | ".join(values_tuple),
        COMPOSITE,
        reason,
        note,
        validation,
    )


def multi_axis_mapping(
    claims: Iterable[Claim], reason: str, note: str = "", validation: str = "아니오"
) -> Mapping:
    claim_tuple = tuple(claims)
    return Mapping(
        ABNORMAL,
        claim_tuple,
        " + ".join(value for claim in claim_tuple for value in claim.values),
        COMPOSITE,
        reason,
        note,
        validation,
    )


def base_mapping(row: dict[str, str]) -> Mapping:
    character = clean(row.get("라벨 확실성"), UNCERTAIN)
    old_type = clean(row.get("표준 유형"), "Uncertain")
    old_reason = clean(row.get("판정 근거"), "기존 주소 라벨 표준화 규칙")
    old_note = clean(row.get("비고"))

    if character == UNCERTAIN:
        return simple_mapping(
            UNCERTAIN,
            NOT_APPLICABLE,
            "Uncertain",
            NA,
            old_reason,
            old_note,
            "예",
        )
    if character == NORMAL:
        return simple_mapping(
            NORMAL,
            BEHAVIOR,
            "Benign",
            NA,
            old_reason,
            old_note,
            "아니오",
        )
    if old_type == "Sanctioned":
        return simple_mapping(ABNORMAL, STATUS, "Sanctioned", SPECIFIC, old_reason, old_note)
    if old_type == "Illicit/Criminal":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Illicit/Criminal",
            BROAD,
            old_reason,
            old_note,
        )
    if old_type == "Other":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Unspecified Abnormal",
            UNSPECIFIED,
            "원 출처는 이상 주소임을 나타내지만 세부 행위 유형을 보장하지 않음",
            old_note,
            "예",
        )
    if old_type in {
        "Phishing",
        "Scam",
        "Hack/Exploit",
        "Rug Pull",
        "Ponzi",
        "Wash Trading",
        "Ransomware",
        "Wallet Drainer",
    }:
        return simple_mapping(ABNORMAL, BEHAVIOR, old_type, SPECIFIC, old_reason, old_note)
    return simple_mapping(
        ABNORMAL,
        BEHAVIOR,
        "Unspecified Abnormal",
        UNSPECIFIED,
        "기존 유형만으로 구체적 이상 행위를 확정할 수 없어 보수적으로 유지",
        old_note,
        "예",
    )


def mapping_for(row: dict[str, str]) -> Mapping:
    dataset = clean(row.get("Dataset"))
    original = clean(row.get("Original Label"), UNKNOWN)

    if dataset == "Cryptocurrency Exchange Scams - Ethereum subset":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Scam",
            SPECIFIC,
            "원본 라벨과 데이터셋 구축 근거가 확인된 scam infrastructure의 자금 수취 주소임을 직접 명시",
            "Address-level Scam attribution으로 비교하되 주소 소유자가 Scam 운영 주체임을 독립적으로 증명하는 것은 아님",
        )

    if original == "phish-hack":
        return composite_mapping(
            ("Phishing", "Hack/Exploit"),
            "원본 라벨이 phishing 또는 hack 가능성을 함께 포함하므로 한 유형으로 축소하지 않음",
            "OR 복합 라벨이며 두 행위가 모두 확정되었다는 뜻은 아님",
        )

    if dataset == "scamsonethereum" and original in {
        "master_blacklist_set",
        "all_across_hard",
    }:
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Unspecified Abnormal",
            BROAD,
            "여러 blacklist의 통합 membership은 이상 여부는 지지하지만 Scam이라는 단일 행위를 보장하지 않음",
            "주소별 세부 악성 행위와 provenance가 공개 파일에서 분리되지 않음",
            "예",
        )

    if dataset == "Real-CATS" and original == "ETH Liquidity Scam":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Scam",
            SPECIFIC,
            "원본은 liquidity scam을 명시하지만 rug-pull 메커니즘까지 보장하지 않음",
            "Rug Pull로의 과도한 구체화를 철회",
            "예",
        )

    if original in {"Plus Token Ponzi 1", "Plus Token Ponzi 2"}:
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Ponzi",
            SPECIFIC,
            "Original Label이 Ponzi를 직접 명시",
        )

    if original in {"Wallet Drainer", "0xhabitat.eth Multisig Drainer"}:
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Wallet Drainer",
            SPECIFIC,
            "Drainer는 자산 탈취 도구·행위를 뜻하지만 phishing 획득 방식을 반드시 보장하지 않음",
            "Phishing으로의 과도한 축소를 철회",
            "예",
        )

    if original == "AFKSystem":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Unspecified Abnormal",
            UNSPECIFIED,
            "사건명만으로 Hack/Exploit 등 세부 행위를 단정할 수 없음",
            "사건 단위 추가 검증 필요",
            "예",
        )

    if original == "ATO Stolen Funds":
        return simple_mapping(
            ABNORMAL,
            STATUS,
            "Stolen Funds",
            SPECIFIC,
            "원본은 도난 자금 관련 상태를 나타내며 해당 주소의 공격 행위를 직접 보장하지 않음",
            "Behavior 판정에 사용하지 않음",
            "예",
        )

    if original == "Artist Impersonator 14":
        return simple_mapping(
            ABNORMAL,
            ROLE,
            "Impersonator",
            SPECIFIC,
            "Original Label이 impersonator 역할을 직접 명시",
            "Behavior와 별도 축으로 비교",
        )

    if original == "BadgerDAO Exploit Funder":
        return simple_mapping(
            ABNORMAL,
            ROLE,
            "Exploit Funder",
            SPECIFIC,
            "Funder는 exploit 연계 역할이며 직접 exploiter 행위를 의미하지 않음",
            "Behavior 판정에는 사건 근거가 추가로 필요",
            "예",
        )

    if original == "Curve DNS Hijacker":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Hack/Exploit",
            SPECIFIC,
            "Original Label이 DNS hijacking 행위를 직접 명시",
        )

    if original in FAKE_UNSPECIFIED_LABELS:
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Unspecified Abnormal",
            UNSPECIFIED,
            "Fake tag와 악성 목록 membership은 이상 여부는 지지하지만 Scam·Phishing·Hack 중 하나를 확정하지 않음",
            "이름의 Fake 키워드만으로 구체 유형을 추정하지 않음",
            "예",
        )

    if original in SCAM_EXPLICIT_LABELS:
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Scam",
            SPECIFIC,
            "Original Label이 Scam을 직접 명시",
            "Root taxonomy와의 일치 여부는 수동 확인 권장",
            "예",
        )

    if original == "MekaVerse-related Scam":
        return simple_mapping(
            ABNORMAL,
            STATUS,
            "Scam-associated",
            SPECIFIC,
            "related라는 표현은 Scam 연관 상태를 뜻하며 직접 행위자임을 보장하지 않음",
            "Behavior 판정에 사용하지 않음",
            "예",
        )

    if original == "RigoBlock Whitehat":
        return simple_mapping(
            ABNORMAL,
            ROLE,
            "Whitehat",
            SPECIFIC,
            "Original Label이 Whitehat 역할을 직접 명시",
            "원 파일의 이상 목록 membership은 유지하되 악성 Behavior로 해석하지 않음",
            "예",
        )

    if original == "Multichain Exploiter 4 (Whitehat)":
        return multi_axis_mapping(
            (
                Claim.single(BEHAVIOR, "Hack/Exploit", SPECIFIC),
                Claim.single(ROLE, "Whitehat", SPECIFIC),
            ),
            "Exploiter 행위와 Whitehat 역할을 서로 다른 축으로 동시에 보존",
            "다축 복합 라벨",
        )

    if original == "Popsicle Swap Hacker (Contract Deployer)":
        return multi_axis_mapping(
            (
                Claim.single(BEHAVIOR, "Hack/Exploit", SPECIFIC),
                Claim.single(ROLE, "Contract Deployer", SPECIFIC),
            ),
            "Hacker 행위와 Contract Deployer 역할을 서로 다른 축으로 동시에 보존",
            "다축 복합 라벨",
        )

    if re.fullmatch(r"Phishing Token Deployer(?: \d+)?", original):
        return multi_axis_mapping(
            (
                Claim.single(BEHAVIOR, "Phishing", SPECIFIC),
                Claim.single(ROLE, "Token Deployer", SPECIFIC),
            ),
            "Phishing 행위와 Token Deployer 역할을 서로 다른 축으로 동시에 보존",
            "다축 복합 라벨",
        )

    if dataset == "Real-CATS" and original == "Metamorphic Contract":
        return simple_mapping(
            ABNORMAL,
            TECHNICAL,
            "Metamorphic Contract",
            SPECIFIC,
            "Original Label은 contract 기술 속성을 나타내며 Behavior 유형이 아님",
            "Account 연구에서는 계정 유형 추가 검증 필요",
            "예",
        )

    if dataset == "Real-CATS" and original == "Other":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Unspecified Abnormal",
            UNSPECIFIED,
            "데이터셋은 이상 주소임을 나타내지만 Other만으로 세부 유형을 확인할 수 없음",
            "세부 사건 검증 필요",
            "예",
        )

    if dataset == "Real-CATS" and original == "Ransomware":
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Ransomware",
            SPECIFIC,
            "Original Label이 Ransomware를 직접 명시",
        )

    if dataset == "Forta Labelled Datasets" and original == UNKNOWN:
        return simple_mapping(
            ABNORMAL,
            BEHAVIOR,
            "Unspecified Abnormal",
            UNSPECIFIED,
            "악성 목록 membership은 확인되지만 주소별 Original Label이 비어 있음",
            "Root별 원 라벨 추가 검증 필요",
            "예",
        )

    return base_mapping(row)


def mapping_history(row: dict[str, str], mapping: Mapping) -> dict[str, str]:
    old_character = clean(row.get("라벨 확실성"), UNCERTAIN)
    old_axis = normalized_old_axis(
        clean(row.get("라벨 속성 축")), old_character, clean(row.get("표준 유형"))
    )
    old_type = clean(row.get("표준 유형"), "Uncertain")
    semantic_axis_changed = set(old_axis.split(" | ")) != set(mapping.axes)
    type_changed = old_type != mapping.display_type
    character_changed = old_character != mapping.character
    changed = type_changed or character_changed or semantic_axis_changed

    changes: list[str] = []
    if character_changed:
        changes.append(f"Label Character: {old_character} → {mapping.character}")
    if semantic_axis_changed:
        changes.append(f"Label Axis: {old_axis} → {mapping.axis_text}")
    if type_changed:
        changes.append(f"Standard Type: {old_type} → {mapping.display_type}")
    if not changes:
        changes.append("기존 의미 매핑 유지")
    changes.append(f"구체성 신규 명시: {mapping.specificity}")
    return {
        "재표준화 여부": "예" if changed else "아니오",
        "기존 라벨 확실성": old_character,
        "기존 라벨 속성 축": old_axis,
        "기존 표준 유형": old_type,
        "재표준화 이력": "; ".join(changes),
        "변경 사유": mapping.reason if changed else NA,
        "변경 근거": (
            f"Original Label={clean(row.get('Original Label'), UNKNOWN)}; "
            f"Root Source={clean(row.get('Root Source'), UNKNOWN)}; 의미 보존형 표준화 규칙"
            if changed
            else "기존 매핑 유지; 구체성 및 구조화 Claim만 명시"
        ),
    }


@dataclass
class RuleAggregate:
    mapping: Mapping
    history: dict[str, str]
    dates: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    old_reasons: set[str] = field(default_factory=set)
    old_notes: set[str] = field(default_factory=set)
    row_count: int = 0


@dataclass
class DatasetEvidence:
    originals: set[str] = field(default_factory=set)
    characters: set[str] = field(default_factory=set)
    claims: dict[tuple[str, tuple[str, ...], str, str], Claim] = field(default_factory=dict)
    roots: set[str] = field(default_factory=set)
    dates: set[str] = field(default_factory=set)
    specificities: set[str] = field(default_factory=set)
    changed_rules: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)

    def add(self, dataset: str, row: dict[str, str], mapping: Mapping, history: dict[str, str]) -> None:
        original = clean(row.get("Original Label"), UNKNOWN)
        self.originals.add(original)
        self.characters.add(mapping.character)
        self.roots.add(clean(row.get("Root Source"), UNKNOWN))
        self.dates.add(clean(row.get("라벨 기준일"), UNKNOWN))
        self.specificities.add(mapping.specificity)
        if mapping.note:
            self.notes.add(mapping.note)
        for claim in mapping.claims:
            self.claims[claim.canonical()] = claim
        if history["재표준화 여부"] == "예":
            self.changed_rules.add(
                (
                    dataset,
                    original,
                    history["기존 표준 유형"],
                    mapping.display_type,
                    history["변경 사유"],
                )
            )

    def resolve(self) -> None:
        if UNCERTAIN in self.characters and len(self.characters) > 1:
            explicit = self.characters - {UNCERTAIN}
            if len(explicit) == 1:
                self.characters = explicit
                self.notes.add("동일 데이터셋의 Uncertain membership보다 명시적 판정을 우선")

        by_axis: dict[str, list[Claim]] = defaultdict(list)
        for claim in self.claims.values():
            by_axis[claim.axis].append(claim)
        retained: dict[tuple[str, tuple[str, ...], str, str], Claim] = {}
        for axis, claims in by_axis.items():
            informative = [
                claim for claim in claims if claim.specificity in {SPECIFIC, COMPOSITE}
            ]
            selected = informative if informative else claims
            for claim in selected:
                retained[claim.canonical()] = claim
            if informative and len(selected) < len(claims):
                self.notes.add("동일 축의 구체적 근거가 있어 포괄·세부유형미상 claim은 비교에서 후순위 처리")
        self.claims = retained

    @property
    def effective_character(self) -> str | None:
        return next(iter(self.characters)) if len(self.characters) == 1 else None

    @property
    def axes(self) -> set[str]:
        return {claim.axis for claim in self.claims.values()}

    @property
    def claim_list(self) -> list[Claim]:
        return sorted(self.claims.values(), key=lambda claim: claim.canonical())

    @property
    def type_components(self) -> set[str]:
        return {value for claim in self.claims.values() for value in claim.values}

    @property
    def type_text(self) -> str:
        values = self.type_components
        if not values:
            if self.effective_character == UNCERTAIN:
                return "Uncertain"
            return UNKNOWN
        return components_text(values).replace(";", " | ")

    @property
    def axis_text(self) -> str:
        return joined(self.axes, fallback=NOT_APPLICABLE)

    @property
    def specificity_text(self) -> str:
        values = {claim.specificity for claim in self.claims.values()}
        if not values:
            values = self.specificities
        return joined(values, fallback=NA)

    @property
    def structure_text(self) -> str:
        return json_text([claim.as_dict() for claim in self.claim_list])

    def groups_for_axis(self, axis: str) -> list[Claim]:
        return [claim for claim in self.claim_list if claim.axis == axis]


def claims_semantically_equal(a: list[Claim], b: list[Claim]) -> bool:
    return {claim.canonical() for claim in a} == {claim.canonical() for claim in b}


def scam_phishing_overlap(values_a: set[str], values_b: set[str]) -> bool:
    return any(
        {value_a, value_b} == {"Scam", "Phishing"}
        for value_a in values_a
        for value_b in values_b
    )


def compare_axis_claims(a: list[Claim], b: list[Claim]) -> tuple[str, str]:
    if claims_semantically_equal(a, b):
        return "Same", "동일 축의 Claim 구조·유형·구체성이 모두 동일"

    broad_specs = {BROAD, UNSPECIFIED}
    a_broad = any(claim.specificity in broad_specs for claim in a)
    b_broad = any(claim.specificity in broad_specs for claim in b)
    values_a = {value for claim in a for value in claim.values}
    values_b = {value for claim in b for value in claim.values}

    if a_broad or b_broad:
        if a_broad != b_broad:
            direction = "A가 포괄적" if a_broad else "B가 포괄적"
            return "Granularity", f"{direction}: 포괄·세부유형미상 Claim과 구체 Claim 비교"
        if values_a == values_b:
            return "Granularity", "같은 포괄 유형이지만 구체성 근거가 다름"
        return "Compatible", "양쪽 모두 포괄·세부유형미상 범주로 직접 유형 충돌을 확정할 수 없음"

    if values_a & values_b:
        return "Compatible", "복합 OR 구성요소 또는 독립 Claim 중 공통 유형이 존재"
    return "Taxonomy", "같은 축의 구체적 유형 집합이 서로 배타적"


@dataclass(frozen=True)
class PairDecision:
    relation_ko: str
    final_relation: str
    analysis_target: str
    major_conflict: str
    common_axes: str
    conflict_axes: str
    granularity_direction: str
    rule: str


def classify_pair(a: DatasetEvidence, b: DatasetEvidence) -> PairDecision:
    ca = a.effective_character
    cb = b.effective_character
    if ca is None or cb is None:
        return PairDecision(
            "비교 불가",
            "Uncertain Comparison",
            "예",
            "아니오",
            joined(a.axes & b.axes),
            "",
            "",
            "한 데이터셋 안에 상충하는 명시적 Label Character가 존재",
        )
    if ca == cb == UNCERTAIN:
        return PairDecision(
            "비교 불가", "Uncertain Comparison", "예", "아니오", "", "", "", "양쪽 모두 Uncertain"
        )
    if UNCERTAIN in {ca, cb}:
        return PairDecision(
            "판정 범위 차이",
            "Label Coverage Difference",
            "예",
            "아니오",
            joined(a.axes & b.axes),
            "",
            "",
            "명시적 판정과 Uncertain의 coverage 차이",
        )

    common_axes = a.axes & b.axes
    extra_a = a.axes - common_axes
    extra_b = b.axes - common_axes
    common_text = joined(common_axes, fallback="")
    if not common_axes:
        final = (
            "Status–Behavior Relation"
            if ({STATUS} <= a.axes and {BEHAVIOR} <= b.axes)
            or ({STATUS} <= b.axes and {BEHAVIOR} <= a.axes)
            else "Axis Difference"
        )
        return PairDecision(
            "속성 축 차이",
            final,
            "예",
            "아니오",
            "",
            "",
            "",
            "공통 비교 축이 없어 Behavior 충돌로 판정하지 않음",
        )

    if {ca, cb} == {ABNORMAL, NORMAL}:
        return PairDecision(
            "악성·정상 직접 충돌",
            "Strong Conflict",
            "예",
            "예",
            common_text,
            common_text,
            "",
            "공통 축에서 명시적 Abnormal과 명시적 Normal이 충돌",
        )

    if ca == cb == NORMAL:
        exact = (
            a.axes == b.axes
            and all(
                claims_semantically_equal(a.groups_for_axis(axis), b.groups_for_axis(axis))
                for axis in common_axes
            )
        )
        if exact:
            return PairDecision("동일", "Same Label", "아니오", "아니오", common_text, "", "", "정상 Claim 동일")
        return PairDecision(
            "정상 속성 차이",
            "Normal Attribute Difference",
            "예",
            "아니오",
            common_text,
            "",
            "",
            "양쪽 모두 Normal이나 속성 구조가 다름",
        )

    if ca != ABNORMAL or cb != ABNORMAL:
        return PairDecision(
            "비교 불가", "Uncertain Comparison", "예", "아니오", common_text, "", "", "지원하지 않는 Label Character 조합"
        )

    axis_results: list[tuple[str, str, str]] = []
    for axis in sorted(common_axes):
        relation, reason = compare_axis_claims(a.groups_for_axis(axis), b.groups_for_axis(axis))
        axis_results.append((axis, relation, reason))

    severity = {"Same": 0, "Compatible": 1, "Granularity": 2, "Taxonomy": 3}
    decisive = max(axis_results, key=lambda item: severity[item[1]])
    decisive_relation = decisive[1]
    conflict_axes = joined(
        {axis for axis, relation, _ in axis_results if relation == "Taxonomy"}, fallback=""
    )
    rule = "; ".join(f"{axis}={relation}({reason})" for axis, relation, reason in axis_results)

    if decisive_relation == "Taxonomy":
        return PairDecision("세부 유형 충돌", "Taxonomy Conflict", "예", "예", common_text, conflict_axes, "", rule)
    if decisive_relation == "Granularity":
        a_broad = any(
            claim.specificity in {BROAD, UNSPECIFIED}
            for axis in common_axes
            for claim in a.groups_for_axis(axis)
        )
        b_broad = any(
            claim.specificity in {BROAD, UNSPECIFIED}
            for axis in common_axes
            for claim in b.groups_for_axis(axis)
        )
        direction = (
            "A가 포괄적"
            if a_broad and not b_broad
            else "B가 포괄적"
            if b_broad and not a_broad
            else "양쪽 포괄성 차이"
        )
        return PairDecision("구체성 차이", "Granularity Difference", "예", "아니오", common_text, "", direction, rule)
    if decisive_relation == "Compatible" or extra_a or extra_b:
        extra_note = ""
        if extra_a or extra_b:
            extra_note = f"; 추가 축 A={joined(extra_a, fallback='없음')}, B={joined(extra_b, fallback='없음')}"
        return PairDecision("의미상 호환", "Compatible Label", "예", "아니오", common_text, "", "", rule + extra_note)
    return PairDecision("동일", "Same Label", "아니오", "아니오", common_text, "", "", rule)


def split_pipe(value: str) -> set[str]:
    return {item.strip() for item in clean(value).split(" | ") if item.strip()}


def dataset_root_sources(dataset: str) -> set[str]:
    try:
        return set(DATASET_ROOT_SOURCE_METADATA[dataset]["sources"])
    except KeyError as exc:
        raise RuntimeError(f"Dataset-level Root Source Set 누락: {dataset}") from exc


def root_source_set_text(dataset: str) -> str:
    return " | ".join(sorted(dataset_root_sources(dataset)))


def root_source_completeness(dataset: str) -> str:
    return str(DATASET_ROOT_SOURCE_METADATA[dataset]["completeness"])


def compare_roots(dataset_a: str, dataset_b: str) -> str:
    a = dataset_root_sources(dataset_a)
    b = dataset_root_sources(dataset_b)
    if a == b:
        return "동일"
    if a & b:
        return "일부 공유"
    return "서로 다름"


def normalize_time(value: str) -> tuple[str, ...] | None:
    text = clean(value)
    if not text or text in {UNKNOWN, "unknown", "Unknown"}:
        return None
    dates = tuple(DATE_RE.findall(text))
    return dates if dates else (text.lower(),)


def compare_times(value_a: str, value_b: str) -> str:
    a = normalize_time(value_a)
    b = normalize_time(value_b)
    if a is None or b is None:
        return UNKNOWN
    return "동일 시기" if a == b else "다른 시기"


def interpret_relation(relation: str, root: str, time: str) -> tuple[str, str, str]:
    interpretations = {
        "Strong Conflict": ("공통 축에서 Abnormal과 명시적 Normal이 직접 충돌", "매우 높음"),
        "Taxonomy Conflict": ("같은 축의 구체적 이상 유형이 서로 다름", "높음"),
        "Granularity Difference": ("이상 여부는 모순되지 않지만 정보 구체성이 다름", "중간"),
        "Compatible Label": ("표현·복합 범위는 다르지만 의미가 중첩되어 호환됨", "낮음"),
        "Label Coverage Difference": ("명시적 판정과 Uncertain의 coverage 차이", "낮음"),
        "Status–Behavior Relation": ("상태와 행위가 병존 가능한 서로 다른 속성", "낮음"),
        "Axis Difference": ("Role·Status·Technical 등 비교 축이 서로 달라 직접 충돌이 아님", "낮음"),
        "Normal Attribute Difference": ("양쪽 모두 Normal이나 정상 속성 표현이 다름", "중간"),
        "Uncertain Comparison": ("라벨 근거 부족 또는 데이터셋 내부 복합 판정으로 직접 비교 불가", "낮음"),
    }
    interpretation, priority = interpretations.get(relation, ("관계 해석 확인 필요", "중간"))
    causes: list[str] = []
    if root == "동일":
        causes.append("Dataset-level Root Source Set이 동일해 후속 가공·재표현 가능성")
    elif root == "일부 공유":
        causes.append("Dataset-level Source Set에 공유 원천과 비공유 원천이 함께 존재")
    elif root == "서로 다름":
        causes.append("현재 확인 가능한 Dataset-level Source Set에서 공통 Root가 확인되지 않음")
    else:
        causes.append("Root Source 정보 부족으로 원천 효과 판정 보류")
    if relation == "Granularity Difference":
        causes.append("포괄·세부유형미상 라벨과 구체 라벨의 정보량 차이")
    elif relation == "Taxonomy Conflict":
        causes.append("복수 행위·taxonomy 정의·데이터셋 구축 목적 차이 가능성")
    elif relation in {"Status–Behavior Relation", "Axis Difference"}:
        causes.append("Behavior 이외 속성을 같은 라벨 문자열처럼 비교한 표면적 차이")
    elif relation == "Label Coverage Difference":
        causes.append("seed·negative·unlabeled 구성 차이")
    if time == "다른 시기":
        causes.append("수집 기간·snapshot 차이에 따른 라벨 변화 가능성")
    elif time == "동일 시기":
        causes.append("확인 가능한 시기가 같아 시간 차이만으로 설명하기 어려움")
    else:
        causes.append("시간 정보 부족으로 시점 원인 판정 불가")
    return interpretation, "; ".join(dict.fromkeys(causes)), priority


def load_account_types(path: Path) -> tuple[dict[str, str], Counter[str]]:
    account_types: dict[str, str] = {}
    counts: Counter[str] = Counter()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"Address", "Account Type"}
        if not required <= set(reader.fieldnames or []):
            raise RuntimeError("00 계정유형 검증 파일의 필수 열이 없습니다.")
        for row in reader:
            address = clean(row.get("Address")).lower()
            account_type = clean(row.get("Account Type"))
            if not ADDRESS_RE.fullmatch(address):
                raise RuntimeError(f"00 주소 형식 오류: {address!r}")
            if account_type not in {"EOA", "Delegated EOA", "Conventional Contract"}:
                raise RuntimeError(f"00 Account Type 오류: {account_type!r}")
            counts[account_type] += 1
            if account_type != "Conventional Contract":
                account_types[address] = account_type
    return account_types, counts


def stream_restandardize_01(
    source: Path,
    output: Path,
    account_types: dict[str, str],
) -> tuple[
    int,
    str,
    dict[tuple[str, str, str], RuleAggregate],
    dict[str, dict[str, DatasetEvidence]],
    Counter[str],
]:
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "Address",
        "Account Type",
        "Dataset",
        "Original Label",
        "라벨 확실성",
        "라벨 속성 축",
        "표준 유형",
        "표준 유형 구성요소",
        "구체성",
        "Root Source",
        "라벨 기준일",
        "원본 파일",
        "판정 근거",
        "비고",
    ]
    rules: dict[tuple[str, str, str], RuleAggregate] = {}
    evidence: dict[str, dict[str, DatasetEvidence]] = defaultdict(dict)
    dataset_rows: Counter[str] = Counter()
    digest = hashlib.sha256()
    row_count = 0

    with source.open(encoding="utf-8-sig", newline="") as input_handle, output.open(
        "w", encoding="utf-8-sig", newline=""
    ) as output_handle:
        reader = csv.DictReader(input_handle)
        required = {
            "Address",
            "Account Type",
            "Dataset",
            "Original Label",
            "라벨 확실성",
            "라벨 속성 축",
            "표준 유형",
            "Root Source",
            "라벨 기준일",
            "원본 파일",
            "판정 근거",
            "비고",
        }
        if not required <= set(reader.fieldnames or []):
            raise RuntimeError(f"기존 01 필수 열 누락: {sorted(required - set(reader.fieldnames or []))}")
        writer = csv.DictWriter(output_handle, fieldnames=fields)
        writer.writeheader()

        for row in reader:
            address = clean(row.get("Address")).lower()
            dataset = clean(row.get("Dataset"))
            original = clean(row.get("Original Label"), UNKNOWN)
            root = clean(row.get("Root Source"), UNKNOWN)
            if dataset not in DATASET_ORDER:
                raise RuntimeError(f"15개 연구 대상 외 Dataset이 01에 존재: {dataset!r}")
            if not ADDRESS_RE.fullmatch(address):
                raise RuntimeError(f"01 주소 형식 오류: {address!r}")
            if clean(row.get("Account Type")) == "Conventional Contract":
                raise RuntimeError(f"01에 Conventional Contract가 남아 있음: {address}")

            mapping = mapping_for(row)
            history = mapping_history(row, mapping)
            writer.writerow(
                {
                    "Address": address,
                    "Account Type": clean(row.get("Account Type"), "Not Audited"),
                    "Dataset": dataset,
                    "Original Label": original,
                    "라벨 확실성": mapping.character,
                    "라벨 속성 축": mapping.axis_text,
                    "표준 유형": mapping.display_type,
                    "표준 유형 구성요소": mapping.components_text,
                    "구체성": mapping.specificity,
                    "Root Source": root,
                    "라벨 기준일": clean(row.get("라벨 기준일"), UNKNOWN),
                    "원본 파일": clean(row.get("원본 파일"), UNKNOWN),
                    "판정 근거": mapping.reason,
                    "비고": mapping.note,
                }
            )
            digest.update(f"{address}\0{dataset}\0{original}\n".encode("utf-8"))
            row_count += 1
            dataset_rows[dataset] += 1

            key = (dataset, original, root)
            aggregate = rules.get(key)
            if aggregate is None:
                aggregate = RuleAggregate(mapping, history)
                rules[key] = aggregate
            elif aggregate.mapping != mapping or aggregate.history != history:
                raise RuntimeError(f"동일 02 규칙 키에 상충하는 매핑: {key}")
            aggregate.dates.add(clean(row.get("라벨 기준일"), UNKNOWN))
            aggregate.files.add(clean(row.get("원본 파일"), UNKNOWN))
            aggregate.old_reasons.add(clean(row.get("판정 근거"), UNKNOWN))
            if clean(row.get("비고")):
                aggregate.old_notes.add(clean(row.get("비고")))
            aggregate.row_count += 1

            if address in account_types:
                dataset_evidence = evidence[address].setdefault(dataset, DatasetEvidence())
                dataset_evidence.add(dataset, row, mapping, history)

    for labels in evidence.values():
        for dataset_evidence in labels.values():
            dataset_evidence.resolve()
    return row_count, digest.hexdigest(), rules, dict(evidence), dataset_rows


def write_02(path: Path, rules: dict[tuple[str, str, str], RuleAggregate]) -> int:
    fields = [
        "Dataset",
        "Original Label",
        "라벨 확실성",
        "라벨 속성 축",
        "표준 유형",
        "표준 유형 구성요소",
        "구체성",
        "Root Source",
        "라벨 기준일",
        "Ground Truth 근거",
        "비고",
        "기존 라벨 확실성",
        "기존 라벨 속성 축",
        "기존 표준 유형",
        "재표준화 여부",
        "재표준화 이력",
        "변경 사유",
        "변경 근거",
        "추가 검증 필요",
        "계정 유형 적용 기준",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for key in sorted(rules, key=lambda item: (DATASET_ORDER[item[0]], item[1], item[2])):
            dataset, original, root = key
            aggregate = rules[key]
            mapping = aggregate.mapping
            history = aggregate.history
            writer.writerow(
                {
                    "Dataset": dataset,
                    "Original Label": original,
                    "라벨 확실성": mapping.character,
                    "라벨 속성 축": mapping.axis_text,
                    "표준 유형": mapping.display_type,
                    "표준 유형 구성요소": mapping.components_text,
                    "구체성": mapping.specificity,
                    "Root Source": root,
                    "라벨 기준일": joined(aggregate.dates),
                    "Ground Truth 근거": mapping.reason,
                    "비고": mapping.note,
                    "기존 라벨 확실성": history["기존 라벨 확실성"],
                    "기존 라벨 속성 축": history["기존 라벨 속성 축"],
                    "기존 표준 유형": history["기존 표준 유형"],
                    "재표준화 여부": history["재표준화 여부"],
                    "재표준화 이력": history["재표준화 이력"],
                    "변경 사유": history["변경 사유"],
                    "변경 근거": history["변경 근거"],
                    "추가 검증 필요": mapping.validation,
                    "계정 유형 적용 기준": "EOA 및 Delegated EOA 포함; Conventional Contract 제외",
                }
            )
    return len(rules)


def load_old_pairs(path: Path) -> dict[tuple[str, str, str], dict[str, str]]:
    old: dict[tuple[str, str, str], dict[str, str]] = {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            key = (row["Address"], row["Dataset A"], row["Dataset B"])
            if key in old:
                raise RuntimeError(f"기존 04 중복 Pair: {key}")
            old[key] = row
    return old


PAIR_FIELDS = [
    "Address",
    "Account Type",
    "데이터셋 포함 수",
    "Dataset A",
    "Dataset B",
    "Original Label A",
    "Original Label B",
    "라벨 확실성 A",
    "라벨 확실성 B",
    "라벨 속성 축 A",
    "라벨 속성 축 B",
    "표준 유형 A",
    "표준 유형 B",
    "표준 유형 구성요소 A",
    "표준 유형 구성요소 B",
    "구체성 A",
    "구체성 B",
    "구조화 라벨 A",
    "구조화 라벨 B",
    "재표준화 라벨 포함 여부 A",
    "재표준화 라벨 포함 여부 B",
    "공통 비교 축",
    "충돌 축",
    "세분화 방향",
    "1차 라벨 관계",
    "최종 관계 유형",
    "05 분석 대상 여부",
    "주요 충돌 여부",
    "판정 규칙",
    "Root Source A",
    "Root Source B",
    "정규화 Root Source Set A",
    "정규화 Root Source Set B",
    "Root Source Information Completeness A",
    "Root Source Information Completeness B",
    "원천 출처 관계",
    "라벨 기준일 A",
    "라벨 기준일 B",
]


@dataclass
class ComparisonStats:
    old_counts: Counter[str] = field(default_factory=Counter)
    new_counts: Counter[str] = field(default_factory=Counter)
    transition_counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    new_addresses: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    old_addresses: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    rule_exposure: Counter[tuple[str, str, str, str, str]] = field(default_factory=Counter)
    rule_changed_pairs: Counter[tuple[str, str, str, str, str]] = field(default_factory=Counter)
    rule_transitions: dict[tuple[str, str, str, str, str], Counter[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    dataset_pair_changes: Counter[tuple[str, str]] = field(default_factory=Counter)
    dataset_pair_transitions: dict[tuple[str, str], Counter[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    representative_rows: list[dict[str, str]] = field(default_factory=list)
    representative_keys: set[tuple[object, ...]] = field(default_factory=set)


def pair_row(
    address: str,
    account_type: str,
    dataset_count: int,
    dataset_a: str,
    dataset_b: str,
    a: DatasetEvidence,
    b: DatasetEvidence,
    decision: PairDecision,
) -> dict[str, str]:
    return {
        "Address": address,
        "Account Type": account_type,
        "데이터셋 포함 수": str(dataset_count),
        "Dataset A": dataset_a,
        "Dataset B": dataset_b,
        "Original Label A": joined(a.originals),
        "Original Label B": joined(b.originals),
        "라벨 확실성 A": joined(a.characters),
        "라벨 확실성 B": joined(b.characters),
        "라벨 속성 축 A": a.axis_text,
        "라벨 속성 축 B": b.axis_text,
        "표준 유형 A": a.type_text,
        "표준 유형 B": b.type_text,
        "표준 유형 구성요소 A": components_text(a.type_components),
        "표준 유형 구성요소 B": components_text(b.type_components),
        "구체성 A": a.specificity_text,
        "구체성 B": b.specificity_text,
        "구조화 라벨 A": a.structure_text,
        "구조화 라벨 B": b.structure_text,
        "재표준화 라벨 포함 여부 A": "예" if a.changed_rules else "아니오",
        "재표준화 라벨 포함 여부 B": "예" if b.changed_rules else "아니오",
        "공통 비교 축": decision.common_axes,
        "충돌 축": decision.conflict_axes,
        "세분화 방향": decision.granularity_direction,
        "1차 라벨 관계": decision.relation_ko,
        "최종 관계 유형": decision.final_relation,
        "05 분석 대상 여부": decision.analysis_target,
        "주요 충돌 여부": decision.major_conflict,
        "판정 규칙": decision.rule,
        "Root Source A": joined(a.roots),
        "Root Source B": joined(b.roots),
        "정규화 Root Source Set A": root_source_set_text(dataset_a),
        "정규화 Root Source Set B": root_source_set_text(dataset_b),
        "Root Source Information Completeness A": root_source_completeness(dataset_a),
        "Root Source Information Completeness B": root_source_completeness(dataset_b),
        "원천 출처 관계": compare_roots(dataset_a, dataset_b),
        "라벨 기준일 A": joined({date for date in a.dates if date != UNKNOWN}),
        "라벨 기준일 B": joined({date for date in b.dates if date != UNKNOWN}),
    }


def maybe_add_representative(
    stats: ComparisonStats,
    new_row: dict[str, str],
    old_row: dict[str, str],
    changed_rules: set[tuple[str, str, str, str, str]],
) -> None:
    old_relation = old_row["최종 관계 유형"]
    new_relation = new_row["최종 관계 유형"]
    if old_relation == new_relation:
        return
    signatures = sorted((rule[0], rule[1]) for rule in changed_rules) or [("", "")]
    signature = signatures[0]
    key = (old_relation, new_relation, signature)
    if key in stats.representative_keys or len(stats.representative_rows) >= 250:
        return
    stats.representative_keys.add(key)
    reasons = sorted({rule[4] for rule in changed_rules})
    stats.representative_rows.append(
        {
            "Address": new_row["Address"],
            "Dataset A": new_row["Dataset A"],
            "Original Label A": new_row["Original Label A"],
            "Dataset B": new_row["Dataset B"],
            "Original Label B": new_row["Original Label B"],
            "기존 Standard Type A": old_row["표준 유형 A"],
            "기존 Standard Type B": old_row["표준 유형 B"],
            "재표준화 Standard Type A": new_row["표준 유형 A"],
            "재표준화 Standard Type B": new_row["표준 유형 B"],
            "기존 관계": old_relation,
            "새 관계": new_relation,
            "변경 이유": "; ".join(reasons) if reasons else "구체성·구조화 Claim 기반 관계 재판정",
        }
    )


def write_03_04(
    output_dir: Path,
    evidence: dict[str, dict[str, DatasetEvidence]],
    account_types: dict[str, str],
    old_pairs: dict[tuple[str, str, str], dict[str, str]],
) -> tuple[int, int, ComparisonStats, list[dict[str, str]]]:
    intersection_path = output_dir / MAIN_OUTPUTS[2]
    pair_path = output_dir / MAIN_OUTPUTS[3]
    stats = ComparisonStats()
    for old_row in old_pairs.values():
        relation = old_row["최종 관계 유형"]
        stats.old_counts[relation] += 1
        stats.old_addresses[relation].add(old_row["Address"])

    intersection_fields = ["Address", "Account Type", "데이터셋 포함 수", *DATASETS]
    intersection_rows = 0
    pair_rows = 0
    new_pair_records: list[dict[str, str]] = []
    seen_keys: set[tuple[str, str, str]] = set()

    with intersection_path.open("w", encoding="utf-8-sig", newline="") as i_handle, pair_path.open(
        "w", encoding="utf-8-sig", newline=""
    ) as p_handle:
        i_writer = csv.DictWriter(i_handle, fieldnames=intersection_fields)
        p_writer = csv.DictWriter(p_handle, fieldnames=PAIR_FIELDS)
        i_writer.writeheader()
        p_writer.writeheader()

        for address in sorted(evidence):
            labels = evidence[address]
            present = [dataset for dataset in DATASETS if dataset in labels]
            if len(present) < 2:
                continue
            account_type = account_types[address]
            i_row: dict[str, object] = {
                "Address": address,
                "Account Type": account_type,
                "데이터셋 포함 수": len(present),
            }
            for dataset in DATASETS:
                ev = labels.get(dataset)
                if ev is None:
                    i_row[dataset] = ""
                else:
                    i_row[dataset] = f"{joined(ev.characters)} || {ev.type_text}"
            i_writer.writerow(i_row)
            intersection_rows += 1

            for dataset_a, dataset_b in itertools.combinations(present, 2):
                a = labels[dataset_a]
                b = labels[dataset_b]
                decision = classify_pair(a, b)
                reverse = classify_pair(b, a)
                if decision.final_relation != reverse.final_relation:
                    raise RuntimeError(f"A/B 대칭성 위반: {address} {dataset_a} {dataset_b}")
                row = pair_row(
                    address,
                    account_type,
                    len(present),
                    dataset_a,
                    dataset_b,
                    a,
                    b,
                    decision,
                )
                key = (address, dataset_a, dataset_b)
                if key in seen_keys:
                    raise RuntimeError(f"새 04 중복 Pair: {key}")
                seen_keys.add(key)
                old_row = old_pairs.get(key)
                if old_row is None:
                    raise RuntimeError(f"기존 04에 없는 Pair: {key}")
                old_relation = old_row["최종 관계 유형"]
                new_relation = decision.final_relation
                stats.new_counts[new_relation] += 1
                stats.new_addresses[new_relation].add(address)
                stats.transition_counts[(old_relation, new_relation)] += 1

                changed_rules = a.changed_rules | b.changed_rules
                for rule in changed_rules:
                    stats.rule_exposure[rule] += 1
                    if old_relation != new_relation:
                        stats.rule_changed_pairs[rule] += 1
                        stats.rule_transitions[rule][(old_relation, new_relation)] += 1
                if old_relation != new_relation:
                    dataset_pair = (dataset_a, dataset_b)
                    stats.dataset_pair_changes[dataset_pair] += 1
                    stats.dataset_pair_transitions[dataset_pair][(old_relation, new_relation)] += 1
                    maybe_add_representative(stats, row, old_row, changed_rules)

                p_writer.writerow(row)
                new_pair_records.append(row)
                pair_rows += 1

    if set(old_pairs) != seen_keys:
        missing = set(old_pairs) - seen_keys
        added = seen_keys - set(old_pairs)
        raise RuntimeError(f"04 Pair key 불변성 위반: missing={len(missing)}, added={len(added)}")
    return intersection_rows, pair_rows, stats, new_pair_records


CAUSE_FIELDS = [
    *[field for field in PAIR_FIELDS if field not in {"05 분석 대상 여부"}],
    "시간 관계",
    "관계 해석",
    "가능한 원인",
    "수동 검증 우선순위",
    "3축 판정 근거",
]


def write_05(path: Path, pair_records: list[dict[str, str]]) -> tuple[int, Counter[str], dict[str, Counter[str]]]:
    relation_counts: Counter[str] = Counter()
    root_counts: Counter[str] = Counter()
    time_counts: Counter[str] = Counter()
    major_root: Counter[tuple[str, str]] = Counter()
    major_time: Counter[tuple[str, str]] = Counter()
    dataset_pairs: Counter[str] = Counter()
    type_pairs: Counter[str] = Counter()
    count = 0

    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CAUSE_FIELDS)
        writer.writeheader()
        for row in pair_records:
            relation = row["최종 관계 유형"]
            if relation == "Same Label":
                continue
            root = row["원천 출처 관계"]
            time = compare_times(row["라벨 기준일 A"], row["라벨 기준일 B"])
            interpretation, causes, priority = interpret_relation(relation, root, time)
            basis = (
                f"Root={root}; Label={relation}; Time={time}; "
                f"축={row['라벨 속성 축 A']} ↔ {row['라벨 속성 축 B']}; "
                f"구체성={row['구체성 A']} ↔ {row['구체성 B']}; "
                f"규칙={row['판정 규칙']}"
            )
            out = {field: row.get(field, "") for field in PAIR_FIELDS if field != "05 분석 대상 여부"}
            out.update(
                {
                    "원천 출처 관계": root,
                    "시간 관계": time,
                    "관계 해석": interpretation,
                    "가능한 원인": causes,
                    "수동 검증 우선순위": priority,
                    "3축 판정 근거": basis,
                }
            )
            writer.writerow(out)
            count += 1
            relation_counts[relation] += 1
            root_counts[root] += 1
            time_counts[time] += 1
            if relation in MAJOR_CONFLICTS:
                major_root[(relation, root)] += 1
                major_time[(relation, time)] += 1
                dataset_pairs[f"{row['Dataset A']} ↔ {row['Dataset B']} | {relation}"] += 1
                type_pairs[f"{row['표준 유형 A']} ↔ {row['표준 유형 B']} | {relation}"] += 1
    extras = {
        "root": root_counts,
        "time": time_counts,
        "major_root": major_root,
        "major_time": major_time,
        "dataset_pairs": dataset_pairs,
        "type_pairs": type_pairs,
    }
    return count, relation_counts, extras


def transition_summary(counter: Counter[tuple[str, str]]) -> str:
    return " | ".join(
        f"{old} → {new}: {count:,}"
        for (old, new), count in counter.most_common()
    ) or NA


def write_comparison_tables(
    comparison_dir: Path,
    rules: dict[tuple[str, str, str], RuleAggregate],
    stats: ComparisonStats,
    pair_total: int,
) -> dict[str, int]:
    comparison_dir.mkdir(parents=True, exist_ok=True)

    changed_rule_rows = []
    for (dataset, original, root), aggregate in rules.items():
        history = aggregate.history
        if history["재표준화 여부"] != "예":
            continue
        changed_rule_rows.append(
            {
                "Dataset": dataset,
                "Original Label": original,
                "Root Source": root,
                "기존 Label Character": history["기존 라벨 확실성"],
                "재표준화 Label Character": aggregate.mapping.character,
                "기존 Label Axis": history["기존 라벨 속성 축"],
                "재표준화 Label Axis": aggregate.mapping.axis_text,
                "기존 Standard Type": history["기존 표준 유형"],
                "재표준화 Standard Type": aggregate.mapping.display_type,
                "구체성": aggregate.mapping.specificity,
                "원본 01 행 수": aggregate.row_count,
                "변경 사유": history["변경 사유"],
                "변경 근거": history["변경 근거"],
                "추가 검증 필요": aggregate.mapping.validation,
            }
        )
    changed_rule_rows.sort(key=lambda row: (DATASET_ORDER[row["Dataset"]], row["Original Label"], row["Root Source"]))
    path = comparison_dir / COMPARISON_OUTPUTS[0]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(changed_rule_rows[0]) if changed_rule_rows else ["Dataset"])
        writer.writeheader()
        writer.writerows(changed_rule_rows)

    relations = [relation for relation in RELATION_ORDER if stats.old_counts[relation] or stats.new_counts[relation]]
    path = comparison_dir / COMPARISON_OUTPUTS[1]
    fields = ["관계 유형", "재표준화 전 Pair 수", "재표준화 후 Pair 수", "증감", "재표준화 전 비율", "재표준화 후 비율"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for relation in relations:
            old_count = stats.old_counts[relation]
            new_count = stats.new_counts[relation]
            writer.writerow(
                {
                    "관계 유형": relation,
                    "재표준화 전 Pair 수": old_count,
                    "재표준화 후 Pair 수": new_count,
                    "증감": new_count - old_count,
                    "재표준화 전 비율": f"{old_count / pair_total:.6%}",
                    "재표준화 후 비율": f"{new_count / pair_total:.6%}",
                }
            )

    path = comparison_dir / COMPARISON_OUTPUTS[2]
    fields = ["기존 관계", "새 관계", "전환 Pair 수", "관계 변경 여부"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for (old_relation, new_relation), count in stats.transition_counts.most_common():
            writer.writerow(
                {
                    "기존 관계": old_relation,
                    "새 관계": new_relation,
                    "전환 Pair 수": count,
                    "관계 변경 여부": "예" if old_relation != new_relation else "아니오",
                }
            )

    path = comparison_dir / COMPARISON_OUTPUTS[3]
    fields = [
        "Dataset",
        "Original Label",
        "기존 Standard Type",
        "재표준화 Standard Type",
        "해당 라벨 노출 Pair 수",
        "관계가 변경된 Pair 수",
        "주요 관계 전환",
        "변경 사유",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for rule, exposure in stats.rule_exposure.most_common():
            dataset, original, old_type, new_type, reason = rule
            writer.writerow(
                {
                    "Dataset": dataset,
                    "Original Label": original,
                    "기존 Standard Type": old_type,
                    "재표준화 Standard Type": new_type,
                    "해당 라벨 노출 Pair 수": exposure,
                    "관계가 변경된 Pair 수": stats.rule_changed_pairs[rule],
                    "주요 관계 전환": transition_summary(stats.rule_transitions[rule]),
                    "변경 사유": reason,
                }
            )

    path = comparison_dir / COMPARISON_OUTPUTS[4]
    fields = ["Dataset A", "Dataset B", "관계가 변경된 Pair 수", "주요 관계 전환"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for (dataset_a, dataset_b), count in stats.dataset_pair_changes.most_common():
            writer.writerow(
                {
                    "Dataset A": dataset_a,
                    "Dataset B": dataset_b,
                    "관계가 변경된 Pair 수": count,
                    "주요 관계 전환": transition_summary(stats.dataset_pair_transitions[(dataset_a, dataset_b)]),
                }
            )

    path = comparison_dir / COMPARISON_OUTPUTS[5]
    representative_fields = [
        "Address",
        "Dataset A",
        "Original Label A",
        "Dataset B",
        "Original Label B",
        "기존 Standard Type A",
        "기존 Standard Type B",
        "재표준화 Standard Type A",
        "재표준화 Standard Type B",
        "기존 관계",
        "새 관계",
        "변경 이유",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=representative_fields)
        writer.writeheader()
        writer.writerows(stats.representative_rows)

    return {
        "changed_rules": len(changed_rule_rows),
        "changed_pair_relations": sum(
            count for (old, new), count in stats.transition_counts.items() if old != new
        ),
        "representatives": len(stats.representative_rows),
    }


def markdown_table(rows: list[list[object]], headers: list[str]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" if index == 0 else "---:" for index in range(len(headers))) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in row) + " |")
    return lines


def render_report_with_historical_comparison(
    row_count: int,
    rule_count: int,
    intersection_rows: int,
    pair_rows: int,
    cause_rows: int,
    account_counts: Counter[str],
    comparison_stats: ComparisonStats,
    relation_counts_05: Counter[str],
    extras_05: dict[str, Counter],
    comparison_meta: dict[str, int],
) -> str:
    old = comparison_stats.old_counts
    new = comparison_stats.new_counts
    new_major = new["Strong Conflict"] + new["Taxonomy Conflict"]
    old_major = old["Strong Conflict"] + old["Taxonomy Conflict"]
    changed_transitions = [
        (old_relation, new_relation, count)
        for (old_relation, new_relation), count in comparison_stats.transition_counts.most_common()
        if old_relation != new_relation
    ][:15]
    top_rules = sorted(
        comparison_stats.rule_changed_pairs.items(),
        key=lambda item: (item[1], comparison_stats.rule_exposure[item[0]]),
        reverse=True,
    )[:12]
    top_dataset_pairs = comparison_stats.dataset_pair_changes.most_common(12)

    lines = [
        "# Ethereum 동일 주소 라벨 재표준화·충돌 분석",
        "",
        "## 1. 연구 목적과 분석 흐름",
        "",
        "원본 Ground Truth가 실제로 보장하는 의미보다 더 구체적인 표준 유형을 만들지 않는 **의미 보존형 재표준화**를 적용했다. Original Label은 수정하지 않았고, 15개 Address/Account 데이터셋의 동일 주소 Pair를 다시 판정했다.",
        "",
        "```text",
        "00 계정유형 검증",
        "        ↓",
        "01 주소·Original Label 통합 및 의미 보존형 전처리",
        "        ↓",
        "02 Label Character × Label Axis × Standard Type × 구체성 정의",
        "        ↓",
        "03 동일 주소 데이터셋 교집합",
        "        ↓",
        "04 모든 Dataset Pair의 구조화 Claim 비교",
        "        ↓",
        "05 Same Label을 제외한 전 관계의 Root × Label × Time 3축 원인 분석",
        "```",
        "",
        "## 2. 공통 전처리와 재표준화 원칙",
        "",
        "- 주소는 소문자 `0x` + 40자리 16진수로 통일했다.",
        "- Label Character는 `Abnormal`, `Normal`, `Uncertain`을 유지했다.",
        "- `악성으로 확인되지 않음`은 Normal로 간주하지 않았다.",
        "- `Unspecified Abnormal`은 Abnormal이지만 세부 Behavior가 불명인 경우이며 Uncertain과 다르다.",
        "- Standard Type은 Phishing, Scam, Hack/Exploit, Rug Pull, Ponzi, Wash Trading, Ransomware, Illicit/Criminal 등을 유지했다.",
        "- 구체성은 `구체적`, `포괄적`, `복합`, `세부유형미상`으로 기록했고 Normal/Uncertain에는 `해당 없음`을 사용했다.",
        "- Label Axis는 `Behavior`, `Status`, `Role`, `Technical Attribute`로 분리했다.",
        "- 원본 라벨이 특정 행위·역할을 직접 명시하고 다른 유형으로 해석될 여지가 작으면, 그 근거가 보장하는 범위 안에서 구체적으로 매핑했다.",
        "- `Scam Receiving Address`는 확인된 scam infrastructure의 자금 수취 주소라는 직접 의미를 보존해 `Behavior: Scam`으로 비교했다. 다만 주소 소유자가 Scam 운영 주체임을 독립적으로 증명하는 라벨로 확대 해석하지 않았다.",
        "- `Wallet Drainer`는 자산 탈취 행위·도구를 직접 나타내지만 phishing 획득 방식을 필수로 보장하지 않으므로 별도 구체 유형으로 유지했다.",
        "- `Honeypot Scam`은 Scam을 직접 명시하지만 유동성 회수형 Rug Pull 메커니즘까지 보장하지 않으므로 `Scam`으로 유지했다.",
        "- `phish-hack`은 `Phishing OR Hack/Exploit`로 보존하며, 둘 모두가 확정됐다는 의미로 해석하지 않았다.",
        "- 구조화 Claim을 사용해 OR 복합 라벨과 여러 독립 라벨의 동시 존재를 구분했다.",
        "- Conventional Contract는 제외하고 Delegated EOA는 별도 Account Type으로 유지했다.",
        f"- 계정유형 검증: EOA {account_counts['EOA']:,}, Delegated EOA {account_counts['Delegated EOA']:,}, Conventional Contract {account_counts['Conventional Contract']:,}.",
        "",
        "### 핵심 재표준화 예",
        "",
        *markdown_table(
            [
                ["scam receiving address (Ethereum subset)", "Scam", "Behavior: Scam", "구체적"],
                ["Wallet Drainer / 0xhabitat.eth Multisig Drainer", "Phishing", "Behavior: Wallet Drainer", "구체적"],
                ["Honeypot Scam", "Scam", "Behavior: Scam", "구체적"],
                ["phish-hack", "Phishing", "Phishing | Hack/Exploit", "복합"],
                ["master_blacklist_set / all_across_hard", "Scam", "Unspecified Abnormal", "포괄적"],
                ["ETH Liquidity Scam", "Rug Pull", "Scam", "구체적"],
                ["Other / 확인 불가", "Other", "Unspecified Abnormal", "세부유형미상"],
                ["Metamorphic Contract", "Other", "Technical Attribute: Metamorphic Contract", "구체적"],
                ["ATO Stolen Funds", "Hack/Exploit 또는 Other", "Status: Stolen Funds", "구체적"],
            ],
            ["Original Label", "기존 Standard Type", "재표준화", "구체성"],
        ),
        "",
        "## 3. 산출 데이터 규모",
        "",
        *markdown_table(
            [
                ["01 전처리 통합표", f"{row_count:,}행"],
                ["02 라벨 속성 정의", f"{rule_count:,}개 규칙"],
                ["03 중복 고유 주소", f"{intersection_rows:,}개"],
                ["04 전체 Pair-Address", f"{pair_rows:,}건"],
                ["05 Same 제외 3축 분석", f"{cause_rows:,}건"],
            ],
            ["산출물", "규모"],
        ),
        "",
        "## 4. Pair 관계 판정 규칙",
        "",
        "1. 양쪽 모두 Uncertain이면 `Uncertain Comparison`, 한쪽만 Uncertain이면 `Label Coverage Difference`다.",
        "2. 공통 Label Axis가 없으면 `Status–Behavior Relation` 또는 `Axis Difference`이며 Behavior 충돌로 세지 않는다.",
        "3. 공통 축의 명시적 Abnormal ↔ Normal만 `Strong Conflict`다.",
        "4. 포괄·세부유형미상 ↔ 구체적은 `Granularity Difference`다.",
        "5. OR 복합 라벨과 그 구성요소 또는 공통 구성요소가 있는 라벨은 `Compatible Label`이다.",
        "6. 같은 축의 구체적 유형이 겹치지 않을 때만 `Taxonomy Conflict` 후보가 된다.",
        "7. 엄격 기준에서 `Phishing ↔ Scam`은 공통 구체 유형이 없으므로 `Taxonomy Conflict`로 판정한다.",
        "",
        "## 5. 재표준화 전후 관계 비교",
        "",
        *markdown_table(
            [
                [relation, f"{old[relation]:,}", f"{new[relation]:,}", f"{new[relation] - old[relation]:+,}"]
                for relation in RELATION_ORDER
                if old[relation] or new[relation]
            ],
            ["관계 유형", "재표준화 전", "재표준화 후", "증감"],
        ),
        "",
        f"- 전체 Pair 수는 **{pair_rows:,}건**으로 전후 동일하다.",
        f"- 관계가 실제로 변경된 Pair는 **{comparison_meta['changed_pair_relations']:,}건**이다.",
        f"- 주요 충돌은 전 {old_major:,}건에서 후 **{new_major:,}건**으로 바뀌었다.",
        "- 충돌 수 감소 자체가 목표가 아니라, 포괄 라벨·복합 라벨·비행위 축에서 발생한 인공적 Taxonomy Conflict를 분리한 결과다.",
        "",
        "### 주요 관계 전환",
        "",
        *markdown_table(
            [[old_relation, new_relation, f"{count:,}"] for old_relation, new_relation, count in changed_transitions],
            ["기존 관계", "새 관계", "Pair 수"],
        ),
        "",
        "## 6. 변화에 큰 영향을 준 Original Label",
        "",
        *markdown_table(
            [
                [
                    rule[0],
                    rule[1],
                    rule[2],
                    rule[3],
                    f"{exposure:,}",
                    f"{comparison_stats.rule_changed_pairs[rule]:,}",
                ]
                for rule, exposure in top_rules
            ],
            ["Dataset", "Original Label", "기존 유형", "새 유형", "노출 Pair", "관계 변경 Pair"],
        ),
        "",
        "## 7. 변화가 큰 Dataset Pair",
        "",
        *markdown_table(
            [
                [dataset_a, dataset_b, f"{count:,}", transition_summary(comparison_stats.dataset_pair_transitions[(dataset_a, dataset_b)])]
                for (dataset_a, dataset_b), count in top_dataset_pairs
            ],
            ["Dataset A", "Dataset B", "관계 변경 Pair", "주요 전환"],
        ),
        "",
        "## 8. 재표준화 후 주요 충돌",
        "",
        *markdown_table(
            [
                ["Strong Conflict", f"{new['Strong Conflict']:,}", f"{len(comparison_stats.new_addresses['Strong Conflict']):,}"],
                ["Taxonomy Conflict", f"{new['Taxonomy Conflict']:,}", f"{len(comparison_stats.new_addresses['Taxonomy Conflict']):,}"],
                ["합계", f"{new_major:,}", f"{len(comparison_stats.new_addresses['Strong Conflict'] | comparison_stats.new_addresses['Taxonomy Conflict']):,}"],
            ],
            ["주요 충돌 유형", "Pair-Address", "고유 주소"],
        ),
        "",
        "Strong Conflict는 정상·이상 직접 모순이므로 최우선 수동 검증 대상이다. Taxonomy Conflict는 같은 Behavior 축의 구체적 유형 차이이며, 복수 행위의 병존·시점 변화·원천 taxonomy 차이를 사건 단위로 확인해야 한다.",
        "",
        "## 9. Root Source × Label × Time 3축 해석",
        "",
        "05는 Same Label을 제외한 모든 Pair를 보존한다. 최종 관계는 Label Claim으로 결정하고 Root Source와 Time은 원인 해석 보조 축으로만 사용했다.",
        "",
        "### 05 전체 원천 출처 관계",
        "",
        *markdown_table(
            [[key, f"{extras_05['root'][key]:,}"] for key in ["동일", "일부 공유", "서로 다름"]],
            ["원천 출처 관계", "Pair-Address"],
        ),
        "",
        "### 05 전체 시간 관계",
        "",
        *markdown_table(
            [[key, f"{extras_05['time'][key]:,}"] for key in ["동일 시기", "다른 시기", UNKNOWN]],
            ["시간 관계", "Pair-Address"],
        ),
        "",
        "시간 정보가 없는 Pair에서는 시점 차이를 원인으로 확정하지 않았으며 `확인 불가`로 남겼다.",
        "",
        "## 10. 해석상 주의사항",
        "",
        "- Same Label 감소는 품질 악화가 아니라, `phish-hack`처럼 이전에 하나로 축소됐던 복합 의미를 정직하게 복원한 결과일 수 있다.",
        "- Granularity Difference는 충돌이 아니라 정보량 차이다. 포괄 blacklist와 구체 행위 라벨을 독립적인 동일 수준 Ground Truth처럼 해석하면 안 된다.",
        "- Compatible Label은 정확히 같은 라벨이라는 뜻이 아니라 OR 구성요소 중첩·의미상 중첩·추가 축 존재를 뜻한다.",
        "- Role, Status, Technical Attribute는 Behavior와 직접 충돌시키지 않았다.",
        "- Root Source 관계는 Dataset-level Label construction Source Set의 중첩이며 개별 주소의 실제 유입 경로를 증명하지 않는다.",
        "- `Phishing ↔ Scam`은 엄격 세부유형 기준에서 Taxonomy Conflict로 처리하며 이 정책 선택이 결과 규모를 지배함을 명시한다.",
        "",
        "## 11. 산출물",
        "",
        "- `01_전처리_주소라벨_통합표.csv`: 재표준화된 주소별 전체 통합표",
        "- `02_라벨_속성_정의.csv`: 구체성·구성요소·기존/신규 유형·재표준화 이력 포함",
        "- `03_중복주소_데이터셋교집합.csv`: 동일 주소별 15개 데이터셋 교집합",
        "- `04_중복주소_데이터셋Pair비교.csv`: 구조화 Claim 기반 모든 Dataset Pair 판정",
        "- `05_충돌주소_원인분석.csv`: Same을 제외한 모든 관계의 Root×Label×Time 3축 분석",
        f"- `{COMPARISON_DIRNAME}/`: 변경 규칙, 전후 관계 수, 관계 전환, Original Label 영향, Dataset Pair 영향, 대표 사례",
        "- `restandardize_label_analysis.py`: 전체 재생성·검증 스크립트",
        "",
        "## 12. 검증 결과",
        "",
        f"- 04 Pair key는 재표준화 전후 **{pair_rows:,}건 모두 보존**됐다.",
        "- 각 Pair는 정확히 하나의 최종 관계 유형에 배정됐다.",
        "- A/B 순서를 바꾸어도 최종 관계 유형이 같음을 전 Pair에서 검증했다.",
        "- Uncertain이 포함된 Pair가 Strong/Taxonomy/Granularity로 들어가지 않도록 검증했다.",
        "- Taxonomy Conflict는 공통 축의 구체적 유형이 겹치지 않는 경우에만 생성했다.",
        "- 03~05에는 EOA와 Delegated EOA만 포함되며 Conventional Contract는 제외했다.",
    ]
    return "\n".join(lines) + "\n"


def render_report(
    row_count: int,
    rule_count: int,
    intersection_rows: int,
    pair_rows: int,
    cause_rows: int,
    account_counts: Counter[str],
    comparison_stats: ComparisonStats,
    relation_counts_05: Counter[str],
    extras_05: dict[str, Counter],
    comparison_meta: dict[str, int],
) -> str:
    """최종 결과만 제시하고 중간·이전 버전 비교값은 노출하지 않는다."""
    final = comparison_stats.new_counts
    major_pairs = final["Strong Conflict"] + final["Taxonomy Conflict"]
    major_addresses = len(
        comparison_stats.new_addresses["Strong Conflict"]
        | comparison_stats.new_addresses["Taxonomy Conflict"]
    )

    lines = [
        "# Ethereum 동일 주소 라벨 충돌 분석 — 최종 보고서",
        "",
        "## 1. 최종 결론",
        "",
        f"15개 Ethereum Address/Account 데이터셋에서 중복 주소 {intersection_rows:,}개와 Dataset Pair {pair_rows:,}건을 비교했다. 최종적으로 직접적인 주요 충돌은 **{major_pairs:,} Pair / {major_addresses:,}개 고유 주소**다.",
        "",
        *markdown_table(
            [
                ["Strong Conflict", f"{final['Strong Conflict']:,}", f"{len(comparison_stats.new_addresses['Strong Conflict']):,}", "Abnormal과 명시적 Normal의 직접 모순"],
                ["Taxonomy Conflict", f"{final['Taxonomy Conflict']:,}", f"{len(comparison_stats.new_addresses['Taxonomy Conflict']):,}", "같은 Behavior 축의 구체적 유형 차이"],
                ["합계", f"{major_pairs:,}", f"{major_addresses:,}", "사건 단위 수동 검증 우선 대상"],
            ],
            ["주요 충돌 유형", "Pair-Address", "고유 주소", "의미"],
        ),
        "",
        f"Same Label을 제외한 {cause_rows:,}건은 05에서 모두 보존했다. Compatible Label, Granularity Difference, Uncertain 및 축 차이는 정보 차이 또는 비교 한계이므로 주요 충돌 수에 포함하지 않았다.",
        "",
        "## 2. 최종 분석 흐름",
        "",
        "```text",
        "00 계정유형 검증",
        "        ↓",
        "01 주소·Original Label 통합 및 의미 보존형 전처리",
        "        ↓",
        "02 Label Character × Label Axis × Standard Type × 구체성 정의",
        "        ↓",
        "03 동일 주소 데이터셋 교집합",
        "        ↓",
        "04 모든 Dataset Pair의 구조화 Claim 비교",
        "        ↓",
        "05 Same Label을 제외한 전 관계의 Root × Label × Time 3축 원인 분석",
        "```",
        "",
        "## 3. 최종 라벨 표준화 원칙",
        "",
        "- 주소는 소문자 `0x` + 40자리 16진수로 통일했다.",
        "- Label Character는 `Abnormal`, `Normal`, `Uncertain`으로 구분하고, 악성으로 확인되지 않았다는 이유만으로 Normal로 간주하지 않았다.",
        "- `Unspecified Abnormal`은 이상 주소임은 확인됐지만 세부 Behavior가 불명인 경우이며 Uncertain과 다르다.",
        "- Label Axis는 `Behavior`, `Status`, `Role`, `Technical Attribute`로 분리했다.",
        "- 원본 라벨이 특정 행위·역할을 직접 명시하고 다른 유형으로 해석될 여지가 작으면 근거 범위 안에서 구체적으로 매핑했다.",
        "- `Scam Receiving Address`는 `Behavior: Scam`, `Wallet Drainer`는 별도 Behavior 유형으로 유지했다.",
        "- `Honeypot Scam`은 Scam으로, 원본에 `Rug` 또는 `Rug Pull`이 직접 명시된 라벨은 Rug Pull로 분류했다.",
        "- `master_blacklist_set`과 `all_across_hard`는 주소별 세부 행위가 없으므로 `Unspecified Abnormal / 포괄적`으로 유지했다. 데이터셋 수준의 맥락은 phishing-related scam corpus다.",
        "- 기존 Standard Type `Other`는 최종 비교 유형으로 사용하지 않았다. 원본 의미를 확인할 수 있으면 구체 유형·Status·Role·Technical Attribute로 재분류하고, 확인할 수 없을 때만 `Unspecified Abnormal`로 남겼다. Original Label은 그대로 보존했다.",
        "- `phish-hack`은 `Phishing OR Hack/Exploit` 복합 의미로 보존했다.",
        "- Conventional Contract는 제외하고 Delegated EOA는 별도 Account Type으로 유지했다.",
        f"- 계정유형 검증 결과: EOA {account_counts['EOA']:,}, Delegated EOA {account_counts['Delegated EOA']:,}, Conventional Contract {account_counts['Conventional Contract']:,}.",
        "",
        "### 핵심 매핑",
        "",
        *markdown_table(
            [
                ["scam receiving address (Ethereum subset)", "Behavior", "Scam", "구체적"],
                ["Wallet Drainer / 0xhabitat.eth Multisig Drainer", "Behavior", "Wallet Drainer", "구체적"],
                ["Honeypot Scam", "Behavior", "Scam", "구체적"],
                ["Rug / Rug Pull 명시 라벨", "Behavior", "Rug Pull", "구체적"],
                ["phish-hack", "Behavior", "Phishing | Hack/Exploit", "복합"],
                ["master_blacklist_set / all_across_hard", "Behavior", "Unspecified Abnormal", "포괄적"],
                ["Other / 확인 불가", "Behavior", "Unspecified Abnormal", "세부유형미상"],
                ["Metamorphic Contract", "Technical Attribute", "Metamorphic Contract", "구체적"],
                ["ATO Stolen Funds", "Status", "Stolen Funds", "구체적"],
            ],
            ["Original Label", "Label Axis", "최종 Standard Type", "구체성"],
        ),
        "",
        "## 4. 최종 데이터 규모",
        "",
        *markdown_table(
            [
                ["01 전처리 통합표", f"{row_count:,}행"],
                ["02 라벨 속성 정의", f"{rule_count:,}개 규칙"],
                ["03 중복 고유 주소", f"{intersection_rows:,}개"],
                ["04 전체 Pair-Address", f"{pair_rows:,}건"],
                ["05 Same 제외 3축 분석", f"{cause_rows:,}건"],
            ],
            ["산출물", "규모"],
        ),
        "",
        "## 5. 최종 Pair 관계 판정 규칙",
        "",
        "1. 양쪽 모두 Uncertain이면 `Uncertain Comparison`, 한쪽만 Uncertain이면 `Label Coverage Difference`다.",
        "2. 공통 Label Axis가 없으면 `Status–Behavior Relation` 또는 `Axis Difference`이며 Behavior 충돌로 세지 않는다.",
        "3. 공통 축의 명시적 Abnormal ↔ Normal만 `Strong Conflict`다.",
        "4. 포괄·세부유형미상 ↔ 구체적은 `Granularity Difference`다.",
        "5. OR 복합 라벨과 그 구성요소 또는 공통 구성요소가 있는 라벨은 `Compatible Label`이다.",
        "6. 같은 축의 구체적 유형이 겹치지 않을 때만 `Taxonomy Conflict`다.",
        "7. 엄격 기준에서 `Phishing ↔ Scam`은 공통 구체 유형이 없으므로 `Taxonomy Conflict`로 판정한다.",
        "",
        "## 6. 최종 Pair 관계 분포",
        "",
        *markdown_table(
            [
                [relation, f"{final[relation]:,}", f"{final[relation] / pair_rows:.6%}"]
                for relation in RELATION_ORDER
                if final[relation]
            ],
            ["최종 관계 유형", "Pair-Address", "전체 비율"],
        ),
        "",
        "- `Same Label`은 동일한 의미의 직접 합의다.",
        "- `Compatible Label`은 의미가 중첩하지만 완전히 같은 라벨은 아니다.",
        "- `Granularity Difference`는 포괄 라벨과 구체 라벨의 정보량 차이이며 충돌이 아니다.",
        "- `Uncertain Comparison`과 `Label Coverage Difference`는 정상·이상 직접 모순으로 해석하지 않는다.",
        "",
        "## 7. Root Source × Label × Time 해석",
        "",
        "05는 Same Label을 제외한 모든 Pair를 보존한다. 최종 관계는 Label Claim으로 결정하고 Root Source와 Time은 원인 해석 보조 축으로 사용했다.",
        "",
        *markdown_table(
            [[key, f"{extras_05['root'][key]:,}"] for key in ["동일", "일부 공유", "서로 다름"]],
            ["원천 출처 관계", "Pair-Address"],
        ),
        "",
        *markdown_table(
            [[key, f"{extras_05['time'][key]:,}"] for key in ["동일 시기", "다른 시기", UNKNOWN]],
            ["시간 관계", "Pair-Address"],
        ),
        "",
        "시간 정보가 없는 Pair에서는 시점 차이를 원인으로 확정하지 않았으며 `확인 불가`로 남겼다. Root Source 관계는 Dataset-level Source Set 중첩이므로 개별 주소의 실제 provenance 또는 완전한 독립성을 증명하지 않는다.",
        "",
        "## 8. 연구 해석",
        "",
        f"- 실질적인 주요 충돌은 **{major_pairs:,} Pair / {major_addresses:,}주소**이며 이 집합이 우선 수동 검증 대상이다.",
        "- Strong Conflict는 정상·이상 직접 모순이므로 가장 우선순위가 높다.",
        "- Taxonomy Conflict는 복수 행위의 병존, 원천 taxonomy 차이, 라벨 시점 차이를 사건 단위로 확인해야 한다.",
        "- Granularity Difference는 포괄 blacklist와 구체 Behavior 라벨의 정보량 차이를 보여준다.",
        "- Role, Status, Technical Attribute는 Behavior와 직접 충돌시키지 않았다.",
        "- `Phishing ↔ Scam` 호환 정책은 결과 규모에 영향을 줄 수 있으므로 논문에서 분석 규칙으로 명시해야 한다.",
        "",
        "## 9. 산출물",
        "",
        "- `01_전처리_주소라벨_통합표.csv`: 최종 주소별 라벨 통합표",
        "- `02_라벨_속성_정의.csv`: 최종 라벨 속성·구체성·구성요소 정의",
        "- `03_중복주소_데이터셋교집합.csv`: 동일 주소별 15개 데이터셋 교집합",
        "- `04_중복주소_데이터셋Pair비교.csv`: 구조화 Claim 기반 모든 Dataset Pair 판정",
        "- `05_충돌주소_원인분석.csv`: Same을 제외한 모든 관계의 Root×Label×Time 분석",
        "- `restandardize_label_analysis.py`: 전체 재생성·검증 스크립트",
        "",
        "## 10. 검증 결과",
        "",
        f"- 04에는 **{pair_rows:,}개 고유 Pair key**가 있으며 중복·self-pair가 없다.",
        "- 각 Pair는 정확히 하나의 최종 관계 유형에 배정됐다.",
        "- A/B 순서를 바꾸어도 최종 관계 유형이 같음을 전 Pair에서 검증했다.",
        "- Uncertain이 포함된 Pair가 Strong/Taxonomy/Granularity로 들어가지 않도록 검증했다.",
        "- Taxonomy Conflict는 공통 축의 구체적 유형이 겹치지 않는 경우에만 생성했다.",
        "- 03~05에는 EOA와 Delegated EOA만 포함되며 Conventional Contract는 제외했다.",
    ]
    return "\n".join(lines) + "\n"


def validate_outputs(
    source_01: Path,
    output_dir: Path,
    source_row_count: int,
    source_digest: str,
    rule_count: int,
    intersection_rows: int,
    pair_rows: int,
    cause_rows: int,
    stats: ComparisonStats,
) -> dict[str, object]:
    if pair_rows != sum(stats.old_counts.values()):
        raise RuntimeError("기존/신규 전체 Pair 수 불일치")
    if pair_rows != sum(stats.new_counts.values()):
        raise RuntimeError("신규 관계 유형 합계가 전체 Pair 수와 다름")
    if cause_rows != pair_rows - stats.new_counts["Same Label"]:
        raise RuntimeError("05 행 수는 전체 Pair에서 Same Label을 제외한 수와 같아야 함")
    expected_pairs = 0
    with (output_dir / MAIN_OUTPUTS[2]).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["Account Type"] not in {"EOA", "Delegated EOA"}:
                raise RuntimeError("03에 분석 제외 Account Type이 있음")
            expected_pairs += math.comb(int(row["데이터셋 포함 수"]), 2)
    if expected_pairs != pair_rows:
        raise RuntimeError(f"03 기반 Pair 기대값 불일치: {expected_pairs} != {pair_rows}")

    digest = hashlib.sha256()
    output_rows = 0
    with (output_dir / MAIN_OUTPUTS[0]).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required_new = {"구체성", "표준 유형 구성요소"}
        if not required_new <= set(reader.fieldnames or []):
            raise RuntimeError("새 01에 구체성 또는 구성요소 열이 없음")
        for row in reader:
            digest.update(
                f"{row['Address']}\0{row['Dataset']}\0{row['Original Label']}\n".encode("utf-8")
            )
            output_rows += 1
    if output_rows != source_row_count or digest.hexdigest() != source_digest:
        raise RuntimeError("01 Original Label·Address·Dataset 보존 검증 실패")

    with (output_dir / MAIN_OUTPUTS[1]).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required_02 = {"구체성", "재표준화 이력", "기존 표준 유형", "재표준화 여부"}
        if not required_02 <= set(reader.fieldnames or []):
            raise RuntimeError("02 필수 재표준화 열 누락")
        count_02 = sum(1 for _ in reader)
    if count_02 != rule_count:
        raise RuntimeError("02 행 수 검증 실패")

    with (output_dir / MAIN_OUTPUTS[3]).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            relation = row["최종 관계 유형"]
            characters = {row["라벨 확실성 A"], row["라벨 확실성 B"]}
            if UNCERTAIN in characters and relation in {
                "Strong Conflict",
                "Taxonomy Conflict",
                "Granularity Difference",
                "Same Label",
            }:
                raise RuntimeError(f"Uncertain 관계 불변조건 위반: {row['Address']}")
            if relation == "Taxonomy Conflict" and not row["충돌 축"]:
                raise RuntimeError(f"Taxonomy에 충돌 축 누락: {row['Address']}")
            if relation == "Strong Conflict" and characters != {ABNORMAL, NORMAL}:
                raise RuntimeError(f"Strong Conflict polarity 오류: {row['Address']}")
            expected_root = compare_roots(row["Dataset A"], row["Dataset B"])
            if row["원천 출처 관계"] != expected_root or expected_root == UNKNOWN:
                raise RuntimeError(f"Root Source Set 관계 오류: {row['Address']}")
            set_a = dataset_root_sources(row["Dataset A"])
            set_b = dataset_root_sources(row["Dataset B"])
            if expected_root == "동일" and set_a != set_b:
                raise RuntimeError(f"Same Root invariant 오류: {row['Address']}")
            if expected_root == "일부 공유" and (not (set_a & set_b) or set_a == set_b):
                raise RuntimeError(f"Partially Shared Root invariant 오류: {row['Address']}")
            if expected_root == "서로 다름" and set_a & set_b:
                raise RuntimeError(f"Different Root invariant 오류: {row['Address']}")

    return {
        "source_01": str(source_01),
        "output_01_rows": source_row_count,
        "original_triplet_sha256": source_digest,
        "mapping_rules": rule_count,
        "intersection_addresses": intersection_rows,
        "pair_rows": pair_rows,
        "cause_rows": cause_rows,
        "relation_counts": dict(stats.new_counts),
        "validation": "passed",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ethereum Address 라벨 의미 보존형 재표준화")
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = parse_args()
    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    if source_dir == output_dir:
        raise RuntimeError(
            "원본 보존을 위해 --source-dir과 --output-dir은 서로 다른 디렉터리여야 합니다."
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    account_path = source_dir / "00_주소_계정유형_검증.csv"
    if not account_path.exists():
        account_path = source_dir.parent / "00_주소_계정유형_검증.csv"
    account_types, account_counts = load_account_types(account_path)
    print("[1/7] 01 재표준화·구조화 Claim 생성", flush=True)
    row_count, digest, rules, evidence, dataset_rows = stream_restandardize_01(
        source_dir / MAIN_OUTPUTS[0], output_dir / MAIN_OUTPUTS[0], account_types
    )
    print(f"  01 rows={row_count:,}, mapping keys={len(rules):,}", flush=True)

    print("[2/7] 02 라벨 속성 정의 생성", flush=True)
    rule_count = write_02(output_dir / MAIN_OUTPUTS[1], rules)

    print("[3/7] 기존 04 로드 및 03·04 재생성", flush=True)
    old_pairs = load_old_pairs(source_dir / MAIN_OUTPUTS[3])
    intersection_rows, pair_rows, comparison_stats, pair_records = write_03_04(
        output_dir, evidence, account_types, old_pairs
    )
    print(f"  shared addresses={intersection_rows:,}, pairs={pair_rows:,}", flush=True)

    print("[4/7] 05 Root×Label×Time 원인 분석 생성", flush=True)
    cause_rows, relation_counts_05, extras_05 = write_05(
        output_dir / MAIN_OUTPUTS[4], pair_records
    )

    print("[5/7] 재표준화 전후 비교표 생성", flush=True)
    comparison_meta = write_comparison_tables(
        output_dir / COMPARISON_DIRNAME, rules, comparison_stats, pair_rows
    )

    print("[6/7] 분석 리포트 생성", flush=True)
    report = render_report(
        row_count,
        rule_count,
        intersection_rows,
        pair_rows,
        cause_rows,
        account_counts,
        comparison_stats,
        relation_counts_05,
        extras_05,
        comparison_meta,
    )
    (output_dir / MAIN_OUTPUTS[5]).write_text(report, encoding="utf-8-sig")

    print("[7/7] 불변조건·원본 보존 검증", flush=True)
    manifest = validate_outputs(
        source_dir / MAIN_OUTPUTS[0],
        output_dir,
        row_count,
        digest,
        rule_count,
        intersection_rows,
        pair_rows,
        cause_rows,
        comparison_stats,
    )
    manifest.update(
        {
            "dataset_rows": dict(dataset_rows),
            "before_relation_counts": dict(comparison_stats.old_counts),
            "comparison": comparison_meta,
        }
    )
    (output_dir / "재표준화_검증_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print("완료", flush=True)
    for relation in RELATION_ORDER:
        before = comparison_stats.old_counts[relation]
        after = comparison_stats.new_counts[relation]
        if before or after:
            print(f"  {relation}: {before:,} -> {after:,} ({after-before:+,})", flush=True)
    print(f"  05 rows: {cause_rows:,}", flush=True)
    print(f"  output: {output_dir}", flush=True)


if __name__ == "__main__":
    main()
