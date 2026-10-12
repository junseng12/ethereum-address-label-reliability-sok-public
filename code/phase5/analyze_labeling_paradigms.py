from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


RESEARCH = {
    "BERT4ETH",
    "XBlock Ethereum Phishing Transaction Network",
    "Phishing Detection on Ethereum (Trans2Vec)",
    "RiskProp",
    "DA-HGNN Phishing Detection Dataset",
    "EthereumHeist",
    "Forta Labelled Datasets",
    "FDGNN Fraud Address Dataset",
}
COMMUNITY = {
    "scamsonethereum",
    "EtherScamDB",
    "Ethereum Illicit Accounts (Farrugia et al.)",
    "Cryptocurrency Exchange Scams - Ethereum subset",
    "Real-CATS",
}
UNCLASSIFIED = {"EX-Graph – Wash-Trading", "OFAC Ethereum Addresses"}
BROAD_TYPES = {
    "", "Unspecified Abnormal", "Illicit/Criminal", "Uncertain",
    "Benign", "Sanctioned", "Not Applicable",
}


def components(value: str) -> set[str]:
    return {part.strip() for part in str(value).split("|") if part.strip()}


def paradigm(dataset: str) -> str:
    if dataset in RESEARCH:
        return "Research"
    if dataset in COMMUNITY:
        return "Community"
    return "Unclassified"


def is_specific_behavior(row: pd.Series, side: str) -> bool:
    types = components(row[f"표준 유형 {side}"])
    return (
        row[f"라벨 확실성 {side}"] == "Abnormal"
        and "Behavior" in row[f"라벨 속성 축 {side}"]
        and bool(types - BROAD_TYPES)
        and not bool(types & {"Unspecified Abnormal", "Illicit/Criminal"})
    )


def add_row(rows, section, item, subgroup="", unit="", denominator="",
            numerator="", rate="", interpretation="", basis="") -> None:
    rows.append({
        "분석 구분": section,
        "항목": item,
        "세부 그룹": subgroup,
        "비교 단위": unit,
        "분모": denominator,
        "분자": numerator,
        "비율(%)": rate,
        "판정 및 해석": interpretation,
        "산출 기준": basis,
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    package_root = Path(__file__).resolve().parents[2]
    parser.add_argument("--results-dir", type=Path, default=package_root / "results")
    parser.add_argument(
        "--output", type=Path,
        default=package_root / "results" / "08_라벨링패러다임_Research_vs_Community_분석.csv",
    )
    args = parser.parse_args()
    intersection = pd.read_csv(
        args.results_dir / "03_중복주소_데이터셋교집합.csv",
        dtype=str, keep_default_na=False,
    )
    pairs = pd.read_csv(
        args.results_dir / "04_중복주소_데이터셋Pair비교.csv",
        dtype=str, keep_default_na=False,
    )
    rows = []

    add_row(rows, "패러다임 정의", "Research-based", "8 datasets",
            interpretation="논문·벤치마크 구축 과정에서 기존 seed, tag, graph 또는 연구 규칙을 사용한 데이터셋",
            basis="; ".join(sorted(RESEARCH)))
    add_row(rows, "패러다임 정의", "Community-based", "5 datasets",
            interpretation="커뮤니티 신고·사기 registry 또는 이를 직접 계승한 데이터셋",
            basis="; ".join(sorted(COMMUNITY)))
    add_row(rows, "패러다임 정의", "Unclassified", "2 datasets",
            interpretation="분석 목적이 다른 Dune 기반 행위 탐지와 OFAC Status 라벨은 패러다임 비교에서 제외",
            basis="; ".join(sorted(UNCLASSIFIED)))

    pairs["Paradigm A"] = pairs["Dataset A"].map(paradigm)
    pairs["Paradigm B"] = pairs["Dataset B"].map(paradigm)
    pairs["Specific A"] = pairs.apply(lambda row: is_specific_behavior(row, "A"), axis=1)
    pairs["Specific B"] = pairs.apply(lambda row: is_specific_behavior(row, "B"), axis=1)
    comparable = pairs[pairs["Specific A"] & pairs["Specific B"]].copy()
    comparable["Type Conflict"] = comparable.apply(
        lambda row: not bool(
            (components(row["표준 유형 A"]) - BROAD_TYPES)
            & (components(row["표준 유형 B"]) - BROAD_TYPES)
        ), axis=1,
    )

    def relation(row: pd.Series) -> str:
        if row["Paradigm A"] == row["Paradigm B"] == "Research":
            return "Research–Research"
        if row["Paradigm A"] == row["Paradigm B"] == "Community":
            return "Community–Community"
        if {row["Paradigm A"], row["Paradigm B"]} == {"Research", "Community"}:
            return "Cross-paradigm"
        return "Unclassified 포함"

    comparable["패러다임 관계"] = comparable.apply(relation, axis=1)
    classified = comparable[comparable["패러다임 관계"] != "Unclassified 포함"].copy()
    for group, frame in classified.groupby("패러다임 관계", sort=False):
        conflicts = int(frame["Type Conflict"].sum())
        add_row(rows, "패러다임별 충돌률", "구체 Behavior 유형 충돌", group,
                "Pair-Address", len(frame), conflicts, conflicts / len(frame) * 100,
                "서로 다른 패러다임 간 비교에서 충돌률이 가장 높음" if group == "Cross-paradigm"
                else "동일 패러다임 내부 비교 결과",
                "양쪽이 Abnormal·Behavior·구체 유형이며 표준 유형 구성요소의 교집합이 없으면 충돌")

    classified["Source 공유"] = classified["원천 출처 관계"].map(
        lambda value: "공유됨" if value in {"동일", "일부 공유"} else "공유 안 됨"
    )
    for (group, shared), frame in classified.groupby(["패러다임 관계", "Source 공유"], sort=False):
        conflicts = int(frame["Type Conflict"].sum())
        add_row(rows, "Root Source 공유 × 패러다임", "구체 Behavior 유형 충돌",
                f"{group} / {shared}", "Pair-Address", len(frame), conflicts,
                conflicts / len(frame) * 100,
                "Root Source 공유 여부를 함께 고려한 패러다임별 충돌률",
                "동일·일부 공유=공유됨; 서로 다름=공유 안 됨")

    research_counts = []
    for dataset in sorted(RESEARCH):
        abnormal = intersection.loc[intersection[dataset].str.startswith("Abnormal ||"), dataset]
        phishing = int(abnormal.str.contains("Phishing", regex=False).sum())
        research_counts.append((len(abnormal), phishing))
        add_row(rows, "Research 라벨 집중도", dataset, unit="Dataset-Address",
                denominator=len(abnormal), numerator=phishing,
                rate=phishing / len(abnormal) * 100 if len(abnormal) else "",
                interpretation="Abnormal 주소 중 표준 유형에 Phishing이 포함된 비율",
                basis="03 교집합 파일의 Dataset cell 기준")
    total_research = sum(item[0] for item in research_counts)
    total_phishing = sum(item[1] for item in research_counts)
    add_row(rows, "Research 라벨 집중도", "Research 전체", unit="Dataset-Address",
            denominator=total_research, numerator=total_phishing,
            rate=total_phishing / total_research * 100,
            interpretation="Research 진영의 Abnormal 라벨이 Phishing 중심으로 구성됨",
            basis="8개 Research 데이터셋의 Abnormal Dataset-Address 합계")

    cross = classified[classified["패러다임 관계"] == "Cross-paradigm"].copy()

    def orient(row: pd.Series) -> tuple[str, str, str]:
        if row["Paradigm A"] == "Community":
            return row["Dataset A"], row["표준 유형 A"], row["표준 유형 B"]
        return row["Dataset B"], row["표준 유형 B"], row["표준 유형 A"]

    cross[["Community Dataset", "Community Type", "Research Type"]] = cross.apply(
        lambda row: pd.Series(orient(row)), axis=1
    )
    selected_community = {
        "Real-CATS", "EtherScamDB",
        "Cryptocurrency Exchange Scams - Ethereum subset",
    }
    for dataset, frame in cross[cross["Community Dataset"].isin(selected_community)].groupby(
        "Community Dataset", sort=False
    ):
        by_address = frame.groupby("Address").agg(
            conflict=("Type Conflict", "min"),
            community_type=("Community Type", "first"),
        )
        conflict_count = int(by_address["conflict"].sum())
        non_phishing = int(by_address["community_type"].map(
            lambda value: "Phishing" not in components(value)).sum())
        add_row(rows, "Community taxonomy 효과", dataset, unit="Address",
                denominator=len(by_address), numerator=conflict_count,
                rate=conflict_count / len(by_address) * 100,
                interpretation=(f"Phishing 비포함 주소 비율 {non_phishing / len(by_address) * 100:.4f}%. "
                                "충돌률이 Community 측 taxonomy 선택과 밀접함"),
                basis="해당 Community 주소의 모든 Research 비교가 충돌할 때 주소 충돌로 집계")

    conflict_cross = cross[cross["Type Conflict"]].copy()
    exact = ((conflict_cross["Community Type"] == "Scam")
             & (conflict_cross["Research Type"] == "Phishing"))
    composite = ((conflict_cross["Community Type"] == "Scam")
                 & (conflict_cross["Research Type"] == "Hack/Exploit | Phishing"))
    categories = [
        ("Scam ↔ Phishing", int(exact.sum())),
        ("Scam ↔ Hack/Exploit | Phishing", int(composite.sum())),
        ("기타", int((~exact & ~composite).sum())),
    ]
    for label, count in categories:
        add_row(rows, "Cross-paradigm 충돌 구성", label, unit="Pair-Address",
                denominator=len(conflict_cross), numerator=count,
                rate=count / len(conflict_cross) * 100,
                interpretation="복합 표준 유형을 보존한 현재 기준의 충돌 구성",
                basis="Cross-paradigm 구체 Behavior Type Conflict")
    phishing_including = int(((conflict_cross["Community Type"] == "Scam")
        & conflict_cross["Research Type"].map(lambda value: "Phishing" in components(value))).sum())
    add_row(rows, "Cross-paradigm 충돌 구성", "Scam ↔ Phishing 포함 Research 라벨 합계",
            unit="Pair-Address", denominator=len(conflict_cross), numerator=phishing_including,
            rate=phishing_including / len(conflict_cross) * 100,
            interpretation="Cross-paradigm 충돌의 거의 전부가 Scam과 Phishing 포함 라벨 사이에서 발생",
            basis="Phishing 단일형과 Hack/Exploit | Phishing 복합형을 모두 포함")

    output = pd.DataFrame(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(args.output, index=False, encoding="utf-8-sig")
    print(f"wrote {len(output):,} rows to {args.output}")


if __name__ == "__main__":
    main()
