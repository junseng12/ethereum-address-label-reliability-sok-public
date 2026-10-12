from __future__ import annotations

import csv
import itertools
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


ANALYSIS_DIR = Path(__file__).resolve().parent
BASE = ANALYSIS_DIR.parent
NONROOT = BASE / "Non-Root Sources"
ROOT = BASE / "Root Sources"
OLD_ANALYSIS = BASE / "1차_주소라벨_일치_실증분석"

SEMANTICS_OUT = ANALYSIS_DIR / "01_label_semantics_mapping.csv"
OVERLAP_OUT = ANALYSIS_DIR / "02_homogeneous_label_overlap.csv"
ROOT_OUT = ANALYSIS_DIR / "03_label_root_cross_analysis.csv"
REPORT_OUT = ANALYSIS_DIR / "ANALYSIS_REPORT.md"

ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
BEHAVIOR_TYPES = {
    "Phishing",
    "Scam",
    "Hack/Exploit",
    "Illicit/Criminal",
    "Rug Pull",
    "Ponzi",
    "Wash Trading",
    "Other",
}


def normalize_address(value: object) -> str | None:
    text = "" if value is None else str(value).strip().lower()
    return text if ADDRESS_RE.fullmatch(text) and text != "0x" + "0" * 40 else None


def find_old_integrated() -> Path:
    candidates = [
        OLD_ANALYSIS / "전체 주소·라벨 통합표.csv",
        OLD_ANALYSIS / "address_label_integrated.csv",
    ]
    for path in candidates:
        if path.exists():
            return path
    large = sorted(OLD_ANALYSIS.glob("*.csv"), key=lambda p: p.stat().st_size, reverse=True)
    if large and large[0].stat().st_size > 500_000_000:
        return large[0]
    raise FileNotFoundError("기존 전체 주소·라벨 통합표를 찾지 못했습니다.")


OLD_INTEGRATED = find_old_integrated()


@dataclass
class Evidence:
    types: set[str] = field(default_factory=set)
    axes: set[str] = field(default_factory=set)
    originals: set[str] = field(default_factory=set)
    root_families: set[str] = field(default_factory=set)
    root_raw: set[str] = field(default_factory=set)
    root_unknown: bool = False


abnormal_sets: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
evidence: dict[tuple[str, str], Evidence] = defaultdict(Evidence)
address_datasets: dict[str, set[str]] = defaultdict(set)
contract_excluded: Counter[str] = Counter()


def root_families(value: str) -> tuple[set[str], bool]:
    x = (value or "").strip().lower()
    if not x or x in {"확인 불가", "unknown"}:
        return set(), True
    # These local artifacts explicitly say the per-address provenance is mixed
    # or unavailable. Do not infer a root merely from a dataset-level list.
    if "mixed" in x or "supplemental source" in x or "upstream unspecified" in x:
        return set(), True
    families: set[str] = set()
    rules = [
        ("etherscamdb", "EtherScamDB"),
        ("etherscan", "Etherscan"),
        ("chainabuse", "Chainabuse"),
        ("walletexplorer", "WalletExplorer"),
        ("ofac", "OFAC"),
        ("xblock", "XBlock"),
        ("cryptoscamdb", "CryptoScamDB"),
        ("dune", "Dune Analytics"),
        ("crypto exchange scams", "Cryptocurrency Exchange Scams Study"),
    ]
    for needle, family in rules:
        if needle in x:
            families.add(family)
    return families, not bool(families)


def load_known_contracts() -> set[str]:
    contracts: set[str] = set()

    forta = NONROOT / "Forta Labelled Datasets" / "labels" / "1"
    with (forta / "phishing_scams.csv").open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("is_contract", "").strip().lower() == "true":
                address = normalize_address(row.get("address"))
                if address:
                    contracts.add(address)
    with (forta / "malicious_smart_contracts.csv").open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            address = normalize_address(row.get("contract_address"))
            if address:
                contracts.add(address)

    # Real-CATS documents Identifier.tsv as the mapping of token-contract IDs
    # to complete contract addresses. It is therefore a local contract oracle,
    # not a source of focal account labels.
    identifiers = NONROOT / "Real-CATS" / "Identifier.tsv"
    with identifiers.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            address = normalize_address(row.get("Identifier"))
            if address:
                contracts.add(address)

    heist = NONROOT / "EthereumHeist" / "Heist label-etherscan.csv"
    with heist.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            tag = row.get("Name Tag", "").strip().lower()
            # Do not classify "Contract Deployer" as a contract: the deployer
            # may be an EOA. Only explicit focal-contract tags are used.
            if tag.endswith(" - contract") or tag.endswith(" rug contract"):
                address = normalize_address(row.get("Address"))
                if address:
                    contracts.add(address)
    return contracts


KNOWN_CONTRACTS = load_known_contracts()


def classify_existing(dataset: str, original: str, canonical: str) -> tuple[str, str, str]:
    """Return (Reliability Class, Normalized Abnormal Type, Label Axis)."""
    raw = (original or "").strip()
    x = raw.lower()
    canon = (canonical or "").strip().lower()

    if dataset == "OFAC Ethereum Addresses":
        return "Abnormal", "Sanctioned", "Status"
    if canon == "unlabeled" or dataset == "XBlock Ethereum Phishing Transaction Network" and "isp=0" in x:
        return "Uncertain", "확인 불가", "Behavior"
    if canon == "normal_unverified":
        return "Uncertain", "확인 불가", "Behavior"
    if canon == "benign":
        if dataset in {"Real-CATS", "RiskProp"}:
            return "Normal", "해당 없음", "Behavior"
        return "Uncertain", "확인 불가", "Behavior"

    if dataset == "EthereumHeist":
        if x in {"", "???", "？？？", "확인 불가"}:
            return "Uncertain", "확인 불가", "Behavior"
        if any(k in x for k in ("phish", "drainer")):
            return "Abnormal", "Phishing", "Behavior"
        if any(k in x for k in ("rug", "honeypot")):
            return "Abnormal", "Rug Pull", "Behavior"
        return "Abnormal", "Hack/Exploit", "Behavior"

    if canon == "phishing":
        return "Abnormal", "Phishing", "Behavior"
    if canon == "hack_exploit":
        return "Abnormal", "Hack/Exploit", "Behavior"
    if canon == "rug_pull":
        return "Abnormal", "Rug Pull", "Behavior"
    if canon == "ponzi":
        return "Abnormal", "Ponzi", "Behavior"
    if canon == "attack_actor":
        return "Abnormal", "Attack Actor", "Role"

    if canon == "malicious_generic":
        if dataset == "Ethereum Illicit Accounts (Farrugia et al.)":
            return "Abnormal", "Illicit/Criminal", "Behavior"
        if dataset in {"EtherScamDB", "scamsonethereum"}:
            return "Abnormal", "Scam", "Behavior"
        if dataset == "Real-CATS":
            return ("Abnormal", "Scam", "Behavior") if "scam" in x else ("Abnormal", "Other", "Behavior")
        # Forta rows can be clearly malicious while their free-text tag does
        # not support a narrower behavior type.
        return "Abnormal", "Other", "Behavior"

    if canon in {"unknown", "unknown_evidence", "attack_victim"}:
        return "Uncertain", "확인 불가", "Behavior"
    return "Uncertain", "확인 불가", "Behavior"


def add_abnormal(
    dataset: str,
    address: str,
    malicious_type: str,
    axis: str,
    original: str,
    root_source: str,
) -> None:
    address = normalize_address(address)
    if not address:
        return
    if address in KNOWN_CONTRACTS:
        contract_excluded[dataset] += 1
        return
    abnormal_sets[dataset][malicious_type].add(address)
    address_datasets[address].add(dataset)
    ev = evidence[(dataset, address)]
    ev.types.add(malicious_type)
    ev.axes.add(axis)
    if original:
        ev.originals.add(original.strip())
    if root_source:
        ev.root_raw.add(root_source.strip())
    families, unknown = root_families(root_source)
    ev.root_families.update(families)
    ev.root_unknown = ev.root_unknown or unknown


def read_existing_abnormal() -> None:
    with OLD_INTEGRATED.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            reliability, malicious_type, axis = classify_existing(
                row.get("Dataset", ""), row.get("Original Label", ""), row.get("Canonical Label", "")
            )
            if reliability != "Abnormal":
                continue
            add_abnormal(
                row.get("Dataset", ""),
                row.get("Address", ""),
                malicious_type,
                axis,
                row.get("Original Label", ""),
                row.get("Root Source", ""),
            )


def add_new_datasets() -> None:
    da_dir = NONROOT / "DA-HGNN Phishing Detection Dataset" / "Final_data"
    for path in sorted(da_dir.glob("*.csv")):
        add_abnormal(
            "DA-HGNN Phishing Detection Dataset",
            path.stem,
            "Phishing",
            "Behavior",
            "Final_data address-file membership (phishing focal address)",
            "Etherscan phishing labels",
        )

    crypto = NONROOT / "Cryptocurrency Exchange Scams - Ethereum Address Subset" / "Ethereum_주소_부분집합.csv"
    with crypto.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            add_abnormal(
                "Cryptocurrency Exchange Scams - Ethereum subset",
                row.get("Address", ""),
                "Scam",
                "Behavior",
                "scam receiving address (Coin=ETH subset)",
                "Cryptocurrency Exchange Scams Study",
            )

    ex_graph = NONROOT / "EX-Graph - Wash-Trading Address Detection" / "dune_wash_trade_tx.csv"
    with ex_graph.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            for field_name in ("from_addr", "to_addr"):
                add_abnormal(
                    "EX-Graph – Wash-Trading",
                    row.get(field_name, ""),
                    "Wash Trading",
                    "Behavior",
                    f"Dune wash-trading transaction participant ({field_name})",
                    "Dune Analytics wash-trading identification",
                )


def semantics_rows() -> list[dict[str, str]]:
    rows: list[tuple[str, str, str, str, str, str, str, str]] = [
        ("BERT4ETH", "phisher_account.txt membership", "Abnormal", "Phishing", "Behavior", "Etherscan", "명시적 phishing account 목록", "로컬 known-contract 필터 적용"),
        ("BERT4ETH", "normal_eoa", "Uncertain", "확인 불가", "Behavior", "Ethereum EOA random sampling", "검증된 정상 목록이 아닌 무작위 EOA 표본", "Main Analysis 제외"),
        ("EtherScamDB", "category=Phishing", "Abnormal", "Phishing", "Behavior", "EtherScamDB", "원본 category가 Phishing을 명시", "community registry candidate"),
        ("EtherScamDB", "category=Scamming/Scam/Fake ICO", "Abnormal", "Scam", "Behavior", "EtherScamDB", "원본 category가 사기 계열을 명시", "Phishing으로 임의 변환하지 않음"),
        ("Ethereum Illicit Accounts (Farrugia et al.)", "FLAG=1", "Abnormal", "Illicit/Criminal", "Behavior", "EtherScamDB historical snapshot", "논문·README의 illicit account 정의", "구체 공격 유형으로 세분하지 않음"),
        ("Ethereum Illicit Accounts (Farrugia et al.)", "FLAG=0", "Uncertain", "확인 불가", "Behavior", "Ethereum active-account random sample", "무작위 표본이며 정상성 독립 검증 근거 부족", "Main Analysis 제외"),
        ("EthereumHeist", "Name Tag contains Hacker/Exploiter/Stolen", "Abnormal", "Hack/Exploit", "Behavior", "Etherscan", "주소별 heist/name tag가 행위를 명시", "명시적 focal contract 제외"),
        ("EthereumHeist", "Name Tag contains Phish/Drainer", "Abnormal", "Phishing", "Behavior", "Etherscan", "원본 Name Tag가 phishing/drainer를 명시", ""),
        ("EthereumHeist", "Name Tag contains Rug/Honeypot", "Abnormal", "Rug Pull", "Behavior", "Etherscan", "원본 Name Tag가 rug 계열을 명시", ""),
        ("EthereumHeist", "Name Tag 불명", "Uncertain", "확인 불가", "Behavior", "Etherscan", "행위 유형을 확인할 수 없음", "Main Analysis 제외"),
        ("FDGNN Fraud Address Dataset", "Phishing first-order nodes filename", "Abnormal", "Phishing", "Behavior", "Mixed: XBlock/Etherscan", "폴더 class가 focal seed label", "주소별 최종 Root는 확인 불가"),
        ("FDGNN Fraud Address Dataset", "Hack first-order nodes filename", "Abnormal", "Hack/Exploit", "Behavior", "Etherscan", "폴더 class가 focal seed label", "주소별 최종 Root는 확인 불가"),
        ("FDGNN Fraud Address Dataset", "Ponzi first-order nodes filename", "Abnormal", "Ponzi", "Behavior", "선행 Ponzi 데이터셋", "폴더 class가 focal seed label", ""),
        ("FDGNN Fraud Address Dataset", "Normal first-order nodes filename", "Uncertain", "확인 불가", "Behavior", "XBlock", "verified benign이 아닌 normal 표본", "Main Analysis 제외"),
        ("Forta Labelled Datasets", "phishing_scams.csv: is_contract=False", "Abnormal", "Phishing", "Behavior", "Etherscan", "phish-hack address label과 contract 여부가 직접 제공", "is_contract=True 제외"),
        ("Forta Labelled Datasets", "etherscan exploit/heist list", "Abnormal", "Hack/Exploit", "Behavior", "Etherscan", "data_source가 exploit/heist 목록을 명시", "malicious_smart_contracts.csv 제외"),
        ("Forta Labelled Datasets", "명시적 malicious tag이나 세부 유형 불명", "Abnormal", "Other", "Behavior", "Etherscan", "악성 목록 포함은 확인되나 세부 행위 불명", "구체 유형으로 추정하지 않음"),
        ("OFAC Ethereum Addresses", "Digital Currency Address - ETH", "Abnormal", "Sanctioned", "Status", "OFAC", "공식 Enhanced SDN 제재 상태", "분석 1의 행위 유형 overlap 제외"),
        ("Phishing Detection on Ethereum (Trans2Vec)", "phishing-address.txt membership", "Abnormal", "Phishing", "Behavior", "EtherScamDB + Etherscan", "공개 phishing address 목록", ""),
        ("Real-CATS", "CE/Sup-CATS phishing labels", "Abnormal", "Phishing", "Behavior", "Chainabuse 또는 보충출처", "원본 label이 phishing을 명시", "주소별 보충출처 불명은 Root Unknown"),
        ("Real-CATS", "CE Hack/Contract Exploit labels", "Abnormal", "Hack/Exploit", "Behavior", "Chainabuse", "원본 label이 hack/exploit을 명시", ""),
        ("Real-CATS", "CE Rug Pull label", "Abnormal", "Rug Pull", "Behavior", "Chainabuse", "원본 label이 rug pull을 명시", ""),
        ("Real-CATS", "그 밖의 *Scam label", "Abnormal", "Scam", "Behavior", "Chainabuse", "원본 label이 scam을 명시", "Phishing/Hack/Rug Pull과 분리"),
        ("Real-CATS", "CE Other/비정형 criminal label", "Abnormal", "Other", "Behavior", "Chainabuse", "criminal dataset 포함이나 세부 유형 불명", ""),
        ("Real-CATS", "BE/Sup-CATS benign", "Normal", "해당 없음", "Behavior", "Exchange-customer construction", "README가 benign exchange-customer addresses로 명시", "Main Analysis 제외"),
        ("RiskProp", "label=1; description=phish-hack", "Abnormal", "Phishing", "Behavior", "Etherscan", "논문의 phishing-account 이상 정의", ""),
        ("RiskProp", "label=0; known account categories", "Normal", "해당 없음", "Behavior", "Etherscan", "exchange/ICO/converter/mining/gambling의 licit account label", "Main Analysis 제외"),
        ("XBlock Ethereum Phishing Transaction Network", "isp=1", "Abnormal", "Phishing", "Behavior", "Etherscan", "README의 labeled phishing seed", ""),
        ("XBlock Ethereum Phishing Transaction Network", "isp=0", "Uncertain", "확인 불가", "Behavior", "Ethereum 2-hop crawl", "phishing seed가 아닌 graph node", "Benign으로 처리하지 않음"),
        ("scamsonethereum", "blacklist file membership", "Abnormal", "Scam", "Behavior", "Mixed 14 blacklists/prior research", "통합 blacklist 포함", "행별 Root Source는 확인 불가"),
        ("xfraud / PDHG Dataset", "numeric node_id/seed label", "Uncertain", "확인 불가", "Behavior", "XBlock derivative", "공개 Parquet에 실제 0x address mapping 없음", "Address overlap 분석 제외"),
        ("DA-HGNN Phishing Detection Dataset", "Final_data/*.csv filename", "Abnormal", "Phishing", "Behavior", "Etherscan", "각 파일명이 focal phishing address", "numeric enhanced non-phishing 표본은 주소 매핑 없어 제외"),
        ("EX-Graph – Wash-Trading", "dune_wash_trade_tx.csv from/to participant", "Abnormal", "Wash Trading", "Behavior", "Dune Analytics", "공개 wash-trading 거래의 참여 주소", "거래 기반 파생 label; 단독 유형이라 분석 1 pair 없음"),
        ("Forta Protect Web3 Competition", "train/test target", "Uncertain", "확인 불가", "Behavior", "Forta curated", "문서에는 EOA target 정의가 있으나 로컬에 train.csv/test.csv 없음", "거래 shard의 상대 주소에 label을 전파하지 않고 제외"),
        ("Cryptocurrency Exchange Scams - Ethereum subset", "Ethereum_주소_부분집합.csv membership", "Abnormal", "Scam", "Behavior", "Cryptocurrency Exchange Scams Study", "확인된 scam infrastructure의 ETH 수취 주소", "abnormal-only"),
    ]
    fields = ["Dataset", "Original Label / Rule", "Reliability Class", "Normalized Abnormal Type", "Label Axis", "Root Source", "판정 근거", "비고"]
    return [dict(zip(fields, row)) for row in rows]


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def build_overlap() -> list[dict[str, object]]:
    by_type: dict[str, dict[str, set[str]]] = defaultdict(dict)
    for dataset, typed in abnormal_sets.items():
        for malicious_type, addresses in typed.items():
            if malicious_type in BEHAVIOR_TYPES and addresses:
                by_type[malicious_type][dataset] = addresses

    rows: list[dict[str, object]] = []
    for malicious_type in sorted(by_type):
        datasets = sorted(by_type[malicious_type])
        if len(datasets) < 2:
            continue
        for a, b in itertools.combinations(datasets, 2):
            aset, bset = by_type[malicious_type][a], by_type[malicious_type][b]
            common = len(aset & bset)
            union = len(aset | bset)
            a_in = common / len(aset) if aset else 0.0
            b_in = common / len(bset) if bset else 0.0
            jaccard = common / union if union else 0.0
            if common == 0:
                interpretation = "공통 Abnormal 주소 없음"
            elif max(a_in, b_in) >= 0.8 and min(a_in, b_in) <= 0.2:
                interpretation = "포함률 비대칭이 커 한 데이터셋이 다른 데이터셋의 부분집합에 가까움"
            elif common >= 1_000 and jaccard < 0.05:
                interpretation = "공통 수는 크지만 Jaccard가 낮아 규모·coverage 차이의 영향이 큼"
            elif jaccard >= 0.5:
                interpretation = "주소 집합 유사도가 높음"
            else:
                interpretation = "부분 중복; 공통 수와 양방향 포함률을 함께 해석해야 함"
            rows.append({
                "Abnormal Type": malicious_type,
                "Dataset A": a,
                "Dataset B": b,
                "A Abnormal Count": len(aset),
                "B Abnormal Count": len(bset),
                "Common Abnormal Count": common,
                "A→B Inclusion": f"{a_in:.10f}",
                "B→A Inclusion": f"{b_in:.10f}",
                "Jaccard": f"{jaccard:.10f}",
                "핵심 해석": interpretation,
            })
    return rows


def compare_roots(a: Evidence, b: Evidence) -> str:
    if a.root_unknown or b.root_unknown or not a.root_families or not b.root_families:
        return "Root Unknown"
    if a.root_families == b.root_families:
        return "Same Root"
    if a.root_families & b.root_families:
        return "Partially Shared Root"
    return "Different Root"


def compare_labels(a: Evidence, b: Evidence) -> str:
    if "Status" in a.axes or "Status" in b.axes:
        if a.axes != b.axes:
            return "Label Comparison Unavailable"
    if a.types & b.types:
        return "Same / Compatible Label"
    if "Other" in a.types or "Other" in b.types:
        return "Label Comparison Unavailable"
    # Illicit/Criminal is a broad abnormal class. Treat it as compatible with
    # a specific behavior only at the relationship layer; preserve both
    # original labels and normalized types in the output.
    if "Illicit/Criminal" in a.types and b.types & BEHAVIOR_TYPES:
        return "Same / Compatible Label"
    if "Illicit/Criminal" in b.types and a.types & BEHAVIOR_TYPES:
        return "Same / Compatible Label"
    return "Different Label"


def cross_type(a: Evidence, b: Evidence) -> str:
    common = a.types & b.types
    if common:
        return " | ".join(sorted(common))
    if "Status" in a.axes or "Status" in b.axes:
        return "Status × Behavior"
    return f"{'/'.join(sorted(a.types))} ↔ {'/'.join(sorted(b.types))}"


def build_root_cross() -> list[dict[str, object]]:
    buckets: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
    for address, datasets in address_datasets.items():
        if len(datasets) < 2:
            continue
        for dataset_a, dataset_b in itertools.combinations(sorted(datasets), 2):
            a = evidence[(dataset_a, address)]
            b = evidence[(dataset_b, address)]
            root_relation = compare_roots(a, b)
            label_relation = compare_labels(a, b)
            malicious_type = cross_type(a, b)
            key = (malicious_type, dataset_a, dataset_b, root_relation, label_relation)
            bucket = buckets.setdefault(key, {
                "count": 0,
                "addresses": [],
                "orig_a": set(),
                "orig_b": set(),
                "root_a": set(),
                "root_b": set(),
            })
            bucket["count"] += 1
            if len(bucket["addresses"]) < 5:
                bucket["addresses"].append(address)
            bucket["orig_a"].update(a.originals)
            bucket["orig_b"].update(b.originals)
            bucket["root_a"].update(a.root_raw)
            bucket["root_b"].update(b.root_raw)

    rows: list[dict[str, object]] = []
    for key, bucket in sorted(buckets.items(), key=lambda item: (-item[1]["count"], item[0])):
        malicious_type, dataset_a, dataset_b, root_relation, label_relation = key
        if root_relation == "Same Root" and label_relation == "Same / Compatible Label":
            interpretation = "동일 원천 라벨의 반복·재사용 가능성이 큼"
        elif root_relation == "Same Root" and label_relation == "Different Label":
            interpretation = "같은 원천이 taxonomy·구축 과정에서 다르게 변환된 사례"
        elif root_relation == "Different Root" and label_relation == "Same / Compatible Label":
            interpretation = "독립 원천 간 동일 판단이지만 자동 확정 GT는 아님"
        elif root_relation == "Different Root" and label_relation == "Different Label":
            interpretation = "taxonomy·시점·복수 행위·오라벨 가능성을 개별 검토할 사례"
        elif root_relation == "Root Unknown":
            interpretation = "주소별 원천이 불명확해 독립성 판단 보류"
        else:
            interpretation = "일부 원천 공유가 있어 독립·재사용 효과가 혼재"
        rows.append({
            "Abnormal Type": malicious_type,
            "Dataset A": dataset_a,
            "Dataset B": dataset_b,
            "Root Relation": root_relation,
            "Label Relation": label_relation,
            "Address Count": bucket["count"],
            "대표 Address 예시": " | ".join(bucket["addresses"]),
            "Original Label A 예시": " | ".join(sorted(bucket["orig_a"])[:5]),
            "Original Label B 예시": " | ".join(sorted(bucket["orig_b"])[:5]),
            "Root Source A": " | ".join(sorted(bucket["root_a"])[:5]) or "확인 불가",
            "Root Source B": " | ".join(sorted(bucket["root_b"])[:5]) or "확인 불가",
            "핵심 해석": interpretation,
        })
    return rows


def auxiliary_normal_uncertain_overlap() -> dict[tuple[str, str], set[str]]:
    overlaps: dict[tuple[str, str], set[str]] = defaultdict(set)
    with OLD_INTEGRATED.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            reliability, _, _ = classify_existing(
                row.get("Dataset", ""), row.get("Original Label", ""), row.get("Canonical Label", "")
            )
            if reliability not in {"Normal", "Uncertain"}:
                continue
            address = normalize_address(row.get("Address"))
            dataset = row.get("Dataset", "")
            if not address or address in KNOWN_CONTRACTS:
                continue
            if any(other != dataset for other in address_datasets.get(address, set())):
                overlaps[(dataset, reliability)].add(address)
    return overlaps


def abnormal_dataset_summary() -> list[tuple[str, int, str]]:
    rows = []
    for dataset in sorted(abnormal_sets):
        all_addresses = set().union(*abnormal_sets[dataset].values()) if abnormal_sets[dataset] else set()
        types = ", ".join(f"{key} {len(value):,}" for key, value in sorted(abnormal_sets[dataset].items()))
        rows.append((dataset, len(all_addresses), types))
    return rows


def render_report(
    overlap_rows: list[dict[str, object]],
    cross_rows: list[dict[str, object]],
    auxiliary: dict[tuple[str, str], set[str]],
) -> str:
    usable = abnormal_dataset_summary()
    behavior_rows = [r for r in overlap_rows if int(r["Common Abnormal Count"]) > 0]
    max_common = max(behavior_rows, key=lambda r: int(r["Common Abnormal Count"]), default=None)
    max_jaccard = max(behavior_rows, key=lambda r: float(r["Jaccard"]), default=None)
    max_asymmetry = max(
        behavior_rows,
        key=lambda r: abs(float(r["A→B Inclusion"]) - float(r["B→A Inclusion"])),
        default=None,
    )
    size_effect = max(
        (r for r in behavior_rows if float(r["Jaccard"]) < 0.05),
        key=lambda r: int(r["Common Abnormal Count"]),
        default=None,
    )
    per_type_best: list[dict[str, object]] = []
    for malicious_type in sorted({str(r["Abnormal Type"]) for r in behavior_rows}):
        candidates = [r for r in behavior_rows if r["Abnormal Type"] == malicious_type]
        per_type_best.append(max(candidates, key=lambda r: float(r["Jaccard"])))

    cross_counts = Counter()
    for row in cross_rows:
        cross_counts[(str(row["Root Relation"]), str(row["Label Relation"]))] += int(row["Address Count"])

    def pair_text(row: dict[str, object] | None) -> str:
        if not row:
            return "해당 사례 없음"
        return (
            f"{row['Dataset A']} ↔ {row['Dataset B']} "
            f"({row['Abnormal Type']}; 공통 {int(row['Common Abnormal Count']):,}, "
            f"A→B {float(row['A→B Inclusion']):.2%}, B→A {float(row['B→A Inclusion']):.2%}, "
            f"Jaccard {float(row['Jaccard']):.4f})"
        )

    lines = [
        "# Ethereum 주소 라벨 신뢰성 비교 분석",
        "",
        "## 1. 전처리 결과",
        "",
        f"- 후보 17개를 실제 로컬 파일로 재점검했으며, Abnormal 주소를 구성할 수 있는 데이터셋은 {len(usable)}개다.",
        "- xfraud/PDHG는 실제 `0x` 주소 매핑이 없고, Forta Protect는 로컬에 `train.csv`·`test.csv` target 표가 없어 Main Analysis에서 제외했다.",
        "- XBlock `isp=1`만 Phishing Abnormal로 사용했고 `isp=0`은 Uncertain으로 처리했다.",
        "- BERT4ETH·FDGNN의 random/normal 표본과 Farrugia의 random sample은 검증된 정상 자료가 아니므로 Uncertain으로 두고 Abnormal 분석에서 제외했다.",
        "- OFAC `Sanctioned`는 행위 유형이 아닌 Status 축으로 분리하여 분석 1에서는 제외했다.",
        f"- 로컬에서 명시적으로 식별된 contract reference {len(KNOWN_CONTRACTS):,}개를 필터링했다. 이 필터는 체인 전체의 역사적 EOA 판정과 동일하지 않다는 한계가 있다.",
        "",
        "### Abnormal 주소 구성",
        "",
        "| Dataset | Abnormal 고유 주소 | 유형별 구성 |",
        "|---|---:|---|",
    ]
    for dataset, count, types in usable:
        lines.append(f"| {dataset} | {count:,} | {types} |")

    lines += [
        "",
        "## 2. 동일 이상 유형 데이터셋 비교",
        "",
        f"- 공통 Abnormal 주소가 가장 많은 Pair: {pair_text(max_common)}",
        f"- Jaccard가 가장 높은 Pair: {pair_text(max_jaccard)}",
        f"- 포함률 비대칭이 가장 큰 Pair: {pair_text(max_asymmetry)}",
        f"- 공통 수 대비 Jaccard가 낮은 대표 Size Effect: {pair_text(size_effect)}",
        "",
        "### 유형별 가장 유사한 Pair",
        "",
        "| Abnormal Type | Pair | Common | A→B | B→A | Jaccard |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in per_type_best:
        lines.append(
            f"| {row['Abnormal Type']} | {row['Dataset A']} ↔ {row['Dataset B']} | "
            f"{int(row['Common Abnormal Count']):,} | {float(row['A→B Inclusion']):.2%} | "
            f"{float(row['B→A Inclusion']):.2%} | {float(row['Jaccard']):.4f} |"
        )

    lines += [
        "",
        "`공통 주소 수`는 coverage 규모의 영향을 받는다. 따라서 위 결과는 양방향 포함률과 Jaccard를 함께 해석해야 한다.",
        "",
        "## 3. Label × Root Source 분석",
        "",
        "아래 수는 고유 주소 수가 아니라 데이터셋 쌍별 주소 비교인 Pair-Address 수다.",
        "",
        "| Root 관계 | Label 관계 | Pair-Address | 해석 |",
        "|---|---|---:|---|",
    ]
    interpretations = {
        ("Same Root", "Same / Compatible Label"): "같은 원천 라벨의 반복·재사용",
        ("Same Root", "Different Label"): "동일 원천이 taxonomy·구축 과정에서 달라진 사례",
        ("Different Root", "Same / Compatible Label"): "독립 원천 간 같은 판단의 교차검증 후보",
        ("Different Root", "Different Label"): "taxonomy·시점·복수 행위·오라벨 가능성 검토 대상",
    }
    for key in [
        ("Same Root", "Same / Compatible Label"),
        ("Same Root", "Different Label"),
        ("Different Root", "Same / Compatible Label"),
        ("Different Root", "Different Label"),
    ]:
        lines.append(f"| {key[0]} | {key[1]} | {cross_counts[key]:,} | {interpretations[key]} |")
    partial = sum(v for (root, _), v in cross_counts.items() if root == "Partially Shared Root")
    unknown = sum(v for (root, _), v in cross_counts.items() if root == "Root Unknown")
    lines += [
        f"| Partially Shared Root | 전체 Label 관계 | {partial:,} | 일부 원천 공유로 독립·재사용 효과 혼재 |",
        f"| Root Unknown | 전체 Label 관계 | {unknown:,} | 주소별 provenance 부족으로 판단 보류 |",
        "",
    ]
    for root_relation, label_relation in [
        ("Different Root", "Same / Compatible Label"),
        ("Different Root", "Different Label"),
    ]:
        examples = [r for r in cross_rows if r["Root Relation"] == root_relation and r["Label Relation"] == label_relation]
        examples.sort(key=lambda r: int(r["Address Count"]), reverse=True)
        lines.append(f"### {root_relation} + {label_relation} 대표 사례")
        lines.append("")
        if not examples:
            lines.append("- 해당 사례 없음")
        else:
            for row in examples[:3]:
                lines.append(
                    f"- {row['Dataset A']} ↔ {row['Dataset B']}: {int(row['Address Count']):,} Pair-Address, "
                    f"유형 `{row['Abnormal Type']}`, 예시 `{str(row['대표 Address 예시']).split(' | ')[0]}`"
                )
        lines.append("")

    lines += [
        "## 4. 기존 분석과 달라진 점",
        "",
        "- 기존 12개에서 신규 5개까지 17개 후보를 감사했으며, 실제 비교 가능성에 따라 15개만 Abnormal 분석에 사용했다.",
        "- 기존의 `동일+유사` 일치율 대신 동일 이상 유형 overlap과 Label×Root 관계를 분리했다.",
        "- generic scam을 phishing으로 간주하지 않고 Scam, Phishing, Hack/Exploit, Illicit/Criminal 등을 별도로 유지했다.",
        "- XBlock `isp=0`과 random normal을 제거하여 대형 Uncertain 집합이 agreement 수치를 지배하지 않게 했다.",
        "- Sanctioned와 공격 행위가 동시에 존재할 수 있도록 OFAC를 Status 축으로 분리했다.",
        "",
        "### Normal / Uncertain 보조 확인",
        "",
        "다른 데이터셋의 Abnormal와 겹친 주소를 아래처럼 확인했다. 이는 정상 라벨 오류가 아니라 해당 데이터셋의 표본·라벨 시점 차이일 수 있다.",
        "",
        "| Dataset | 기존 분류 | 다른 데이터셋 Abnormal와 겹친 주소 |",
        "|---|---|---:|",
    ]
    for (dataset, reliability), addresses in sorted(auxiliary.items()):
        lines.append(f"| {dataset} | {reliability} | {len(addresses):,} |")

    lines += [
        "",
        "## 5. 핵심 결론",
        "",
        f"- Abnormal-only 분석에서도 가장 큰 절대 중복과 가장 높은 집합 유사도는 같은 현상이 아니었다: 각각 `{pair_text(max_common)}`와 `{pair_text(max_jaccard)}`이다.",
        "- 높은 overlap은 Dataset Count만으로 독립 확인으로 해석할 수 없으며, Same Root·Partially Shared Root를 반드시 분리해야 한다.",
        f"- Different Root + Same/Compatible Label은 {cross_counts[("Different Root", "Same / Compatible Label")]:,} Pair-Address로, 우선 검증 가치가 있는 독립 교차발견 후보다.",
        f"- Different Root + Different Label은 {cross_counts[("Different Root", "Different Label")]:,} Pair-Address이며 자동 오류가 아니라 taxonomy·시점·복수 행위를 검토할 사례다.",
        "- 이번 결과는 로컬 파일에서 확인 가능한 contract를 제외했지만 완전한 역사적 EOA 판정은 아니므로, 최종 Ground Truth 확정 전 블록 시점별 account-code 검증이 필요하다.",
        "",
        "## 재현 정보",
        "",
        f"- 기존 입력: `{OLD_INTEGRATED.relative_to(BASE)}`",
        "- 신규 입력: DA-HGNN `Final_data/*.csv`, EX-Graph `dune_wash_trade_tx.csv`, Cryptocurrency Exchange Scams `Ethereum_주소_부분집합.csv`",
        "- 실행 코드: `run_analysis.py`",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    read_existing_abnormal()
    add_new_datasets()

    semantics = semantics_rows()
    overlap_rows = build_overlap()
    cross_rows = build_root_cross()
    auxiliary = auxiliary_normal_uncertain_overlap()

    write_csv(
        SEMANTICS_OUT,
        semantics,
        ["Dataset", "Original Label / Rule", "Reliability Class", "Normalized Abnormal Type", "Label Axis", "Root Source", "판정 근거", "비고"],
    )
    write_csv(
        OVERLAP_OUT,
        overlap_rows,
        ["Abnormal Type", "Dataset A", "Dataset B", "A Abnormal Count", "B Abnormal Count", "Common Abnormal Count", "A→B Inclusion", "B→A Inclusion", "Jaccard", "핵심 해석"],
    )
    write_csv(
        ROOT_OUT,
        cross_rows,
        ["Abnormal Type", "Dataset A", "Dataset B", "Root Relation", "Label Relation", "Address Count", "대표 Address 예시", "Original Label A 예시", "Original Label B 예시", "Root Source A", "Root Source B", "핵심 해석"],
    )
    REPORT_OUT.write_text(render_report(overlap_rows, cross_rows, auxiliary), encoding="utf-8")


if __name__ == "__main__":
    main()
