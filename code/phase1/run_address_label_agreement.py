from __future__ import annotations

import csv
import datetime as dt
import itertools
import json
import pickletools
import re
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile


csv.field_size_limit(1024 * 1024 * 1024)


ANALYSIS_DIR = Path(__file__).resolve().parent
BASE = ANALYSIS_DIR.parent
ROOT = BASE / "Root Sources"
NONROOT = BASE / "Non-Root Sources"
DB_PATH = ANALYSIS_DIR / "_address_label_working.sqlite"
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
ADDRESS_FIND_RE = re.compile(r"0x[0-9a-fA-F]{40}")
UNKNOWN = "확인 불가"

ALL_DATASETS = [
    "BlockSec Incident Library",
    "EtherScamDB",
    "OFAC Ethereum Addresses",
    "PeckShield Alerts",
    "REKT News",
    "SlowMist Hacked",
    "BCCC-DeFiFraudTrans-2025",
    "BERT4ETH",
    "Blockchain Address Poisoning Companion Dataset",
    "DeFiGuard Dataset",
    "Do Not Rug on Me",
    "Ethereum Illicit Accounts (Farrugia et al.)",
    "Ethereum Ponzi Dataset",
    "EthereumHeist",
    "FDGNN Fraud Address Dataset",
    "Forta Labelled Datasets",
    "Horus Dataset",
    "HOUSTON DeFi Attack Benchmark",
    "Phishing Detection on Ethereum (Trans2Vec)",
    "PTXPhish",
    "Real-CATS",
    "RiskProp",
    "RPHunter (Ethereum-EVM subset)",
    "Rug Pull Dataset (Ethereum subset)",
    "scamsonethereum",
    "TokenScout",
    "Trace2Inv Benchmark",
    "XBlock Ethereum Phishing Transaction Network",
]

# 1차 실증 분석의 범위는 실제 파일에서 주소 자체에 Original Label을
# 직접 부여하는 데이터셋으로 한정한다. 사건/거래/토큰/컨트랙트 라벨을
# 단순히 그 안에 등장하는 주소로 투영하는 데이터셋은 포함하지 않는다.
ADDRESS_LABEL_DATASETS = [
    "EtherScamDB",
    "OFAC Ethereum Addresses",
    "BERT4ETH",
    "Ethereum Illicit Accounts (Farrugia et al.)",
    "EthereumHeist",
    "FDGNN Fraud Address Dataset",
    "Forta Labelled Datasets",
    "Phishing Detection on Ethereum (Trans2Vec)",
    "Real-CATS",
    "RiskProp",
    "scamsonethereum",
    "XBlock Ethereum Phishing Transaction Network",
]


def normalize_address(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text.startswith("0x") and ADDRESS_RE.fullmatch(text):
        return text
    return None


def addresses_in(value: object) -> list[str]:
    if value is None:
        return []
    return sorted({x.lower() for x in ADDRESS_FIND_RE.findall(str(value))})


def safe(value: object, fallback: str = UNKNOWN) -> str:
    text = "" if value is None else str(value).strip()
    return text if text else fallback


def canonical_from_text(text: str, default: str = "unknown") -> str:
    x = text.lower().replace("_", " ").replace("-", " ")
    if any(k in x for k in ("benign", "legitimate", "truthworthy", "trustworthy")):
        return "benign"
    if any(k in x for k in ("normal", "non seed", "isp=0", "unlabeled")):
        return "normal_unverified" if "normal" in x else "unlabeled"
    if any(k in x for k in ("phish", "drainer", "ice phishing", "address poisoning")):
        return "phishing"
    if any(k in x for k in ("rug", "liquidity", "sale restrict", "fee modification", "hidden mint")):
        return "rug_pull"
    if "ponzi" in x or "pyramid" in x:
        return "ponzi"
    if any(k in x for k in ("hack", "heist", "exploit", "reentrancy", "overflow", "attack")):
        return "hack_exploit"
    if "sanction" in x or "ofac" in x:
        return "sanctioned"
    if any(k in x for k in ("scam", "criminal", "illicit", "malicious", "blacklist")):
        return "malicious_generic"
    if "victim" in x or "attacked contract" in x or x in {"interface", "implementation"}:
        return "attack_victim"
    if "attacker" in x:
        return "attack_actor"
    return default


def normalized_label_set(labels: set[str]) -> set[str]:
    return {re.sub(r"\s+", " ", x.strip().lower()) for x in labels}


MALICIOUS_SPECIFIC = {
    "phishing",
    "rug_pull",
    "ponzi",
    "hack_exploit",
    "malicious_generic",
    "attack_actor",
}
NORMALISH = {"benign", "normal_unverified"}
UNKNOWNISH = {"unknown", "unlabeled", "unknown_evidence"}


def compare_labels(raw_a: set[str], canon_a: set[str], raw_b: set[str], canon_b: set[str]) -> str:
    if normalized_label_set(raw_a) == normalized_label_set(raw_b):
        return "동일 라벨"
    if canon_a == canon_b and canon_a:
        return "유사 라벨"
    if canon_a & canon_b:
        return "유사 라벨"
    if canon_a <= NORMALISH and canon_b <= NORMALISH:
        return "유사 라벨"
    if ("malicious_generic" in canon_a and canon_b & MALICIOUS_SPECIFIC) or (
        "malicious_generic" in canon_b and canon_a & MALICIOUS_SPECIFIC
    ):
        return "유사 라벨"
    if canon_a & UNKNOWNISH or canon_b & UNKNOWNISH:
        return "확인 불가"
    return "서로 다른 라벨"


def root_families(values: set[str]) -> set[str]:
    families: set[str] = set()
    for value in values:
        x = value.strip().lower()
        if not x or x == UNKNOWN.lower() or "upstream unspecified" in x or "mixed" in x:
            continue
        found = False
        mappings = [
            ("etherscamdb", "EtherScamDB"),
            ("etherscan", "Etherscan"),
            ("blocksec", "BlockSec"),
            ("peckshield", "PeckShield"),
            ("slowmist", "SlowMist"),
            ("rekt", "REKT"),
            ("chainabuse", "Chainabuse"),
            ("ofac", "OFAC"),
            ("tokenscout", "TokenScout"),
            ("defihacklabs", "DeFiHackLabs"),
            ("cryptoscamdb", "CryptoScamDB"),
            ("wallet explorer", "WalletExplorer"),
        ]
        for needle, family in mappings:
            if needle in x:
                families.add(family)
                found = True
        if not found:
            families.add(re.sub(r"\s+", " ", x))
    return families


def compare_roots(roots_a: set[str], roots_b: set[str]) -> str:
    fa = root_families(roots_a)
    fb = root_families(roots_b)
    if fa and fb and fa & fb:
        return "동일 Root Source 포함"
    if not fa or not fb:
        return "확인 불가/혼합 Source"
    return "독립 Source"


class Store:
    def __init__(self, path: Path):
        if path.exists():
            path.unlink()
        self.con = sqlite3.connect(path)
        self.con.executescript(
            """
            PRAGMA journal_mode=MEMORY;
            PRAGMA synchronous=OFF;
            PRAGMA temp_store=MEMORY;
            CREATE TABLE labels (
                address TEXT NOT NULL,
                dataset TEXT NOT NULL,
                original_label TEXT NOT NULL,
                canonical_label TEXT NOT NULL,
                root_source TEXT NOT NULL,
                label_date TEXT NOT NULL,
                source_file TEXT NOT NULL,
                evidence_field TEXT NOT NULL,
                evidence_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(address,dataset,original_label,root_source,label_date,source_file,evidence_field)
            ) WITHOUT ROWID;
            """
        )
        self.pending: list[tuple[str, ... | int]] = []
        self.candidate = Counter()
        self.invalid = Counter()

    def add(
        self,
        address: object,
        dataset: str,
        original_label: object,
        canonical_label: str,
        root_source: object,
        label_date: object,
        source_file: str,
        evidence_field: str,
        count: int = 1,
    ) -> None:
        self.candidate[dataset] += count
        normalized = normalize_address(address)
        if normalized is None:
            self.invalid[dataset] += count
            return
        row = (
            normalized,
            dataset,
            safe(original_label),
            canonical_label,
            safe(root_source),
            safe(label_date),
            source_file,
            evidence_field,
            count,
        )
        self.pending.append(row)
        if len(self.pending) >= 20_000:
            self.flush()

    def flush(self) -> None:
        if not self.pending:
            return
        self.con.executemany(
            """
            INSERT INTO labels(address,dataset,original_label,canonical_label,root_source,label_date,source_file,evidence_field,evidence_count)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(address,dataset,original_label,root_source,label_date,source_file,evidence_field)
            DO UPDATE SET evidence_count=evidence_count+excluded.evidence_count
            """,
            self.pending,
        )
        self.pending.clear()

    def finish(self) -> None:
        self.flush()
        self.con.commit()
        self.con.execute("CREATE INDEX idx_labels_address_dataset ON labels(address,dataset)")
        self.con.execute("CREATE INDEX idx_labels_dataset_address ON labels(dataset,address)")
        self.con.commit()


MANIFEST: dict[str, dict[str, str]] = {
    name: {"status": "대기", "source_files": "", "extraction_rule": "", "caveat": ""}
    for name in ALL_DATASETS
}


def manifest(dataset: str, status: str, files: str, rule: str, caveat: str = "") -> None:
    MANIFEST[dataset] = {
        "status": status,
        "source_files": files,
        "extraction_rule": rule,
        "caveat": caveat,
    }


def read_csv_rows(path: Path, delimiter: str = ","):
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        yield from csv.DictReader(handle, delimiter=delimiter)


def extract_root_sources(store: Store) -> None:
    dataset = "EtherScamDB"
    path = ROOT / dataset / "etherscamdb_eth_address_occurrences.csv"
    for row in read_csv_rows(path):
        original = safe(row.get("category"), safe(row.get("label")))
        store.add(
            row.get("eth_address_normalized") or row.get("eth_address"), dataset, original,
            canonical_from_text(original, "malicious_generic"), "EtherScamDB Community Registry", UNKNOWN,
            path.name, "eth_address"
        )
    manifest(dataset, "포함", path.name, "eth_address와 원본 category 추출", "커뮤니티 registry candidate이며 확정 GT가 아님")

    dataset = "OFAC Ethereum Addresses"
    # The research-facing dataset name is retained, while the directory on
    # disk uses the normalized Root Source name.
    path = ROOT / "OFAC" / "ofac_sanctioned_eth.csv"
    for row in read_csv_rows(path):
        store.add(
            row.get("address_normalized") or row.get("address"), dataset, row.get("label"), "sanctioned",
            "OFAC Enhanced SDN", row.get("data_as_of"), path.name, "Digital Currency Address - ETH"
        )
    manifest(dataset, "포함", path.name, "Digital Currency Address - ETH로 이미 필터된 address와 label 추출")


def extract_bccc(store: Store) -> None:
    dataset = "BCCC-DeFiFraudTrans-2025"
    folder = NONROOT / dataset / "CSVs" / "Extracted" / "CSVs"
    for kind, filename in [("fraud", "DeFiTransLyzer_fraud.csv"), ("legitimate", "DeFiTransLyzer_legitimate.csv")]:
        path = folder / filename
        for row in read_csv_rows(path):
            flag = safe(row.get("flag"))
            canonical = "malicious_generic" if flag == "1" else "normal_unverified"
            store.add(row.get("address"), dataset, flag, canonical, "Etherscan tag/known-status", UNKNOWN, filename, "address")
    manifest(dataset, "포함", "DeFiTransLyzer_fraud.csv; DeFiTransLyzer_legitimate.csv", "focal address와 원본 flag(1/0) 추출", "flag=0은 verified benign이 아님")


def extract_bert4eth(store: Store) -> None:
    dataset = "BERT4ETH"
    data = NONROOT / dataset / "Data"
    positive = data / "phisher_account.txt"
    with positive.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            store.add(line.strip(), dataset, "phisher_account", "phishing", "Etherscan phish-hack", UNKNOWN, positive.name, "account")
    normal_zip = data / "normal_trans.zip"
    with ZipFile(normal_zip) as archive:
        for info in archive.infolist():
            name = info.filename.lower()
            if info.is_dir() or not name.endswith(".csv") or "__macosx" in name:
                continue
            target_index = 6 if "_in_" in name else 5 if "_out_" in name else None
            if target_index is None:
                continue
            with archive.open(info) as raw:
                import io
                reader = csv.reader(io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline=""))
                for row in reader:
                    if len(row) > target_index:
                        store.add(row[target_index], dataset, "normal_eoa", "normal_unverified", "Ethereum random EOA sampling", UNKNOWN, normal_zip.name, info.filename)
    manifest(dataset, "포함", "phisher_account.txt; normal_trans.zip", "positive account list와 normal 거래파일의 방향별 focal EOA 추출", "normal EOA는 검증된 benign이 아님; counterparties는 제외")


def copy_rug_dataset(store: Store, dataset: str, folder_name: str) -> None:
    path = NONROOT / folder_name / "rugpull_full_dataset_new.csv"
    for row in read_csv_rows(path):
        if safe(row.get("Chain"), "").upper() != "ETH":
            continue
        original = safe(row.get("Type"), "rug-pull dataset membership")
        store.add(row.get("address"), dataset, original, "rug_pull", safe(row.get("Sources"), "SoK mixed sources"), UNKNOWN, path.name, "address")
    manifest(dataset, "포함", path.name, "Chain=ETH인 address와 원본 Type 추출", "두 폴더의 CSV가 동일하여 독립 GT가 아님")


def extract_farrugia(store: Store) -> None:
    dataset = "Ethereum Illicit Accounts (Farrugia et al.)"
    path = NONROOT / dataset / "Account_Stats" / "Complete.csv"
    for row in read_csv_rows(path):
        flag = safe(row.get("FLAG"))
        canonical = "malicious_generic" if flag == "1" else "normal_unverified"
        store.add(row.get("Address"), dataset, flag, canonical, "EtherScamDB historical snapshot" if flag == "1" else "Ethereum active-account random sample", "2019-04-17" if flag == "1" else UNKNOWN, path.name, "Address")
    manifest(dataset, "포함", path.name, "Address와 원본 FLAG(1/0) 추출", "FLAG=0 random sample에는 hidden illicit이 포함될 수 있음")


def extract_ponzi(store: Store) -> None:
    dataset = "Ethereum Ponzi Dataset"
    path = NONROOT / dataset / "ponzi-addresses.csv"
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if row:
                store.add(row[0], dataset, "ponzi-addresses.csv membership", "ponzi", "Etherscan verified source/manual review", UNKNOWN, path.name, row[1] if len(row) > 1 else "contract name")
    manifest(dataset, "포함", path.name, "무헤더 CSV 첫 열 contract address를 positive membership으로 추출", "둘째 열은 label이 아니라 contract/project name")


def extract_heist(store: Store) -> None:
    dataset = "EthereumHeist"
    path = NONROOT / dataset / "Heist label-etherscan.csv"
    for row in read_csv_rows(path):
        store.add(row.get("Address"), dataset, row.get("Name Tag"), "hack_exploit", "Etherscan heist/name-tag", UNKNOWN, path.name, "Address")
    manifest(dataset, "포함", path.name, "Address와 원본 Etherscan Name Tag 추출", "현재 파일에는 raw transaction flow가 없음")


def extract_fdgnn(store: Store) -> None:
    dataset = "FDGNN Fraud Address Dataset"
    root = NONROOT / dataset
    classes = {
        "Hack first-order nodes": "hack_exploit",
        "Normal first-order nodes": "normal_unverified",
        "Phishing first-order nodes": "phishing",
        "Ponzi first-order nodes": "ponzi",
        "Scam first-order nodes": "malicious_generic",
    }
    for folder, canonical in classes.items():
        for path in (root / folder).glob("*.csv"):
            store.add(path.stem, dataset, folder, canonical, "Mixed: XBlock/Etherscan/CryptoScamDB/prior Ponzi", UNKNOWN, f"{folder}/*.csv", "filename seed address")
    manifest(dataset, "포함", "; ".join(f"{x}/*.csv" for x in classes), "주소별 CSV 파일명 seed와 디렉터리 class 추출", "통합·파생 데이터로 source 중복과 leakage 가능")


def extract_forta(store: Store) -> None:
    dataset = "Forta Labelled Datasets"
    folder = NONROOT / dataset / "labels" / "1"
    path = folder / "etherscan_malicious_labels.csv"
    for row in read_csv_rows(path):
        original = safe(row.get("wallet_tag"))
        store.add(row.get("banned_address"), dataset, original, canonical_from_text(original, "malicious_generic"), row.get("data_source") or "Etherscan", UNKNOWN, str(path.relative_to(NONROOT / dataset)), "banned_address")
    path = folder / "phishing_scams.csv"
    for row in read_csv_rows(path):
        original = safe(row.get("etherscan_labels"), safe(row.get("etherscan_tag")))
        store.add(row.get("address"), dataset, original, "phishing", "Etherscan", UNKNOWN, str(path.relative_to(NONROOT / dataset)), "address")
    manifest(
        dataset,
        "포함",
        "labels/1/etherscan_malicious_labels.csv; labels/1/phishing_scams.csv",
        "banned_address/address 필드에 직접 붙은 원본 Etherscan 라벨만 추출",
        "malicious_smart_contracts.csv는 분석 단위가 Smart Contract이므로 제외; creator address와 Optimism chainId=10도 제외",
    )


def extract_horus(store: Store) -> None:
    dataset = "Horus Dataset"
    path = NONROOT / dataset / "horus" / "tracer" / "ethereum" / "data" / "labeled_accounts.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for address, value in data.items():
        labels = value.get("labels") or [value.get("category") or UNKNOWN]
        for label in labels:
            store.add(address, dataset, label, canonical_from_text(str(label), "unknown"), "Horus auxiliary labeled_accounts (upstream unspecified)", UNKNOWN, str(path.relative_to(NONROOT / dataset)), "JSON key")
    manifest(dataset, "포함", str(path.relative_to(NONROOT / dataset)), "labeled_accounts.json의 address key와 labels 배열 추출", "Horus 공격 규칙 결과의 Tx를 주소 라벨로 투영하지 않음")


def extract_houston(store: Store) -> None:
    dataset = "HOUSTON DeFi Attack Benchmark"
    pdf = NONROOT / dataset / "dataset" / "defi-incidents-dataset.pdf"
    text = subprocess.check_output(["pdftotext", "-layout", str(pdf), "-"], text=True, encoding="utf-8", errors="replace")
    pattern = re.compile(r"^\s*(\d+)\s+(?:url|-)\s+(.+?)\s+(0x[0-9a-fA-F]{40})\s+(\d+)\s+(0x[0-9a-fA-F]{64})\s*$")
    parsed = 0
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        parsed += 1
        incident_no, company, address, block, txhash = match.groups()
        store.add(address, dataset, "Smart Contract Address (attacked)", "attack_victim", "Incident report/postmortem", UNKNOWN, str(pdf.relative_to(NONROOT / dataset)), f"incident={incident_no};company={company.strip()};block={block};tx={txhash}")
    status = "포함" if parsed else "추출 실패"
    manifest(dataset, status, str(pdf.relative_to(NONROOT / dataset)), f"PDF의 Smart Contract Address (attacked) 열 추출; parsed={parsed}", "defi-incidents.csv는 Polynetwork 1건 예시이므로 전체 115건 PDF를 기준으로 함")


def extract_trans2vec(store: Store) -> None:
    dataset = "Phishing Detection on Ethereum (Trans2Vec)"
    path = NONROOT / dataset / "phishing accounts.zip"
    with ZipFile(path) as archive:
        member = next(x for x in archive.infolist() if x.filename.endswith("phishing-address.txt"))
        with archive.open(member) as raw:
            import io
            for line in io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace"):
                store.add(line.strip(), dataset, "phishing-address", "phishing", "EtherScamDB|Etherscan", "before 2019-01-03", path.name, member.filename)
    manifest(dataset, "포함", "phishing accounts.zip/phishing-address.txt", "공개 positive address 목록 추출", "random/unlabeled normal 주소의 별도 명시 목록은 현재 파일에서 확인되지 않음")


XLSX_NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}


def xlsx_colnum(ref: str) -> int:
    letters = "".join(x for x in ref if x.isalpha())
    result = 0
    for char in letters:
        result = result * 26 + ord(char.upper()) - 64
    return result - 1


def read_xlsx(path: Path) -> dict[str, list[list[str]]]:
    result: dict[str, list[list[str]]] = {}
    with ZipFile(path) as archive:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            for item in root.findall("m:si", XLSX_NS):
                shared.append("".join(x.text or "" for x in item.iter("{%s}t" % XLSX_NS["m"])))
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        targets = {x.attrib["Id"]: x.attrib["Target"] for x in relationships}
        for sheet in workbook.find("m:sheets", XLSX_NS):
            name = sheet.attrib["name"]
            rid = sheet.attrib["{%s}id" % XLSX_NS["r"]]
            target = targets[rid].lstrip("/")
            if not target.startswith("xl/"):
                target = "xl/" + target
            root = ET.fromstring(archive.read(target))
            rows: list[list[str]] = []
            for row_node in root.findall(".//m:sheetData/m:row", XLSX_NS):
                row: list[str] = []
                for cell in row_node.findall("m:c", XLSX_NS):
                    index = xlsx_colnum(cell.attrib.get("r", "A1"))
                    while len(row) <= index:
                        row.append("")
                    kind = cell.attrib.get("t")
                    value_node = cell.find("m:v", XLSX_NS)
                    inline = cell.find("m:is", XLSX_NS)
                    if kind == "s" and value_node is not None:
                        value = shared[int(value_node.text)]
                    elif kind == "inlineStr" and inline is not None:
                        value = "".join(x.text or "" for x in inline.iter("{%s}t" % XLSX_NS["m"]))
                    else:
                        value = value_node.text if value_node is not None else ""
                    row[index] = value
                rows.append(row)
            result[name] = rows
    return result


def extract_ptxphish(store: Store) -> None:
    dataset = "PTXPhish"
    path = NONROOT / dataset / "dataset" / "InitialAddress.xlsx"
    rows = read_xlsx(path)["Sheet1"]
    headers = rows[0]
    for col in range(0, len(headers), 4):
        label = safe(headers[col], "")
        if not label:
            continue
        for row in rows[1:]:
            if col < len(row) and row[col]:
                store.add(row[col], dataset, label, "phishing", "PTXPhish initial-address category (upstream not in file)", UNKNOWN, str(path.relative_to(NONROOT / dataset)), f"column={label}")
    manifest(dataset, "포함", str(path.relative_to(NONROOT / dataset)), "InitialAddress.xlsx의 공격 기법별 address 열 추출", "PTXPHISH.xlsx의 Benign KOL/Developer 값은 TxHash이므로 Address 분석에서 제외")


def extract_real_cats(store: Store) -> None:
    dataset = "Real-CATS"
    folder = NONROOT / dataset
    for filename in ["CE.tsv", "BE.tsv", "Sup-CATS.tsv"]:
        path = folder / filename
        for row in read_csv_rows(path, "\t"):
            label = safe(row.get("label"))
            canonical = canonical_from_text(label, "malicious_generic" if filename == "CE.tsv" else "unknown")
            if filename == "BE.tsv":
                root = "WalletExplorer|Etherscan exchange labels"
                label_date = "2024-05-30 dataset label cutoff"
            elif filename == "CE.tsv":
                root = "Chainabuse"
                label_date = "2024-05-30 dataset label cutoff"
            else:
                root = "Real-CATS supplemental source"
                label_date = UNKNOWN
            store.add(row.get("address"), dataset, label, canonical, root, label_date, filename, "address")
    manifest(dataset, "포함", "CE.tsv; BE.tsv; Sup-CATS.tsv", "Ethereum 및 supplemental address와 원본 label 추출; Bitcoin BB/CB 제외", "benign은 exchange next-hop 구성이고 실제 file 관찰 범위가 README cutoff보다 김")


def extract_riskprop(store: Store) -> None:
    dataset = "RiskProp"
    path = NONROOT / dataset / "data" / "803_Account_Labels.csv"
    for row in read_csv_rows(path):
        raw = safe(row.get("discription"), safe(row.get("label")))
        canonical = "phishing" if safe(row.get("label")) == "1" else "benign"
        store.add(row.get("Address"), dataset, raw, canonical, "Etherscan labels", "2019-12-01~2019-12-31", str(path.relative_to(NONROOT / dataset)), "Address")
    manifest(dataset, "포함", str(path.relative_to(NONROOT / dataset)), "803개 명시 label account만 추출; risk score와 나머지 graph node 제외", "label=0은 known non-phishing category이지 전체 graph 정상 라벨이 아님")


def extract_rphunter(store: Store) -> None:
    dataset = "RPHunter (Ethereum-EVM subset)"
    folder = NONROOT / dataset / "Data" / "Dataset"
    for archive_name, original, canonical, root in [
        ("Rug-Bytecode.zip", "Rug-Bytecode", "rug_pull", "Security vendors/expert verification"),
        ("Normal-Bytecode.zip", "Normal-Bytecode", "benign", "TokenScout"),
    ]:
        path = folder / archive_name
        with ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                store.add(Path(info.filename).stem, dataset, original, canonical, root, UNKNOWN, f"Data/Dataset/{archive_name}", "bytecode filename")
    xlsx = NONROOT / dataset / "Data" / "Rug-Pull-Incidents.xlsx"
    total = read_xlsx(xlsx).get("Total", [])
    if total:
        headers = total[0]
        for values in total[1:]:
            row = {headers[i]: values[i] if i < len(values) else "" for i in range(len(headers))}
            if safe(row.get("Chain"), "").upper() != "ETH":
                continue
            risks = [safe(row.get(k), "") for k in ("Sale Restrict", "Variable Manipulation", "Balance Tamper")]
            risks = [x for x in risks if x]
            if not risks:
                risks = ["Rug-Pull-Incidents.xlsx membership"]
            for risk in risks:
                store.add(row.get("Address"), dataset, risk, "rug_pull", row.get("Source") or "Security vendors", "before 2024-05", str(xlsx.relative_to(NONROOT / dataset)), "Address")
    manifest(dataset, "포함", "Data/Dataset/Rug-Bytecode.zip; Normal-Bytecode.zip; Data/Rug-Pull-Incidents.xlsx", "bytecode 파일명 address와 ETH incident Address/원본 risk 유형 추출", "Normal은 TokenScout 의존; XLSX의 비ETH chain 제외")


def extract_scamsonethereum(store: Store) -> None:
    dataset = "scamsonethereum"
    folder = NONROOT / dataset
    for filename in ["master_blacklist_set.txt", "all_across_hard.txt"]:
        path = folder / filename
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                for address in addresses_in(line):
                    store.add(address, dataset, path.stem, "malicious_generic", "Mixed 14 blacklists/prior research/Etherscan", UNKNOWN, filename, "line membership")
    manifest(dataset, "포함", "master_blacklist_set.txt; all_across_hard.txt", "각 행에서 42자리 Ethereum address 추출; 원본 파일명을 label로 보존", "행별 원천·category·snapshot이 없음")


def extract_tokenscout(store: Store) -> None:
    dataset = "TokenScout"
    folder = NONROOT / dataset
    token_to_id = json.loads((folder / "token-dict.json").read_text(encoding="utf-8"))
    id_to_token = {str(value): key for key, value in token_to_id.items()}
    path = folder / "token_labels_processed.csv"
    for row in read_csv_rows(path):
        token_id = safe(row.get("token_address"), "")
        raw1 = safe(row.get("t1-labels"))
        raw2 = safe(row.get("t2-labels"))
        original = f"t1-labels={raw1};t2-labels={raw2}"
        canonical = canonical_from_text(raw2, canonical_from_text(raw1, "unknown"))
        store.add(id_to_token.get(token_id), dataset, original, canonical, "Web3 auditor consensus", "2023-02 dataset cutoff", path.name, f"token_address_id={token_id}")
    manifest(dataset, "포함", "token_labels_processed.csv; token-dict.json", "numeric token ID를 token-dict의 실제 contract address로 복원하고 원본 t1/t2 label 보존", "truthworthy 오탈자는 Original Label에서 수정하지 않음")


def extract_trace2inv(store: Store) -> None:
    dataset = "Trace2Inv Benchmark"
    folder = NONROOT / dataset / "benchmarks"
    for path in folder.glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        root = value.get("category") or "Mixed incident reports"
        store.add(value.get("interface"), dataset, "interface", "attack_victim", root, UNKNOWN, f"benchmarks/{path.name}", "interface")
        store.add(value.get("implementation"), dataset, "implementation", "attack_victim", root, UNKNOWN, f"benchmarks/{path.name}", "implementation")
    manifest(dataset, "포함", "benchmarks/*.json", "interface와 implementation victim contract address를 원본 역할별 추출", "training/testing TxHash는 Address 분석에서 제외")


def extract_xblock(store: Store) -> None:
    dataset = "XBlock Ethereum Phishing Transaction Network"
    path = NONROOT / dataset / "Ethereum Phishing Transaction Network" / "MulDiGraph.pkl"
    expected = 2_973_489
    started = False
    current_address: str | None = None
    extracted = 0
    with path.open("rb") as handle:
        for opcode, argument, _ in pickletools.genops(handle):
            if not started:
                if opcode.name in {"BINUNICODE", "SHORT_BINUNICODE", "UNICODE"} and argument == "_node":
                    started = True
                continue
            if opcode.name in {"BINUNICODE", "SHORT_BINUNICODE", "UNICODE"} and isinstance(argument, str):
                candidate = normalize_address(argument)
                if candidate:
                    current_address = candidate
                    continue
            if current_address and opcode.name in {"BININT1", "BININT2", "BININT"} and argument in (0, 1):
                raw = f"isp={argument}"
                canonical = "phishing" if argument == 1 else "unlabeled"
                root = "Etherscan phish-hack" if argument == 1 else "Etherscan 2-hop crawl (non-seed unlabeled)"
                store.add(current_address, dataset, raw, canonical, root, UNKNOWN, "MulDiGraph.pkl", "node attribute isp")
                extracted += 1
                current_address = None
                if extracted % 250_000 == 0:
                    store.flush()
                    print(f"  XBlock nodes: {extracted:,}", flush=True)
                if extracted == expected:
                    break
    status = "포함" if extracted == expected else "부분 추출"
    manifest(dataset, status, "MulDiGraph.pkl", f"pickle opcode를 비실행 방식으로 읽어 _node address와 원본 isp 값을 추출; extracted={extracted}", "isp=0은 정상 주소가 아니라 non-seed unlabeled node")


def extract_all(store: Store) -> None:
    tasks = [
        ("Address Root Sources", lambda: extract_root_sources(store)),
        ("BERT4ETH", lambda: extract_bert4eth(store)),
        ("Farrugia", lambda: extract_farrugia(store)),
        ("EthereumHeist", lambda: extract_heist(store)),
        ("FDGNN", lambda: extract_fdgnn(store)),
        ("Forta", lambda: extract_forta(store)),
        ("Trans2Vec", lambda: extract_trans2vec(store)),
        ("Real-CATS", lambda: extract_real_cats(store)),
        ("RiskProp", lambda: extract_riskprop(store)),
        ("scamsonethereum", lambda: extract_scamsonethereum(store)),
        ("XBlock", lambda: extract_xblock(store)),
    ]
    exclusions = {
        "BlockSec Incident Library": ("blocksec_incident_transactions.csv", "Incident/Transaction 라벨 및 attacker/victim 역할을 주소 라벨로 투영하지 않음"),
        "PeckShield Alerts": ("peckshield_alert_references.csv", "Alert/Incident Reference 단위이며 직접 주소 라벨이 없음"),
        "REKT News": ("rekt_incidents.csv", "Incident 단위이며 observed address의 역할·라벨이 확정되지 않음"),
        "SlowMist Hacked": ("slowmist_incidents.csv", "Incident 단위이며 observed address의 역할·라벨이 확정되지 않음"),
        "BCCC-DeFiFraudTrans-2025": ("DeFiTransLyzer_fraud.csv; DeFiTransLyzer_legitimate.csv", "Transaction의 fraud/legitimate 라벨을 focal address에 상속하지 않음"),
        "Blockchain Address Poisoning Companion Dataset": ("payoff_transfers_ethereum.csv; address_poisoning_ethereum.sql.gz", "Transfer/Incident 라벨을 sender·recipient 주소 라벨로 투영하지 않음"),
        "DeFiGuard Dataset": ("dataset/selected_malicious/*.json; selected_benign/*.json", "Transaction cash-flow graph 라벨을 graph node 주소에 투영하지 않음"),
        "Do Not Rug on Me": ("rugpull_full_dataset_new.csv", "분석 단위가 Rug-Pull Incident/Token Contract임"),
        "Ethereum Ponzi Dataset": ("ponzi-addresses.csv", "분석 단위가 Smart Contract임"),
        "Horus Dataset": ("horus/tracer/ethereum/data/*", "주 분석 단위가 Transaction/EVM execution finding임; 보조 labeled_accounts도 제외"),
        "HOUSTON DeFi Attack Benchmark": ("dataset/defi-incidents-dataset.pdf", "분석 단위가 Incident/First Attack Transaction/Victim Contract임"),
        "PTXPhish": ("dataset/PTXPHISH.xlsx; dataset/InitialAddress.xlsx", "원본 라벨 단위가 Transaction이며 InitialAddress는 후보 거래 탐색용 seed임"),
        "RPHunter (Ethereum-EVM subset)": ("Data/Dataset/*; Data/Rug-Pull-Incidents.xlsx", "분석 단위가 Token/Smart Contract/Rug-Pull Incident임"),
        "Rug Pull Dataset (Ethereum subset)": ("rugpull_full_dataset_new.csv", "분석 단위가 Rug-Pull Incident/Token Contract임"),
        "TokenScout": ("token_labels_processed.csv; token-dict.json", "분석 단위가 ERC-20 Token/Contract임"),
        "Trace2Inv Benchmark": ("benchmarks/*.json", "분석 단위가 Victim Contract/Exploit Transaction/Transaction History임"),
    }
    for dataset, (files, reason) in exclusions.items():
        manifest(dataset, "주소 기반 분석 대상 아님", files, reason, "파일에 0x 주소가 있어도 주소 자체의 Original Label로 해석하지 않음")
    for name, task in tasks:
        print(f"[extract] {name}", flush=True)
        task()
        store.flush()

    extracted_scope = {dataset for dataset, info in MANIFEST.items() if info["status"] == "포함"}
    if extracted_scope != set(ADDRESS_LABEL_DATASETS):
        raise RuntimeError(
            f"주소 데이터셋 범위 불일치: expected={sorted(ADDRESS_LABEL_DATASETS)}, actual={sorted(extracted_scope)}"
        )


def write_csv(path: Path, header: list[str], rows) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def build_outputs(store: Store) -> dict[str, object]:
    con = store.con
    print("[output] integrated table", flush=True)
    integrated_path = ANALYSIS_DIR / "전체 주소·라벨 통합표.csv"
    with integrated_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Address", "Dataset", "Original Label", "Canonical Label", "Root Source", "Label Date", "Source Files", "Evidence Fields", "Evidence Count"])
        for row in con.execute(
            """
            SELECT address,dataset,original_label,canonical_label,root_source,label_date,
                   GROUP_CONCAT(DISTINCT source_file),GROUP_CONCAT(DISTINCT evidence_field),SUM(evidence_count)
            FROM labels
            GROUP BY address,dataset,original_label,canonical_label,root_source,label_date
            ORDER BY address,dataset,original_label
            """
        ):
            writer.writerow(row)

    dataset_sizes = {
        row[0]: row[1]
        for row in con.execute("SELECT dataset,COUNT(DISTINCT address) FROM labels GROUP BY dataset")
    }
    datasets = sorted(dataset_sizes)
    dataset_label_rows = {
        row[0]: row[1]
        for row in con.execute(
            """
            SELECT dataset,COUNT(*) FROM (
                SELECT address,dataset,original_label,canonical_label,root_source,label_date
                FROM labels
                GROUP BY address,dataset,original_label,canonical_label,root_source,label_date
            ) GROUP BY dataset
            """
        )
    }
    global_unique = con.execute("SELECT COUNT(DISTINCT address) FROM labels").fetchone()[0]
    membership_count = con.execute("SELECT COUNT(*) FROM (SELECT DISTINCT address,dataset FROM labels)").fetchone()[0]
    integrated_rows = sum(dataset_label_rows.values())

    print("[output] overlap and comparison tables", flush=True)
    pair_intersection = Counter()
    pair_comparison = defaultdict(Counter)
    pair_root = defaultdict(Counter)
    pair_joint = defaultdict(Counter)
    dataset_shared = Counter()
    dataset_comparison = defaultdict(Counter)
    dataset_root = defaultdict(Counter)
    comparison_totals = Counter()
    root_totals = Counter()
    joint_totals = Counter()
    shared_global = 0

    comparison_path = ANALYSIS_DIR / "주소별 데이터셋 쌍 라벨 비교표.csv"
    conflict_path = ANALYSIS_DIR / "라벨 충돌 판정 집계.csv"
    wide_path = ANALYSIS_DIR / "중복 주소.csv"
    with comparison_path.open("w", encoding="utf-8-sig", newline="") as comp_handle, conflict_path.open("w", encoding="utf-8-sig", newline="") as conflict_handle, wide_path.open("w", encoding="utf-8-sig", newline="") as wide_handle:
        comp_writer = csv.writer(comp_handle)
        conflict_writer = csv.writer(conflict_handle)
        comparison_header = [
            "Address", "Dataset A", "Original Labels A", "Canonical Labels A", "Root Sources A",
            "Dataset B", "Original Labels B", "Canonical Labels B", "Root Sources B",
            "Label Comparison", "Root Source Relation"
        ]
        comp_writer.writerow(comparison_header)
        conflict_writer.writerow(comparison_header)
        wide_writer = csv.writer(wide_handle)
        wide_writer.writerow(["Address", "Dataset Count", *datasets])

        query = con.execute(
            "SELECT address,dataset,original_label,canonical_label,root_source FROM labels ORDER BY address,dataset"
        )
        for address, group in itertools.groupby(query, key=lambda row: row[0]):
            by_dataset: dict[str, dict[str, set[str]]] = {}
            for _, dataset, original, canonical, root in group:
                item = by_dataset.setdefault(dataset, {"original": set(), "canonical": set(), "root": set()})
                item["original"].add(original)
                item["canonical"].add(canonical)
                item["root"].add(root)
            present = sorted(by_dataset)
            if len(present) < 2:
                continue
            shared_global += 1
            for dataset in present:
                dataset_shared[dataset] += 1
            wide_writer.writerow([
                address,
                len(present),
                *[" | ".join(sorted(by_dataset[d]["original"])) if d in by_dataset else "" for d in datasets],
            ])
            for a, b in itertools.combinations(present, 2):
                key = (a, b)
                pair_intersection[key] += 1
                va, vb = by_dataset[a], by_dataset[b]
                comparison = compare_labels(va["original"], va["canonical"], vb["original"], vb["canonical"])
                root_relation = compare_roots(va["root"], vb["root"])
                pair_comparison[key][comparison] += 1
                pair_root[key][root_relation] += 1
                pair_joint[key][(comparison, root_relation)] += 1
                dataset_comparison[a][comparison] += 1
                dataset_comparison[b][comparison] += 1
                dataset_root[a][root_relation] += 1
                dataset_root[b][root_relation] += 1
                comparison_totals[comparison] += 1
                root_totals[root_relation] += 1
                joint_totals[(comparison, root_relation)] += 1
                output_row = [
                    address,
                    a, " | ".join(sorted(va["original"])), " | ".join(sorted(va["canonical"])), " | ".join(sorted(va["root"])),
                    b, " | ".join(sorted(vb["original"])), " | ".join(sorted(vb["canonical"])), " | ".join(sorted(vb["root"])),
                    comparison, root_relation,
                ]
                comp_writer.writerow(output_row)
                if comparison == "서로 다른 라벨":
                    conflict_writer.writerow(output_row)

    # 사용자가 요청한 한글 파일명은 동일한 strict address-only wide table의 별칭이다.

    count_matrix = []
    jaccard_matrix = []
    for a in datasets:
        count_row = [a]
        jaccard_row = [a]
        for b in datasets:
            if a == b:
                inter = dataset_sizes[a]
            else:
                inter = pair_intersection[tuple(sorted((a, b)))]
            union = dataset_sizes[a] + dataset_sizes[b] - inter
            count_row.append(inter)
            jaccard_row.append(f"{inter / union:.10f}" if union else "0")
        count_matrix.append(count_row)
        jaccard_matrix.append(jaccard_row)
    write_csv(ANALYSIS_DIR / "데이터셋 간 공통 주소 개수 행렬.csv", ["Dataset", *datasets], count_matrix)
    write_csv(ANALYSIS_DIR / "데이터셋 간 주소 자카드 유사도 행렬.csv", ["Dataset", *datasets], jaccard_matrix)

    pair_rows = []
    root_rows = []
    for a, b in itertools.combinations(datasets, 2):
        key = (a, b)
        inter = pair_intersection[key]
        union = dataset_sizes[a] + dataset_sizes[b] - inter
        comp = pair_comparison[key]
        roots = pair_root[key]
        joint = pair_joint[key]
        pair_rows.append([
            a, b, dataset_sizes[a], dataset_sizes[b], inter, union,
            f"{inter / dataset_sizes[a]:.10f}" if dataset_sizes[a] else "0",
            f"{inter / dataset_sizes[b]:.10f}" if dataset_sizes[b] else "0",
            f"{inter / union:.10f}" if union else "0",
            comp["동일 라벨"], comp["유사 라벨"], comp["서로 다른 라벨"], comp["확인 불가"],
        ])
        root_rows.append([
            a, b, inter,
            roots["동일 Root Source 포함"], roots["독립 Source"], roots["확인 불가/혼합 Source"],
            f"{roots['동일 Root Source 포함'] / inter:.10f}" if inter else "0",
            f"{roots['독립 Source'] / inter:.10f}" if inter else "0",
            joint[("동일 라벨", "동일 Root Source 포함")], joint[("유사 라벨", "동일 Root Source 포함")], joint[("서로 다른 라벨", "동일 Root Source 포함")], joint[("확인 불가", "동일 Root Source 포함")],
            joint[("동일 라벨", "독립 Source")], joint[("유사 라벨", "독립 Source")], joint[("서로 다른 라벨", "독립 Source")], joint[("확인 불가", "독립 Source")],
            joint[("동일 라벨", "확인 불가/혼합 Source")], joint[("유사 라벨", "확인 불가/혼합 Source")], joint[("서로 다른 라벨", "확인 불가/혼합 Source")], joint[("확인 불가", "확인 불가/혼합 Source")],
        ])
    write_csv(
        ANALYSIS_DIR / "데이터셋 쌍별 주소 중복률·자카드·라벨 판정 집계.csv",
        ["Dataset A", "Dataset B", "Unique Addresses A", "Unique Addresses B", "Common Addresses", "Union Addresses", "A Inclusion Rate", "B Inclusion Rate", "Jaccard Similarity", "Same Label", "Similar Label", "Different Label", "Unresolved Label"],
        pair_rows,
    )
    write_csv(
        ANALYSIS_DIR / "동일 Root-독립 Source 집계.csv",
        ["Dataset A", "Dataset B", "Common Addresses", "Same Root Source", "Independent Source", "Unknown/Mixed Source", "Same Root Rate", "Independent Rate", "SameRoot-SameLabel", "SameRoot-SimilarLabel", "SameRoot-DifferentLabel", "SameRoot-UnresolvedLabel", "Independent-SameLabel", "Independent-SimilarLabel", "Independent-DifferentLabel", "Independent-UnresolvedLabel", "UnknownRoot-SameLabel", "UnknownRoot-SimilarLabel", "UnknownRoot-DifferentLabel", "UnknownRoot-UnresolvedLabel"],
        root_rows,
    )

    summary_rows = []
    for dataset in datasets:
        comp = dataset_comparison[dataset]
        root = dataset_root[dataset]
        resolved = comp["동일 라벨"] + comp["유사 라벨"] + comp["서로 다른 라벨"]
        summary_rows.append([
            dataset,
            dataset_sizes[dataset],
            dataset_label_rows[dataset],
            dataset_shared[dataset],
            dataset_sizes[dataset] - dataset_shared[dataset],
            f"{dataset_shared[dataset] / dataset_sizes[dataset]:.10f}" if dataset_sizes[dataset] else "0",
            comp["동일 라벨"], comp["유사 라벨"], comp["서로 다른 라벨"], comp["확인 불가"],
            f"{(comp['동일 라벨'] + comp['유사 라벨']) / resolved:.10f}" if resolved else "0",
            f"{comp['서로 다른 라벨'] / resolved:.10f}" if resolved else "0",
            root["동일 Root Source 포함"], root["독립 Source"], root["확인 불가/혼합 Source"],
        ])
    write_csv(
        ANALYSIS_DIR / "데이터셋별 중복률·일치율·충돌률.csv",
        ["Dataset", "Unique Addresses", "Address-Label Rows", "Addresses Shared With Other Datasets", "Exclusive Addresses", "Address Overlap Rate", "Same Label Pair-Addresses", "Similar Label Pair-Addresses", "Different Label Pair-Addresses", "Unresolved Label Pair-Addresses", "Resolved Label Agreement Rate", "Resolved Label Conflict Rate", "Same Root Pair-Addresses", "Independent Root Pair-Addresses", "Unknown/Mixed Root Pair-Addresses"],
        summary_rows,
    )

    manifest_rows = []
    for dataset in ALL_DATASETS:
        info = MANIFEST[dataset]
        status = info["status"]
        if status == "포함" and dataset_sizes.get(dataset, 0) == 0:
            status = "실제 파일 내 유효 주소 0건"
        manifest_rows.append([
            dataset,
            status,
            info["source_files"],
            info["extraction_rule"],
            dataset_sizes.get(dataset, 0),
            dataset_label_rows.get(dataset, 0),
            store.candidate.get(dataset, 0),
            store.invalid.get(dataset, 0),
            info["caveat"],
        ])
    write_csv(
        ANALYSIS_DIR / "데이터셋별 주소·라벨 추출 및 제외 규칙.csv",
        ["Dataset", "Status", "Actual Source Files", "Address/Label Extraction Rule", "Unique Valid Addresses", "Integrated Label Rows", "Candidate Address Occurrences", "Invalid Address Occurrences", "Caveat"],
        manifest_rows,
    )

    return {
        "datasets": datasets,
        "dataset_sizes": dataset_sizes,
        "global_unique": global_unique,
        "membership_count": membership_count,
        "integrated_rows": integrated_rows,
        "shared_global": shared_global,
        "pair_intersection": pair_intersection,
        "pair_comparison": pair_comparison,
        "pair_root": pair_root,
        "comparison_totals": comparison_totals,
        "root_totals": root_totals,
        "joint_totals": joint_totals,
    }


def write_report(stats: dict[str, object]) -> None:
    datasets: list[str] = stats["datasets"]
    sizes: dict[str, int] = stats["dataset_sizes"]
    pair_intersection: Counter = stats["pair_intersection"]
    pair_comparison: dict = stats["pair_comparison"]
    comparison_totals: Counter = stats["comparison_totals"]
    root_totals: Counter = stats["root_totals"]
    joint_totals: Counter = stats["joint_totals"]
    top_pairs = sorted(pair_intersection.items(), key=lambda item: item[1], reverse=True)[:15]
    top_conflicts = sorted(
        ((pair, values["서로 다른 라벨"]) for pair, values in pair_comparison.items()),
        key=lambda item: item[1], reverse=True
    )[:15]
    resolved = comparison_totals["동일 라벨"] + comparison_totals["유사 라벨"] + comparison_totals["서로 다른 라벨"]
    lines = [
        "# 1차 실증 분석 — Address Label Agreement Analysis",
        "",
        f"- 분석 실행 시각: {dt.datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- 주소 기반 분석 대상: {len(datasets)}개 / 전체 점검 {len(ALL_DATASETS)}개",
        f"- 전체 고유 Ethereum 주소: {stats['global_unique']:,}개",
        f"- Address-Dataset membership: {stats['membership_count']:,}개",
        f"- 통합 Address-Label 행: {stats['integrated_rows']:,}개",
        f"- 2개 이상 데이터셋에 등장한 고유 주소: {stats['shared_global']:,}개",
        "",
        "## 판정 정의",
        "",
        "- 동일 라벨: 두 데이터셋의 Original Label 집합이 소문자·공백 정리 후 동일.",
        "- 유사 라벨: Original Label은 다르지만 별도 Canonical Label이 같거나, generic malicious와 구체 악성 유형처럼 계층적으로 양립.",
        "- 서로 다른 라벨: phishing/rug-pull/ponzi/hack/benign/victim 등 의미가 다른 것으로 판정.",
        "- 확인 불가: 주소 데이터셋의 원본 라벨이 unlabeled이거나 의미를 확정할 수 없는 경우.",
        "- Original Label은 변경하지 않았고 Canonical Label은 비교 판정용 별도 열로만 저장.",
        "",
        "## 전체 Label 비교",
        "",
        f"- 동일 라벨 pair-address: {comparison_totals['동일 라벨']:,}",
        f"- 유사 라벨 pair-address: {comparison_totals['유사 라벨']:,}",
        f"- 서로 다른 라벨 pair-address: {comparison_totals['서로 다른 라벨']:,}",
        f"- 확인 불가 pair-address: {comparison_totals['확인 불가']:,}",
        f"- 확인 가능한 비교의 일치율(동일+유사): {((comparison_totals['동일 라벨'] + comparison_totals['유사 라벨']) / resolved):.4%}" if resolved else "- 확인 가능한 비교 없음",
        "",
        "## Root Source 관계",
        "",
        f"- 동일 Root Source 포함: {root_totals['동일 Root Source 포함']:,}",
        f"- 독립 Source: {root_totals['독립 Source']:,}",
        f"- 확인 불가/혼합 Source: {root_totals['확인 불가/혼합 Source']:,}",
        f"- 동일 Root에서 동일·유사 라벨: {joint_totals[('동일 라벨', '동일 Root Source 포함')] + joint_totals[('유사 라벨', '동일 Root Source 포함')]:,}",
        f"- 독립 Source에서 동일·유사 라벨: {joint_totals[('동일 라벨', '독립 Source')] + joint_totals[('유사 라벨', '독립 Source')]:,}",
        "",
        "동일 Root Source가 포함된 일치는 독립적인 다수 Ground Truth로 해석하면 안 된다.",
        "",
        "## 공통 주소가 많은 Dataset Pair",
        "",
        "| Dataset A | Dataset B | 공통 주소 |",
        "|---|---|---:|",
    ]
    for (a, b), count in top_pairs:
        lines.append(f"| {a} | {b} | {count:,} |")
    lines.extend(["", "## 라벨 충돌이 많은 Dataset Pair", "", "| Dataset A | Dataset B | 충돌 주소 |", "|---|---|---:|"])
    for (a, b), count in top_conflicts:
        if count:
            lines.append(f"| {a} | {b} | {count:,} |")
    lines.extend([
        "",
        "## 실제 파일 기준 핵심 주의사항",
        "",
        "- 주소 자체에 Original Label이 직접 부여된 데이터셋만 포함했다.",
        "- Incident·Transaction·Token·Smart Contract 라벨을 그 안에 등장한 주소로 투영하지 않았다.",
        "- XBlock의 `isp=0`은 정상 주소가 아니라 phishing seed가 아닌 2-hop 이웃 주소다.",
        "- BERT4ETH의 normal EOA와 FDGNN의 Normal은 verified benign이 아니다.",
        "- RiskProp의 risk score는 Ground Truth가 아니므로 803_Account_Labels.csv의 명시 label만 사용했다.",
        "- Forta는 직접 address 라벨 파일 2개만 사용하고 malicious_smart_contracts.csv는 제외했다.",
        "- EthereumHeist는 Heist label-etherscan.csv의 Address와 Name Tag만 사용했다.",
        "",
        "## 산출물",
        "",
        "- `전체 주소·라벨 통합표.csv`: 원본 라벨을 보존한 통합 long table",
        "- `중복 주소.csv`: 2개 이상 데이터셋에 나타난 주소의 wide join",
        "- `데이터셋 간 공통 주소 개수 행렬.csv`: 공통 주소 개수 행렬",
        "- `데이터셋 간 주소 자카드 유사도 행렬.csv`: Jaccard 행렬",
        "- `데이터셋 쌍별 주소 중복률·자카드·라벨 판정 집계.csv`: 포함률·Jaccard·라벨 판정 집계",
        "- `주소별 데이터셋 쌍 라벨 비교표.csv`: 주소별 dataset pair 라벨 비교",
        f"- `라벨 충돌 판정 집계.csv`: `서로 다른 라벨` 판정만 모은 {comparison_totals['서로 다른 라벨']:,}개 충돌 행",
        "- `동일 Root-독립 Source 집계.csv`: 동일 Root/독립 Source 집계",
        "- `데이터셋별 중복률·일치율·충돌률.csv`: 데이터셋별 중복률·일치율·충돌률",
        "- `데이터셋별 주소·라벨 추출 및 제외 규칙.csv`: 실제 파일과 추출/제외 규칙",
    ])
    (ANALYSIS_DIR / "ANALYSIS_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    store = Store(DB_PATH)
    try:
        extract_all(store)
        print("[index] finalize", flush=True)
        store.finish()
        stats = build_outputs(store)
        write_report(stats)
        print("[done]", json.dumps({
            "datasets_with_addresses": len(stats["datasets"]),
            "global_unique_addresses": stats["global_unique"],
            "integrated_rows": stats["integrated_rows"],
            "shared_addresses": stats["shared_global"],
        }, ensure_ascii=False), flush=True)
        return 0
    finally:
        store.con.close()
        if DB_PATH.exists():
            DB_PATH.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
