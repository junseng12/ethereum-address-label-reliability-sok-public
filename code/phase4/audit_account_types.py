from __future__ import annotations

import csv
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path


BASE = Path(__file__).resolve().parent
OUTPUT = BASE / "00_주소_계정유형_검증.csv"
INTERSECTION_INPUT = BASE / "03_중복주소_데이터셋교집합.csv"
CACHE = BASE / "_account_type_code_cache.csv"

# The block used for the reproducible audit performed on 2026-08-28.
BLOCK_NUMBER = 25_850_281
BLOCK_HEX = hex(BLOCK_NUMBER)
BLOCK_TIME_UTC = "2026-08-28 00:54:23 UTC"
BATCH_SIZE = 100
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
DELEGATION_RE = re.compile(r"^0xef0100[0-9a-f]{40}$")

RPC_ENDPOINTS = (
    "https://eth-mainnet.public.blastapi.io",
    "https://ethereum-rpc.publicnode.com",
)


def load_addresses() -> list[str]:
    # Once 00 exists, reuse its complete pre-filter address universe. The current
    # 03 output intentionally excludes contracts and must not shrink a re-audit.
    source = OUTPUT if OUTPUT.exists() else INTERSECTION_INPUT
    addresses: list[str] = []
    with source.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            address = (row.get("Address") or "").strip().lower()
            if not ADDRESS_RE.fullmatch(address):
                raise ValueError(f"Invalid Ethereum address in {source.name}: {address!r}")
            addresses.append(address)
    if len(addresses) != len(set(addresses)):
        raise ValueError(f"Duplicate addresses found in {source.name}")
    return sorted(addresses)


def rpc_batch(endpoint: str, addresses: list[str]) -> dict[str, str]:
    payload = [
        {
            "jsonrpc": "2.0",
            "id": index,
            "method": "eth_getCode",
            "params": [address, BLOCK_HEX],
        }
        for index, address in enumerate(addresses)
    ]
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "address-account-type-audit/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.load(response)
    if not isinstance(body, list) or len(body) != len(addresses):
        raise RuntimeError(f"Partial batch response: expected={len(addresses)}, received={len(body) if isinstance(body, list) else 'non-list'}")
    by_id = {item.get("id"): item for item in body if isinstance(item, dict)}
    if set(by_id) != set(range(len(addresses))):
        raise RuntimeError("RPC response IDs do not match the request batch")
    result: dict[str, str] = {}
    for index, address in enumerate(addresses):
        item = by_id[index]
        if "error" in item or not isinstance(item.get("result"), str):
            raise RuntimeError(f"RPC error for {address}: {item.get('error', item)}")
        code = item["result"].lower()
        if not code.startswith("0x"):
            raise RuntimeError(f"Malformed bytecode for {address}: {code!r}")
        result[address] = code
    return result


def fetch_codes(addresses: list[str]) -> dict[str, str]:
    codes: dict[str, str] = {}
    if CACHE.exists():
        with CACHE.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                address = row.get("Address", "")
                code = row.get("Code", "")
                if address in addresses and code.startswith("0x"):
                    codes[address] = code

    remaining = [address for address in addresses if address not in codes]
    cache_exists = CACHE.exists() and CACHE.stat().st_size > 0
    with CACHE.open("a", encoding="utf-8-sig", newline="") as cache_handle:
        cache_writer = csv.DictWriter(cache_handle, fieldnames=["Address", "Code"])
        if not cache_exists:
            cache_writer.writeheader()
        for start in range(0, len(remaining), BATCH_SIZE):
            batch = remaining[start : start + BATCH_SIZE]
            last_error: Exception | None = None
            for attempt in range(10):
                endpoint = RPC_ENDPOINTS[(start // BATCH_SIZE + attempt) % len(RPC_ENDPOINTS)]
                try:
                    batch_codes = rpc_batch(endpoint, batch)
                    codes.update(batch_codes)
                    cache_writer.writerows(
                        {"Address": address, "Code": batch_codes[address]} for address in batch
                    )
                    cache_handle.flush()
                    last_error = None
                    break
                except (OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
                    last_error = exc
                    time.sleep(min(1 + attempt * 2, 20))
            if last_error is not None:
                raise RuntimeError(f"Unable to audit remaining batch starting at {start}: {last_error}")
            completed = len(codes)
            if completed % 2_500 < BATCH_SIZE or completed == len(addresses):
                print(f"[audit] {completed:,}/{len(addresses):,}", flush=True)
    if set(codes) != set(addresses):
        raise RuntimeError("The completed audit does not cover every input address")
    return codes


def classify(code: str) -> tuple[str, str]:
    if code in {"0x", "0x0", "0x00"}:
        return "EOA", "eth_getCode returned empty code"
    if DELEGATION_RE.fullmatch(code):
        return "Delegated EOA", "EIP-7702 delegation indicator (0xef0100 || address)"
    return "Conventional Contract", "Non-empty runtime bytecode; not an EIP-7702 delegation indicator"


def write_output(addresses: list[str], codes: dict[str, str]) -> None:
    fields = [
        "Address",
        "Account Type",
        "검증 블록",
        "블록 시각(UTC)",
        "판정 규칙",
    ]
    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for address in addresses:
            account_type, rule = classify(codes[address])
            writer.writerow(
                {
                    "Address": address,
                    "Account Type": account_type,
                    "검증 블록": BLOCK_NUMBER,
                    "블록 시각(UTC)": BLOCK_TIME_UTC,
                    "판정 규칙": rule,
                }
            )


def validate(addresses: list[str]) -> None:
    counts: dict[str, int] = {}
    output_addresses: set[str] = set()
    with OUTPUT.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            output_addresses.add(row["Address"])
            account_type = row["Account Type"]
            counts[account_type] = counts.get(account_type, 0) + 1
    if output_addresses != set(addresses):
        raise RuntimeError("Account-type output coverage validation failed")
    if sum(counts.values()) != len(addresses):
        raise RuntimeError("Account-type output row-count validation failed")
    print("[result] " + ", ".join(f"{key}={value:,}" for key, value in sorted(counts.items())))
    print(f"[output] {OUTPUT}")


def main() -> None:
    addresses = load_addresses()
    codes = fetch_codes(addresses)
    write_output(addresses, codes)
    validate(addresses)
    if CACHE.exists():
        CACHE.unlink()


if __name__ == "__main__":
    main()
