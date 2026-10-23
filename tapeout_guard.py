#!/usr/bin/env python3
"""TapeOut Upgrade Guard: pinned, read-only evidence of X Layer code/upgrade controls.

No signing, sending, approvals, permissions requests, keys, explorer scraping, or
writes to a blockchain. The tool cannot prove contract safety or treasury backing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

CHAIN_ID = 196
DEFAULT_RPC = "https://rpc.xlayer.tech"
# TapeOut X Layer deployment coordinates independently documented by
# NetLayerLabs/Cerebr/TAPEOUT.md on Oct 4, 2026. Re-verify onchain.
FACTORY = "0x1f09daefa827f02cbb40967cc91b259763760761"
TRANSISTOR_BEACON = "0x1059Ad62cAbB6a6925bb65aA617300556c60A51B"
CIRCUIT_BEACON = "0xf70d1ed4f62CF3780157B0b421b7E2F45bD0991C"
# External, not independently verified as TapeOut-official, source-file value as checked 2026-10-23.
DOCUMENTED_FACTORY_IMPL = "0x74956236ab64ed143933040b4137e8a352e4d17b"
# https://eips.ethereum.org/EIPS/eip-1967
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e019a8f7e8e9b7c593a4fbe19501723f"
BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"  # implementation()
OWNER_SELECTOR = "0x8da5cb5b"  # owner()
HEX = re.compile(r"^0x[0-9a-fA-F]*$")
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class EvidenceError(RuntimeError):
    """Do not silently replace a verified reference with an incomplete read."""


def _read_hex(value: object, *, max_bytes: int = 262144) -> bytes:
    if not isinstance(value, str) or not HEX.fullmatch(value) or len(value) % 2 != 0:
        raise EvidenceError("RPC provided malformed hex")
    raw = bytes.fromhex(value[2:])
    if len(raw) > max_bytes:
        raise EvidenceError("RPC hex value exceeds size budget")
    return raw


def decoded_address(word: object) -> str | None:
    raw = _read_hex(word, max_bytes=32)
    if len(raw) != 32 or any(raw[:12]):
        raise EvidenceError("Expected one ABI 32-byte address word")
    addr = raw[12:].hex()
    return None if addr == "0" * 40 else "0x" + addr


class Rpc:
    def __init__(self, url: str = DEFAULT_RPC, *, opener=None, timeout: int = 12):
        if not url.startswith("https://") or "@" in url or "#" in url:
            raise EvidenceError("Only an explicit HTTPS RPC URL without embedded credentials is allowed")
        self.url = url
        self.opener = opener or urllib.request.urlopen
        self.timeout = timeout
        self.sequence = 0

    def call(self, method: str, params: list) -> object:
        # Deliberately read-only RPC allowlist. Fail closed for unrecognized methods.
        if method not in {
            "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber",
            "eth_getCode", "eth_getStorageAt", "eth_call"
        }:
            raise EvidenceError("Only allowed read-only eth RPC calls are supported")
        self.sequence += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params},
            separators=(",", ":")
        ).encode()
        req = urllib.request.Request(
            self.url, data=payload, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "OneCursor-TapeOut-ReadOnly-UpgradeGuard/0.1"}
        )
        try:
            with self.opener(req, timeout=self.timeout) as stream:
                if stream.status != 200:
                    raise EvidenceError(f"RPC returned HTTP {stream.status}")
                body = stream.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise EvidenceError("RPC response exceeds 1MiB")
                response = json.loads(body)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise EvidenceError(f"Read-only RPC unavailable: {type(exc).__name__}") from None

        if (not isinstance(response, dict) or response.get("jsonrpc") != "2.0"
                or response.get("id") != self.sequence or response.get("error")
                or "result" not in response):
            raise EvidenceError(f"RPC response invalid or error for {method}")
        return response["result"]


def canonical_hex_integer(x: object) -> int:
    if not isinstance(x, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", x):
        raise EvidenceError("Invalid JSON-RPC integer")
    return int(x, 16)


def code_fingerprint(rpc: Rpc, address: str, tag: str) -> dict:
    if not ADDRESS.fullmatch(address):
        raise EvidenceError("Invalid contract address")
    raw = _read_hex(rpc.call("eth_getCode", [address, tag]))
    if not raw:
        raise EvidenceError(f"No contract runtime code at {address} at pinned block")
    return {
        "address": address.lower(),
        "runtime_bytes": len(raw),
        "runtime_sha256": hashlib.sha256(raw).hexdigest(),
        "fingerprint_hash": "SHA-256, not Ethereum keccak-256"
    }


def read_optional_owner(rpc: Rpc, address: str, tag: str) -> dict:
    # Some components are not Ownable. Failure is explicitly marked NOT_READABLE;
    # it is never described as a zero address, safe owner, or EOA.
    try:
        word = rpc.call("eth_call", [{"to": address, "data": OWNER_SELECTOR}, tag])
        return {"state": "READ", "address": decoded_address(word)}
    except EvidenceError:
        return {"state": "NOT_READABLE", "address": None}


def build_snapshot(rpc: Rpc, *, at_block: int | None = None) -> dict:
    chain = canonical_hex_integer(rpc.call("eth_chainId", []))
    if chain != CHAIN_ID:
        raise EvidenceError(f"RPC chain {chain} is not expected X Layer chainId 196")
    head = canonical_hex_integer(rpc.call("eth_blockNumber", []))
    if at_block is not None and (type(at_block) is not int or at_block < 1 or at_block > head):
        raise EvidenceError("Requested historic block must be between 1 and current head")
    height = head if at_block is None else at_block
    if height < 1:
        raise EvidenceError("RPC chain block number must be positive")
    block_tag = hex(height)
    header = rpc.call("eth_getBlockByNumber", [block_tag, False])
    if (not isinstance(header, dict) or canonical_hex_integer(header.get("number")) != height
            or not isinstance(header.get("hash"), str)
            or not re.fullmatch(r"0x[0-9a-fA-F]{64}", header["hash"])):
        raise EvidenceError("Pinned block header mismatch or incomplete")
    ts = canonical_hex_integer(header.get("timestamp"))

    factory_proxy = code_fingerprint(rpc, FACTORY, block_tag)
    f_impl_raw = rpc.call("eth_getStorageAt", [FACTORY, IMPLEMENTATION_SLOT, block_tag])
    f_impl_addr = decoded_address(f_impl_raw)
    if not f_impl_addr:
        raise EvidenceError("Factory EIP-1967 implementation pointer is null")
    factory_impl = code_fingerprint(rpc, f_impl_addr, block_tag)
    f_admin = decoded_address(rpc.call("eth_getStorageAt", [FACTORY, ADMIN_SLOT, block_tag]))

    components = {
        "factory": {
            "kind": "UUPS/EIP-1967 proxy (reported, verify by code)",
            "proxy": factory_proxy,
            "implementation": factory_impl,
            "eip1967_admin_slot_address": f_admin,
            "owner_call": read_optional_owner(rpc, FACTORY, block_tag),
        }
    }
    for label, address in [
        ("transistor_beacon", TRANSISTOR_BEACON),
        ("circuit_beacon", CIRCUIT_BEACON)
    ]:
        beacon = code_fingerprint(rpc, address, block_tag)
        impl = decoded_address(rpc.call(
            "eth_call", [{"to": address, "data": BEACON_IMPLEMENTATION_SELECTOR}, block_tag]
        ))
        if not impl:
            raise EvidenceError(f"{label}: implementation() returned null")
        components[label] = {
            "kind": "IBeacon implementation()",
            "beacon": beacon,
            "implementation": code_fingerprint(rpc, impl, block_tag),
            "owner_call": read_optional_owner(rpc, address, block_tag),
        }

    return {
        "schema": "tapeout-upgrade-guard-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "network": {
            "name": "X Layer", "chain_id": chain, "rpc_origin": rpc.url,
            "block_number": height, "block_hash": header["hash"].lower(),
            "block_timestamp_utc": datetime.fromtimestamp(ts, timezone.utc).isoformat()
        },
        "source": {
            "deployment_listing": "https://github.com/NetLayerLabs/Cerebr/blob/main/TAPEOUT.md",
            "chain_explorer": "https://www.oklink.com/xlayer",
            "standard": "https://eips.ethereum.org/EIPS/eip-1967",
            "source_truth": "Public RPC bytecode and storage at one pinned block",
            "external_documented_factory_implementation": DOCUMENTED_FACTORY_IMPL,
            "external_doc_checked_date_utc": "2026-10-23",
            "external_doc_vs_live_implementation": (
                "MISMATCH_RECHECK_SOURCE_AND_UPGRADE_HISTORY"
                if f_impl_addr.lower() != DOCUMENTED_FACTORY_IMPL.lower() else "MATCH"
            )
        },
        "components": components,
        "limitations": [
            "This is not a security audit or a guarantee against malicious upgrades.",
            "SHA-256 runtime fingerprints are not keccak-256 Ethereum code hashes.",
            "owner() is optional and cannot by itself prove access control or Safe signer policy.",
            "Off-chain fund backing, governance timelocks, fee safety, bytecode source verification and code semantics are not proved.",
            "These deployed addresses originate from third-party public documentation; verify before using for funds.",
            "No wallet authentication, on-chain transactions or personally identifying user data is used."
        ],
    }


FIELDS = {
    "factory": ("proxy", "implementation", "owner_call", "eip1967_admin_slot_address"),
    "transistor_beacon": ("beacon", "implementation", "owner_call"),
    "circuit_beacon": ("beacon", "implementation", "owner_call"),
}


def evaluate_diff(a: dict, b: dict) -> dict:
    if a.get("schema") != "tapeout-upgrade-guard-v1" or b.get("schema") != "tapeout-upgrade-guard-v1":
        raise EvidenceError("Snapshot schema mismatch")
    if a.get("network", {}).get("chain_id") != CHAIN_ID or b.get("network", {}).get("chain_id") != CHAIN_ID:
        raise EvidenceError("Snapshot chain IDs inconsistent")
    before = a["network"]["block_number"]
    after = b["network"]["block_number"]
    if not isinstance(before, int) or not isinstance(after, int) or after < before:
        raise EvidenceError("Evidence must be in nondecreasing block order")
    changes = []
    for label, fields in FIELDS.items():
        try:
            first, last = a["components"][label], b["components"][label]
            for field in fields:
                va, vb = first[field], last[field]
                # Never silently ignore missing or partially populated evidence.
                if field in ("proxy", "beacon", "implementation"):
                    for child in ("address", "runtime_sha256", "runtime_bytes"):
                        if child not in va or child not in vb:
                            raise EvidenceError(f"Incomplete {label}.{field}.{child} evidence")
                        if va[child] != vb[child]:
                            changes.append({"component": label, "field": f"{field}.{child}",
                                            "from": va[child], "to": vb[child]})
                else:
                    if va != vb:
                        changes.append({"component": label, "field": field, "from": va, "to": vb})
        except (KeyError, TypeError):
            raise EvidenceError(f"One or both snapshots lack complete {label} evidence") from None
    return {
        "schema": "tapeout-upgrade-diff-v1",
        "chain_id": CHAIN_ID,
        "earlier_block": before, "later_block": after,
        "code_or_control_changes": changes,
        "status": "CHANGE_REQUIRES_HUMAN_REVIEW" if changes else "NO_OBSERVED_DIFFERENCE",
        "caution": "No difference between two observations is not proof nothing changed between blocks.",
    }


def write_json_atomically(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".upgrade-guard-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("snapshot", help="Read-only public RPC at one pinned X Layer block")
    a.add_argument("--rpc", default=DEFAULT_RPC)
    a.add_argument("--block", type=int, help="Optional historical block number, at or below current head")
    a.add_argument("--out", required=True, type=Path)
    b = sub.add_parser("diff", help="Compare two saved pinned snapshots offline")
    b.add_argument("before", type=Path)
    b.add_argument("after", type=Path)
    b.add_argument("--out", type=Path)
    args = p.parse_args(argv)
    try:
        if args.mode == "snapshot":
            result = build_snapshot(Rpc(args.rpc), at_block=args.block)
            write_json_atomically(args.out, result)
            print(json.dumps({
                "status": "READ_ONLY_VERIFIED_PINNED_SNAPSHOT",
                "chain_id": result["network"]["chain_id"],
                "block_number": result["network"]["block_number"],
                "block_hash": result["network"]["block_hash"],
                "component_count": len(result["components"]),
                "outfile": str(args.out), "funds_spent": 0, "signed_transactions": 0
            }, separators=(",", ":")))
        elif args.mode == "diff":
            result = evaluate_diff(
                json.loads(args.before.read_text(encoding="utf-8")),
                json.loads(args.after.read_text(encoding="utf-8")),
            )
            if args.out:
                write_json_atomically(args.out, result)
            print(json.dumps(result, separators=(",", ":")))
        return 0
    except (EvidenceError, OSError, ValueError, KeyError) as exc:
        print(f"FAIL_CLOSED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
