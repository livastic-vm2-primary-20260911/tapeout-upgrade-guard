"""Fully offline regression tests for the public TapeOut bytecode-drift utility."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import sys

MOD = Path(__file__).resolve().parents[1] / "tapeout_guard.py"
spec = importlib.util.spec_from_file_location("tapeout_guard", MOD)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


def addr(i):
    return f"0x{i:040x}"


def word(i):
    return f"0x{i:064x}"


class FakeRpc:
    """Constrained original contract snapshot on entirely synthetic addresses."""
    def __init__(self, chain_id=196, *, owner=True, missing_impl=False):
        self.url = "https://synthetic.example"
        self.chain_id = chain_id
        self.seq = []
        self.owner = owner
        self.missing_impl = missing_impl
        self.height = 505
        self.pinned = None
        self.proxies = {guard.FACTORY.lower(): 101, guard.TRANSISTOR_BEACON.lower(): 102, guard.CIRCUIT_BEACON.lower(): 103}
        self.implementations = {guard.FACTORY.lower(): 201, guard.TRANSISTOR_BEACON.lower(): 202, guard.CIRCUIT_BEACON.lower(): 203}
    def call(self, method, params):
        self.seq.append((method, params))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.height)
        if method == "eth_getBlockByNumber":
            if len(params)!=2 or params[1] is not False:
                raise AssertionError("Unexpected block header arguments")
            self.pinned = params[0]
            return {"number":params[0],"hash":"0x"+"12"*32,"timestamp":hex(1792000000)}
        if method == "eth_getCode":
            address, tag = params
            if tag != self.pinned:
                raise AssertionError("Unpinned eth_getCode")
            if address.lower() in self.proxies:
                return "0x" + ("%02x" % self.proxies[address.lower()])*7
            if address.lower() in (addr(201), addr(202), addr(203)):
                return "0x" + "60"*12
            return "0x"
        if method == "eth_getStorageAt":
            target, slot, tag = params
            if tag != self.pinned:
                raise AssertionError("Unpinned eth_getStorageAt")
            if target.lower() != guard.FACTORY.lower():
                raise AssertionError("Storage slot read of non-factory")
            if slot == guard.IMPLEMENTATION_SLOT:
                return word(0 if self.missing_impl else 201)
            if slot == guard.ADMIN_SLOT:
                return word(0)
            raise AssertionError("Unrecognized storage slot")
        if method == "eth_call":
            txn, tag = params
            if tag != self.pinned:
                raise AssertionError("Unpinned eth_call")
            if txn["data"] == guard.OWNER_SELECTOR:
                if not self.owner:
                    raise guard.EvidenceError("Ownable not implemented")
                return word(300 if txn["to"].lower() == guard.FACTORY.lower() else 0)
            if txn["data"] == guard.BEACON_IMPLEMENTATION_SELECTOR:
                target = txn["to"].lower()
                return word(self.implementations[target])
            raise AssertionError("Unexpected eth_call")
        raise AssertionError("Unrecognized RPC call")


class DummyHTTP:
    status = 200
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)
    def __enter__(self): return self
    def __exit__(self, *_): self.stream.close()
    def read(self, size=-1): return self.stream.read(size)


class GuardTests(unittest.TestCase):
    def test_01_non_hex_word_rejected(self):
        with self.assertRaises(guard.EvidenceError): guard.decoded_address("not hex")
    def test_02_short_address_rejected(self):
        with self.assertRaises(guard.EvidenceError): guard.decoded_address("0x1234")
    def test_03_nonzero_padding_rejected(self):
        with self.assertRaises(guard.EvidenceError): guard.decoded_address("0x" + "ff"*12 + "00"*20)
    def test_04_zero_owner_is_null_not_secure(self):
        self.assertIsNone(guard.decoded_address(word(0)))
    def test_05_valid_owner_address(self):
        self.assertEqual(guard.decoded_address(word(77)), addr(77))
    def test_06_bad_network_fail_closed(self):
        with self.assertRaisesRegex(guard.EvidenceError, "not expected"):
            guard.build_snapshot(FakeRpc(chain_id=1))
    def test_07_missing_proxy_slot_fail_closed(self):
        with self.assertRaisesRegex(guard.EvidenceError, "null"):
            guard.build_snapshot(FakeRpc(missing_impl=True))
    def test_08_pin_every_read(self):
        rpc=FakeRpc()
        snapshot=guard.build_snapshot(rpc)
        self.assertEqual(snapshot["network"]["block_number"],505)
        self.assertEqual(snapshot["network"]["chain_id"],196)
        for method, params in rpc.seq:
            self.assertIn(method, {"eth_chainId","eth_blockNumber","eth_getBlockByNumber","eth_getCode","eth_getStorageAt","eth_call"})
            if method == "eth_getCode":self.assertEqual(params[-1],"0x1f9")
            if method == "eth_getStorageAt":self.assertEqual(params[-1],"0x1f9")
            if method == "eth_call":self.assertEqual(params[-1],"0x1f9")
        self.assertEqual(set(snapshot["components"]),set(guard.FIELDS))
    def test_09_bytecode_real_sha256(self):
        rpc=FakeRpc()
        rpc.pinned="0x1f9"
        result=guard.code_fingerprint(rpc,guard.FACTORY,"0x1f9")
        self.assertEqual(result["runtime_sha256"],hashlib.sha256(bytes.fromhex("65"*7)).hexdigest())
        self.assertEqual(result["runtime_bytes"],7)
    def test_10_absent_code_is_error(self):
        with self.assertRaisesRegex(guard.EvidenceError,"No contract"):
            rpc=FakeRpc()
            rpc.pinned="0x1f9"
            guard.code_fingerprint(rpc,addr(555),"0x1f9")
    def test_11_owner_unreadable_stated(self):
        rpc=FakeRpc(owner=False)
        snapshot=guard.build_snapshot(rpc)
        for comp in snapshot["components"].values():self.assertEqual(comp["owner_call"]["state"],"NOT_READABLE")
    def test_12_no_diff_at_same_snapshot(self):
        s=guard.build_snapshot(FakeRpc())
        d=guard.evaluate_diff(s,copy.deepcopy(s))
        self.assertEqual(d["status"],"NO_OBSERVED_DIFFERENCE")
        self.assertFalse(d["code_or_control_changes"])
    def test_13_modified_implementation_hash_alerts(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s);t["network"]["block_number"]+=1
        t["components"]["circuit_beacon"]["implementation"]["runtime_sha256"]="ab"*32
        d=guard.evaluate_diff(s,t)
        self.assertEqual(d["status"],"CHANGE_REQUIRES_HUMAN_REVIEW")
        self.assertTrue(any(x["field"]=="implementation.runtime_sha256" for x in d["code_or_control_changes"]))
    def test_14_pointer_change_detected(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s);t["network"]["block_number"]+=1
        t["components"]["factory"]["implementation"]["address"]=addr(800)
        d=guard.evaluate_diff(s,t)
        self.assertTrue(any(x["field"]=="implementation.address" for x in d["code_or_control_changes"]))
    def test_15_admin_change_alerts(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s);t["network"]["block_number"]+=1
        t["components"]["factory"]["eip1967_admin_slot_address"]=addr(6)
        self.assertIn("eip1967_admin_slot_address",[x["field"] for x in guard.evaluate_diff(s,t)["code_or_control_changes"]])
    def test_16_owner_change_alerts(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s);t["network"]["block_number"]+=1
        t["components"]["factory"]["owner_call"]["address"]=addr(444)
        self.assertIn("owner_call",[x["field"] for x in guard.evaluate_diff(s,t)["code_or_control_changes"]])
    def test_17_reverse_block_order_rejected(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s);t["network"]["block_number"]-=1
        with self.assertRaises(guard.EvidenceError):guard.evaluate_diff(s,t)
    def test_18_missing_component_proof_rejected(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s)
        del t["components"]["circuit_beacon"]["implementation"]["runtime_sha256"]
        with self.assertRaises(guard.EvidenceError):guard.evaluate_diff(s,t)
    def test_19_different_network_rejected(self):
        s=guard.build_snapshot(FakeRpc());t=copy.deepcopy(s);t["network"]["chain_id"]=1
        with self.assertRaises(guard.EvidenceError):guard.evaluate_diff(s,t)
    def test_20_secret_bearing_rpc_disallowed(self):
        with self.assertRaises(guard.EvidenceError):guard.Rpc("https://user:pass@rpc.example")
    def test_21_http_not_supported(self):
        with self.assertRaises(guard.EvidenceError):guard.Rpc("http://example.com")
    def test_22_no_chain_writes_permitted(self):
        rpc=guard.Rpc("https://example.com")
        for method in ("eth_sendTransaction","eth_sendRawTransaction","personal_sign","eth_sign","wallet_switchEthereumChain"):
            with self.subTest(method=method):
                with self.assertRaises(guard.EvidenceError):rpc.call(method,[])
    def test_23_rpc_success_contract(self):
        def opener(req,timeout):
            d=json.loads(req.data)
            self.assertEqual(d["method"],"eth_chainId")
            return DummyHTTP(json.dumps({"jsonrpc":"2.0","id":1,"result":"0xc4"}).encode())
        rpc=guard.Rpc("https://example.com",opener=opener)
        self.assertEqual(rpc.call("eth_chainId",[]),"0xc4")
    def test_24_rpc_error_fail_closed(self):
        def opener(*args,**kwargs):
            return DummyHTTP(b'{"jsonrpc":"2.0","id":1,"error":{"message":"unavailable"}}')
        with self.assertRaises(guard.EvidenceError):guard.Rpc("https://example.com",opener=opener).call("eth_chainId",[])
    def test_25_partial_truncated_evidence_rejected(self):
        with self.assertRaises(guard.EvidenceError):guard._read_hex("0x"+"a1"*262145)
    def test_27_explicit_historic_block_pinning(self):
        rpc=FakeRpc();rpc.height=506
        snap=guard.build_snapshot(rpc,at_block=505)
        self.assertEqual(snap["network"]["block_number"],505)
        self.assertTrue(all(params[-1]=="0x1f9" for method,params in rpc.seq if method in ("eth_getCode","eth_getStorageAt","eth_call")))
    def test_28_future_block_is_rejected(self):
        with self.assertRaises(guard.EvidenceError):guard.build_snapshot(FakeRpc(),at_block=506)
    def test_29_zero_block_is_rejected(self):
        with self.assertRaises(guard.EvidenceError):guard.build_snapshot(FakeRpc(),at_block=0)
    def test_26_native_snapshot_has_no_passwords(self):
        s=guard.build_snapshot(FakeRpc())
        raw=json.dumps(s).lower()
        for key in ("private_key","mnemonic","seed_phrase","password"):
            self.assertNotIn(key,raw)


if __name__ == "__main__":
    unittest.main()
