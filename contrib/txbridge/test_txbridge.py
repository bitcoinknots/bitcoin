#!/usr/bin/env python3
"""Unit tests for the parts of txbridge that touch untrusted bytes. Run: python3 test_txbridge.py"""
import struct
import unittest

import txbridge

# Block 170, the first transaction ever sent between two people. Legacy format.
LEGACY_HEX = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
LEGACY_TXID = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
# A segwit transaction from mainnet block tip on 2026-09-06 (marker 00, flag 01, witness data present).
SEGWIT_HEX = "020000000001025772de8baf0b2c9bec3a130aff620457eafc1c3e27805c5f8cec2cd14084b9140100000000ffffffff53a0565e5736f72010c177e8996884e377ef76bd562e75aadbd9377016ebf3870000000000ffffffff021eed0800000000001600143d1d5a7c0a93f8f22ad547fe0cede4fe715ce0092f7e0b000000000017a9145a100aa3ccdd64fb84c95ce36c7aa1da03b40ed78702483045022100829917f4f11de8768fa8842441822fb517a6764ff5a0a87b17f380e15d383a1802202c36ed61be23dc440b90b9f5126c858fe603d7915876e75173b3d60214e2a6da012102bbe2aa637c3213db26d85b9c1290f978a85a07df0f9b6de518f427623c5f522a02483045022100af97cb157d13764ba00dbc9269c801c93bd5368effdf6db64b81f8d9e6947a6d02206e21156efd97aed2e8cb332e2219e50a151a3dee6dc855daabebd01d6f31e641012102bbe2aa637c3213db26d85b9c1290f978a85a07df0f9b6de518f427623c5f522a00000000"
SEGWIT_TXID = "fa3f7c31bff0efd824fe09ad7da4f9a49442e07017148a02003420a0853392c8"


class TxidTests(unittest.TestCase):
    def test_legacy(self):
        raw = bytes.fromhex(LEGACY_HEX)
        self.assertEqual(txbridge.txid_of(raw), LEGACY_TXID)
        # For a legacy transaction the txid is the hash of the whole thing.
        self.assertEqual(txbridge.sha256d(raw)[::-1].hex(), LEGACY_TXID)

    def test_segwit(self):
        raw = bytes.fromhex(SEGWIT_HEX)
        self.assertEqual(raw[4:6], b"\x00\x01")
        self.assertEqual(txbridge.txid_of(raw), SEGWIT_TXID)
        # And the wtxid (hash of the full bytes) is a different hash.
        self.assertNotEqual(txbridge.sha256d(raw)[::-1].hex(), SEGWIT_TXID)

    def test_rejects_garbage(self):
        for bad in (b"", b"\x01", bytes(10), bytes(200), b"\xff" * 64):
            with self.assertRaises(Exception):
                txbridge.txid_of(bad)

    def test_rejects_truncated_and_padded(self):
        raw = bytes.fromhex(SEGWIT_HEX)
        for cut in (5, 40, 100, len(raw) - 1):
            with self.assertRaises(Exception):
                txbridge.txid_of(raw[:cut])
        with self.assertRaises(Exception):
            txbridge.txid_of(raw + b"\x00")

    def test_rejects_absurd_counts(self):
        # version, then an input count claiming 2**32 inputs
        raw = struct.pack("<i", 2) + b"\xfe" + struct.pack("<I", 0xFFFFFFFF) + bytes(64)
        with self.assertRaises(Exception):
            txbridge.txid_of(raw)
        # zero inputs in a legacy transaction is not a transaction
        raw = struct.pack("<i", 2) + b"\x00" + b"\x01" + bytes(9) + b"\x00" + bytes(4)
        with self.assertRaises(Exception):
            txbridge.txid_of(raw)


class FramingTests(unittest.TestCase):
    def test_varint_roundtrip(self):
        for n in (0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000):
            b = txbridge.varint(n)
            self.assertEqual(txbridge.read_varint(b + b"\x00", 0)[0], n)

    def test_version_payload_shape(self):
        p = txbridge.version_payload(relay=True)
        ver, services = struct.unpack_from("<iQ", p, 0)
        self.assertEqual(ver, txbridge.PROTOCOL_VERSION)
        self.assertEqual(services, 0)          # we serve nothing
        self.assertEqual(p[-1], 1)              # and want their transactions
        self.assertEqual(txbridge.version_payload(relay=False)[-1], 0)

    def test_clean_text(self):
        self.assertEqual(txbridge.clean_text(b"\x1b[31mX\r\n/Satoshi:1/"), "?[31mX??/Satoshi:1/")
        self.assertEqual(len(txbridge.clean_text(b"a" * 500)), 80)

    def test_host_group(self):
        self.assertEqual(txbridge.host_group("10.1.2.3"), txbridge.host_group("10.1.9.9"))
        self.assertNotEqual(txbridge.host_group("10.1.2.3"), txbridge.host_group("10.2.2.3"))
        self.assertEqual(txbridge.host_group("2001:db8::1"), txbridge.host_group("2001:db8::2"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
