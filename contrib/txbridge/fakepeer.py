#!/usr/bin/env python3
"""A hostile peer for testing knots-txbridge. Listens on a port, speaks the regtest wire format, and misbehaves per --mode."""
import argparse, asyncio, hashlib, os, random, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from txbridge import NETWORKS, varint, read_varint, net_addr, sha256d, MSG_TX

MAGIC = NETWORKS["regtest"][0]

def frame(cmd, payload, magic=MAGIC, checksum=None):
    return magic + cmd.ljust(12, b"\0") + struct.pack("<I", len(payload)) + (checksum or sha256d(payload)[:4]) + payload

def version(ua=b"/FakePeer:0.1/", services=0x409):
    return struct.pack("<iQq", 70016, services, int(time.time())) + net_addr(0) + net_addr(0) + struct.pack("<Q", 1) + varint(len(ua)) + ua + struct.pack("<i", 0) + b"\x01"

def synth_tx(witness=True, seed=0):
    r = random.Random(seed)
    prev = bytes(r.getrandbits(8) for _ in range(32))
    vin = prev + struct.pack("<I", 0) + varint(0) + b"\xff\xff\xff\xff"
    vout = struct.pack("<Q", 1000) + varint(22) + b"\x00\x14" + bytes(r.getrandbits(8) for _ in range(20))
    core = struct.pack("<i", 2) + varint(1) + vin + varint(1) + vout
    if witness:
        witness = varint(2) + varint(71) + bytes(r.getrandbits(8) for _ in range(71)) + varint(33) + bytes(r.getrandbits(8) for _ in range(33))
        return struct.pack("<i", 2) + b"\x00\x01" + varint(1) + vin + varint(1) + vout + witness + b"\0\0\0\0"
    return core + b"\0\0\0\0"

async def read_msg(reader):
    hdr = await reader.readexactly(24)
    cmd = hdr[4:16].rstrip(b"\0"); ln = struct.unpack("<I", hdr[16:20])[0]
    return cmd, await reader.readexactly(ln)

async def handle(reader, writer, mode, args):
    w = writer.write
    try:
        cmd, _ = await read_msg(reader)          # bridge's version
        ua = b"\x1b[31mEVIL\x1b[0m\r\nINJECTED LOG LINE /Satoshi:99.0/" if mode == "ansiua" else b"/FakePeer:0.1/"
        if mode == "shortversion":
            w(frame(b"version", b"\x01\x02\x03")); await writer.drain()
            return
        w(frame(b"version", version(ua))); w(frame(b"verack", b"")); await writer.drain()
        cmd, _ = await read_msg(reader)          # verack
        if mode == "honest":
            raw = bytes.fromhex(args.tx)
            txid = sha256d(raw[:4] + raw[6:] if raw[4] == 0 else raw)  # not used; announce by real txid from args
            h = bytes.fromhex(args.txid)[::-1]
            w(frame(b"inv", varint(1) + struct.pack("<I", MSG_TX) + h)); await writer.drain()
            while True:
                cmd, payload = await read_msg(reader)   # wtxidrelay, verack, pings... until the getdata
                if cmd == b"getdata":
                    break
            w(frame(b"tx", raw)); await writer.drain()
            return
        if mode == "bigmsg":                     # a 4 MB 'tx' of garbage
            w(frame(b"tx", bytes(4_000_000))); await writer.drain(); return
        if mode == "hugelen":                    # header claiming 4 GB
            w(MAGIC + b"tx".ljust(12, b"\0") + struct.pack("<I", 0xFFFFFFFF) + b"\0\0\0\0"); await writer.drain(); return
        if mode == "badchecksum":
            w(frame(b"inv", varint(1) + struct.pack("<I", 1) + bytes(32), checksum=b"\0\0\0\0")); await writer.drain(); return
        if mode == "badmagic":
            w(frame(b"ping", bytes(8), magic=b"\xde\xad\xbe\xef")); await writer.drain(); return
        if mode == "invflood":                   # 200 x 50,000 fake txids, never delivered
            for k in range(200):
                items = b"".join(struct.pack("<I", MSG_TX) + hashlib.sha256(struct.pack("<II", k, j)).digest() for j in range(50_000))
                w(frame(b"inv", varint(50_000) + items)); await writer.drain()
            # drain getdata quietly, deliver nothing
            while True:
                await read_msg(reader)
        if mode == "invbadcount":                # varint says 1,000,000 items, payload has 1
            w(frame(b"inv", varint(1_000_000) + struct.pack("<I", MSG_TX) + bytes(32))); await writer.drain(); return
        if mode == "garbagetx":                  # 5,000 unsolicited garbage txs as fast as possible
            for k in range(5000):
                w(frame(b"tx", os.urandom(200)))
                if k % 100 == 0: await writer.drain()
            await writer.drain(); return
        if mode == "txflood":                    # 5,000 unsolicited well-formed synthetic txs in a burst
            for k in range(5000):
                w(frame(b"tx", synth_tx(seed=k)))
                if k % 100 == 0: await writer.drain()
            await writer.drain(); return
        if mode == "malleate":                   # same txid, 6 different witnesses
            base = synth_tx(seed=7)
            for k in range(6):
                t = bytearray(base); t[-40] ^= (k + 1)   # flip a byte inside the last witness item
                w(frame(b"tx", bytes(t)))
            await writer.drain(); return
        if mode == "slowloris":                  # header of a tx, then silence
            w(MAGIC + b"tx".ljust(12, b"\0") + struct.pack("<I", 100) + b"\0\0\0\0"); await writer.drain()
            await asyncio.sleep(400); return
        if mode == "dupversion":
            w(frame(b"version", version())); await writer.drain(); return
        if mode == "ansiua":
            return
        if mode == "idle":
            await asyncio.sleep(400); return
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()

async def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--mode", required=True); ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tx"); ap.add_argument("--txid"); ap.add_argument("--seconds", type=int, default=60)
    args = ap.parse_args()
    srv = await asyncio.start_server(lambda r, w: handle(r, w, args.mode, args), "127.0.0.1", args.port)
    async with srv:
        await asyncio.sleep(args.seconds)

if __name__ == "__main__":
    asyncio.run(main())
