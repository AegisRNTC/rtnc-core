#!/usr/bin/env python3
import hashlib
import struct
import sys

COIN = 100_000_000

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def ser_compact_size(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xFFFFFFFF:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def push_data(data: bytes) -> bytes:
    l = len(data)
    if l < 0x4c:
        return bytes([l]) + data
    raise ValueError("timestamp too long for simple push")

def script_num(n: int) -> bytes:
    if n == 0:
        return b""
    neg = n < 0
    n = -n if neg else n
    out = bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)

def push_int(n: int) -> bytes:
    b = script_num(n)
    return bytes([len(b)]) + b if b else b'\x00'

def bits_to_target(bits: int) -> int:
    # "compact" -> target integer
    exp = bits >> 24
    mant = bits & 0x007fffff
    if bits & 0x00800000:
        raise ValueError("negative compact")
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))

def coinbase_tx(timestamp: str, reward_sat: int, pubkey_hex: str) -> bytes:
    # Matches Bitcoin Core CreateGenesisBlock pattern:
    # scriptSig: 486604799 (0x1d00ffff) << 4 << timestamp
    ts = timestamp.encode('utf-8')
    script_sig = push_int(486604799) + push_int(4) + push_data(ts)

    version = struct.pack('<I', 1)
    marker_flag = b''  # no segwit
    vin_cnt = b'\x01'
    prevout = b'\x00' * 32 + struct.pack('<I', 0xFFFFFFFF)
    scriptsig = ser_compact_size(len(script_sig)) + script_sig
    sequence = struct.pack('<I', 0xFFFFFFFF)
    vin = prevout + scriptsig + sequence

    vout_cnt = b'\x01'
    value = struct.pack('<q', reward_sat)
    pubkey = bytes.fromhex(pubkey_hex)
    pk_script = push_data(pubkey) + b'\xac'  # OP_CHECKSIG
    vout = value + ser_compact_size(len(pk_script)) + pk_script

    locktime = struct.pack('<I', 0)

    return version + marker_flag + vin_cnt + vin + vout_cnt + vout + locktime

def merkle_root(tx_hashes: list[bytes]) -> bytes:
    layer = tx_hashes[:]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def header_hash(version: int, prevhash: bytes, merkleroot: bytes, ntime: int, nbits: int, nonce: int) -> bytes:
    hdr = struct.pack('<I', version)
    hdr += prevhash[::-1]
    hdr += merkleroot[::-1]
    hdr += struct.pack('<I', ntime)
    hdr += struct.pack('<I', nbits)
    hdr += struct.pack('<I', nonce)
    return sha256d(hdr)

def main():
    if len(sys.argv) != 6:
        print("Usage: genesis_rtnc.py <timestamp> <pubkey_hex> <time> <bits_hex> <start_nonce>")
        print("Example: genesis_rtnc.py \"RTNC genesis 2026-02-07\" 02abcd... 1707320000 0x1f00ffff 0")
        sys.exit(1)

    timestamp = sys.argv[1]
    pubkey_hex = sys.argv[2]
    ntime = int(sys.argv[3])
    nbits = int(sys.argv[4], 0)
    nonce = int(sys.argv[5])

    tx = coinbase_tx(timestamp, 50 * COIN, pubkey_hex)
    txid = sha256d(tx)
    mr = merkle_root([txid])

    target = bits_to_target(nbits)

    version = 1
    prev = b'\x00' * 32

    while True:
        h = header_hash(version, prev, mr, ntime, nbits, nonce)
        h_int = int.from_bytes(h[::-1], 'big')
        if h_int <= target:
            print("FOUND")
            print(f"timestamp: {timestamp}")
            print(f"pubkey:    {pubkey_hex}")
            print(f"time:      {ntime}")
            print(f"bits:      0x{nbits:08x}")
            print(f"nonce:     {nonce}")
            print(f"merkleroot:{mr[::-1].hex()}")
            print(f"genesis:   {h[::-1].hex()}")
            return
        nonce += 1

if __name__ == "__main__":
    main()
