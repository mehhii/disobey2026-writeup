#!/usr/bin/env python3
from Crypto.Cipher import AES, ARC4
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1, SHA256
import hashlib, itertools, struct

PW = b"verySecureEncryptionThisIs"
start = open("start.bin","rb").read()     # 20 bytes
ct    = open("archive.bin","rb").read()   # 546 bytes

def zip_header_score(pt: bytes) -> int:
    # score plausibility of ZIP local file header at offset 0
    if len(pt) < 40: return -999
    if not pt.startswith(b"PK\x03\x04"): return -999

    ver = int.from_bytes(pt[4:6], "little")
    flags = int.from_bytes(pt[6:8], "little")
    comp = int.from_bytes(pt[8:10], "little")
    fnlen = int.from_bytes(pt[26:28], "little")
    xlen  = int.from_bytes(pt[28:30], "little")

    score = 0
    # version is usually small
    if ver in (10, 20, 45, 51, 52, 63): score += 3
    elif 0 < ver < 100: score += 1

    # encryption flag should be set in ZIP if zip --password used
    if flags & 0x0001: score += 3
    else: score -= 2

    # compression method common
    if comp in (0, 8, 9, 12, 14): score += 2
    else: score -= 1

    # filename length plausible
    if 1 <= fnlen <= 80: score += 2
    else: score -= 2

    # extra field plausible
    if 0 <= xlen <= 200: score += 1
    else: score -= 1

    # try filename bytes printable-ish if present
    if 30 + fnlen <= len(pt):
        fn = pt[30:30+fnlen]
        if all(32 <= b < 127 for b in fn): score += 2
        if b".txt" in fn: score += 1

    return score

def best_of(name, pts):
    best = None
    for pt in pts:
        sc = zip_header_score(pt)
        if best is None or sc > best[0]:
            best = (sc, pt)
    return best

def cut_keystream(full: bytes, skip: int) -> bytes:
    return full[skip:skip+len(ct)]

def xor_bytes(a,b): return bytes(x^y for x,y in zip(a,b))

# Candidate key bytes
key_materials = [
    ("pw", PW),
    ("pw+start", PW+start),
    ("start+pw", start+PW),
    ("sha256(pw)", hashlib.sha256(PW).digest()),
    ("sha256(pw+start)", hashlib.sha256(PW+start).digest()),
    ("sha256(start+pw)", hashlib.sha256(start+PW).digest()),
]

# Nonce/IV candidates from start.bin
s = start
chunks = {
    "s[:8]": s[:8], "s[8:16]": s[8:16], "s[12:20]": s[12:20],
    "s[:12]": s[:12], "s[8:20]": s[8:20],
    "s[:16]": s[:16], "s[4:20]": s[4:20],
}

max_skip = 128  # metadata before file chunk
best_global = None

def consider(label, pt, extra=None):
    global best_global
    sc = zip_header_score(pt)
    if best_global is None or sc > best_global[0]:
        best_global = (sc, label, extra, pt)

# 1) RC4 (ARC4) with skip (RC4 stream offset)
for km_name, km in key_materials:
    # common: rc4 key = sha256(material) or raw material truncated
    keys = [
        ("raw", km),
        ("sha256", hashlib.sha256(km).digest()),
        ("md5", hashlib.md5(km).digest()),
    ]
    for kname, key in keys:
        # Generate RC4 stream long enough then XOR by decrypting a zero stream:
        # easiest: decrypt ct but also try skipping by discarding bytes.
        for skip in (0, 4, 8, 16, 32, 64, 96, 128):
            cipher = ARC4.new(key)
            cipher.decrypt(b"\x00"*skip)          # drop bytes
            pt = cipher.decrypt(ct)
            consider(f"rc4_{km_name}_{kname}_drop{skip}", pt)

# 2) AES stream modes (CTR/CFB/OFB) with various nonce/iv interpretations and skip
def aes_try(key16, mode, iv_or_nonce, initial_value=None, skip=0):
    # produce keystream by encrypting zeros, then xor
    if mode == "CTR":
        if initial_value is None:
            c = AES.new(key16, AES.MODE_CTR, nonce=iv_or_nonce)
        else:
            c = AES.new(key16, AES.MODE_CTR, nonce=iv_or_nonce, initial_value=initial_value)
    elif mode == "CFB":
        c = AES.new(key16, AES.MODE_CFB, iv=iv_or_nonce, segment_size=128)
    elif mode == "OFB":
        c = AES.new(key16, AES.MODE_OFB, iv=iv_or_nonce)
    else:
        return None

    # advance stream by skip bytes (encrypt zeros)
    if skip:
        c.encrypt(b"\x00"*skip)
    return c.decrypt(ct)

for km_name, km in key_materials:
    # AES-128 key candidates
    key16s = [
        ("sha256[:16]", hashlib.sha256(km).digest()[:16]),
        ("md5", hashlib.md5(km).digest()),
        ("pwpad16", (km[:16].ljust(16,b"\x00"))),
    ]
    for k16_name, key16 in key16s:
        # CTR: nonce can be 0..15 bytes in PyCryptodome; try nonce from start slices and various counter initial values
        for n_name, n in chunks.items():
            if len(n) > 15: 
                continue
            for skip in (0, 4, 8, 16, 32, 64, 96, 128):
                # try without explicit counter (pycryptodome builds counter from nonce)
                try:
                    pt = aes_try(key16, "CTR", n, None, skip)
                    consider(f"aesctr_{km_name}_{k16_name}_nonce{n_name}_skip{skip}", pt)
                except Exception:
                    pass

        # CTR with nonce=first 8 and counter from next 8 (common)
        if len(s) >= 16:
            nonce8 = s[:8]
            ctr8_be = int.from_bytes(s[8:16], "big")
            ctr8_le = int.from_bytes(s[8:16], "little")
            for skip in (0, 8, 16, 32, 64, 128):
                for ctrv, ctrn in [(ctr8_be,"be"), (ctr8_le,"le")]:
                    try:
                        pt = aes_try(key16, "CTR", nonce8, ctrv, skip)
                        consider(f"aesctr_{km_name}_{k16_name}_nonce8_ctr{ctrn}_skip{skip}", pt)
                    except Exception:
                        pass

        # CFB/OFB need 16-byte IV; try from start padded/hashed into 16
        iv16s = []
        for iv_name, iv in [("s[:16]", s[:16]), ("s[4:20]", s[4:20])]:
            if len(iv) == 16: iv16s.append((iv_name, iv))
        # derive IV if not 16:
        iv16s.append(("sha256(start)[:16]", hashlib.sha256(start).digest()[:16]))
        iv16s.append(("sha256(pw+start)[:16]", hashlib.sha256(PW+start).digest()[:16]))

        for iv_name, iv16 in iv16s:
            for skip in (0, 16, 32, 64, 128):
                for mode in ("CFB","OFB"):
                    try:
                        pt = aes_try(key16, mode, iv16, None, skip)
                        consider(f"aes{mode.lower()}_{km_name}_{k16_name}_{iv_name}_skip{skip}", pt)
                    except Exception:
                        pass

# 3) PBKDF2-derived AES keys (common in scripts)
iters = [1000, 4096, 10000, 20000, 50000]
salts = [("s[:8]", s[:8]), ("s[12:20]", s[12:20]), ("s[:16]", s[:16]), ("s", s)]
for salt_name, salt in salts:
    for rounds in iters:
        for hname, hmod in [("sha1", SHA1), ("sha256", SHA256)]:
            key16 = PBKDF2(PW, salt, dkLen=16, count=rounds, hmac_hash_module=hmod)
            # use iv from start-derived
            iv = hashlib.sha256(start).digest()[:16]
            for skip in (0, 16, 32, 64, 128):
                # CTR nonce from start slices
                for n_name, n in chunks.items():
                    if len(n) > 15: continue
                    try:
                        pt = aes_try(key16, "CTR", n, None, skip)
                        consider(f"pbkdf2_{salt_name}_r{rounds}_{hname}_aesctr_nonce{n_name}_skip{skip}", pt)
                    except Exception:
                        pass

                # OFB/CFB with derived iv
                for mode in ("CFB","OFB"):
                    try:
                        pt = aes_try(key16, mode, iv, None, skip)
                        consider(f"pbkdf2_{salt_name}_r{rounds}_{hname}_aes{mode.lower()}_ivsha256(start)_skip{skip}", pt)
                    except Exception:
                        pass

sc, label, extra, pt = best_global
print("[*] BEST SCORE:", sc)
print("[*] BEST LABEL:", label)
open("best_guess.zip", "wb").write(pt)
print("[*] wrote best_guess.zip")
print("[*] first 64 bytes:")
print(pt[:64].hex())
