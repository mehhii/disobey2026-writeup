key_hex = "<KEY HERE>"
key = bytes.fromhex(key_hex)

encrypted_hex = """
<FULL PAYLOAD HERE>
"""

# Convert the hex string to a byte array
encrypted_bytes = bytes(int(b, 16) for b in encrypted_hex.strip().split())

# XOR decryption
decrypted = bytearray()
for i in range(len(encrypted_bytes)):
    decrypted.append(encrypted_bytes[i] ^ key[i % len(key)])

with open("stage2.bin", "wb") as f:
    f.write(decrypted)