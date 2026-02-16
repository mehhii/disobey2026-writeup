def reverse_transformed_key(output_bytes):
    result = []
    running_xor = 0

    for i, expected in enumerate(output_bytes):
        found = False
        for b in range(0x00, 0x100):
            if i % 2 == 0:
                transformed = b | 0x80
            else:
                transformed = (b - 0x20) & 0xFF

            trial = running_xor ^ (~transformed & 0xFF) ^ i
            if trial == expected:
                result.append(b)
                running_xor = trial
                found = True
                break

        if not found:
            print(f"Failed at byte {i}")
            return None

    return bytes(result)

# Expected output bytes from DAT_ram_455f
expected_output = bytes([
    0x49, 0xA5, 0xEB, 0x0E, 0x13, 0xFE, 0xB1, 0x5F,
    0x1B, 0xFF, 0xBE, 0x52, 0x19, 0xF3, 0xE1, 0x01,
    0x0F, 0xF8, 0xAC, 0x57, 0x0C, 0xFE, 0xA3, 0x58,
    0x59, 0xFA, 0xA9, 0x55, 0x57, 0xA3, 0xFA, 0x5B
])

key = reverse_transformed_key(expected_output)
if key:
    print("Recovered Activation Key:", key.decode('ascii', errors='replace'))
else:
    print("Reversal failed.")