import struct

target = bytes.fromhex(
    '660c4c86a62c1c9c1c661c2c9c6ca6cc'
    'a66c6caca6a6864c2c46ec8cec468c9c'
    '4cecc6664c46864cd2'
)

def bit_reverse_32(n):
    n &= 0xFFFFFFFF
    n = ((n & 0xAAAAAAAA) >> 1) | ((n & 0x55555555) << 1)
    n = ((n & 0xCCCCCCCC) >> 2) | ((n & 0x33333333) << 2)
    n = ((n & 0xF0F0F0F0) >> 4) | ((n & 0x0F0F0F0F) << 4)
    n = ((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)
    n = ((n >> 16) | (n << 16)) & 0xFFFFFFFF
    return n

result = bytearray(target)
for j in range(10):
    word = struct.unpack_from('<I', result, j*4)[0]
    struct.pack_into('<I', result, j*4, bit_reverse_32(word))

registration_key = result[:40].decode('ascii')
print(f"Registration key: {registration_key}")
print(f"Flag: DH{{{registration_key}}}")
