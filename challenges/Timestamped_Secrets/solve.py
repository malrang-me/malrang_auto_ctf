from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ciphertext = bytes.fromhex("24823b2b2d104b36ad2078cafc8d98f22488e78df83b29f507d9b910ad51a464")
hint_timestamp = 1770242615

# Try timestamps around the hint
for ts in range(hint_timestamp - 100, hint_timestamp + 100):
    key = sha256(str(ts).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        if b"picoCTF" in pt:
            print(f"Timestamp: {ts}")
            print(f"Flag: {pt.decode()}")
            break
    except:
        pass
