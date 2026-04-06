#!/usr/bin/env python3
"""Crypto oracle interaction framework for CTF challenges.

Provides base class and implementations for:
- RSA LSB/parity oracle attack
- CBC padding oracle (Vaudenay) attack

Usage: Copy to challenge dir, customize query() for the target protocol.
Requires: pwntools (pip install pwntools)
"""

from pwn import *
from decimal import Decimal, getcontext
import sys

# High precision for RSA parity oracle binary search
getcontext().prec = 1024


class OracleBase:
    """Base class for crypto oracle interactions."""

    def __init__(self, host: str, port: int, verbose: bool = False):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.conn = None

    def connect(self):
        """Establish connection to remote oracle."""
        if self.conn is not None:
            self.close()
        self.conn = remote(self.host, self.port)
        if self.verbose:
            log.info(f"Connected to {self.host}:{self.port}")
        return self.conn

    def query(self, data: bytes) -> bool:
        """Send data to oracle and return True/False response.

        Override this method for your specific challenge protocol.
        Must return True if oracle indicates valid/even, False otherwise.
        """
        raise NotImplementedError("Override query() for your challenge protocol")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None


class RSAParityOracle(OracleBase):
    """RSA LSB/parity oracle attack via multiplicative homomorphism.

    Given E(m), we send E(m * 2^k) = E(m) * (2^k)^e mod n.
    The oracle reveals LSB(m * 2^k mod n), allowing binary search on m.
    """

    def query(self, ct_bytes: bytes) -> bool:
        """Send ciphertext, return True if plaintext is even (LSB=0).

        Override this for your specific protocol. Example:
            self.conn.sendline(ct_bytes.hex())
            resp = self.conn.recvline().strip()
            return b'even' in resp or b'0' in resp
        """
        raise NotImplementedError(
            "Override query() to match your oracle's protocol.\n"
            "Return True if plaintext is EVEN (LSB=0), False if ODD (LSB=1)."
        )

    def attack(self, n: int, e: int, ct: int) -> int:
        """Recover plaintext via RSA parity oracle.

        Args:
            n: RSA modulus
            e: RSA public exponent
            ct: Ciphertext as integer

        Returns:
            Recovered plaintext as integer
        """
        if self.conn is None:
            self.connect()

        nbits = n.bit_length()
        log.info(f"RSA parity oracle: {nbits}-bit modulus, need ~{nbits} queries")

        # Binary search bounds using Decimal for precision
        lo = Decimal(0)
        hi = Decimal(n)
        multiplier = pow(2, e, n)
        current_ct = ct

        for i in range(nbits):
            # ct' = ct * 2^e mod n  (encrypts 2*m mod n)
            current_ct = (current_ct * multiplier) % n
            ct_bytes = current_ct.to_bytes((current_ct.bit_length() + 7) // 8, 'big')

            is_even = self.query(ct_bytes)

            # If 2^(i+1) * m mod n is even, then 2^(i+1)*m < n (no wraparound)
            # so m < n/2^(i+1) from current perspective
            mid = (lo + hi) / 2
            if is_even:
                hi = mid
            else:
                lo = mid

            if self.verbose and i % 64 == 0:
                log.info(f"  bit {i}/{nbits}")

        plaintext = int(hi)
        log.success(f"Recovered plaintext: {plaintext}")
        return plaintext


class CBCPaddingOracle(OracleBase):
    """Vaudenay CBC padding oracle attack.

    Decrypts CBC ciphertext by exploiting a padding validity oracle.
    Processes one block at a time, right to left within each block.
    """

    def query(self, data: bytes) -> bool:
        """Send IV+ciphertext, return True if padding is valid.

        Override this for your specific protocol. Example:
            self.conn.sendline(data.hex())
            resp = self.conn.recvline().strip()
            return b'ok' in resp or b'valid' in resp or b'1' in resp
        """
        raise NotImplementedError(
            "Override query() to match your oracle's protocol.\n"
            "Return True if padding is VALID, False otherwise."
        )

    def _decrypt_block(self, prev_block: bytes, target_block: bytes,
                       block_size: int) -> bytes:
        """Decrypt a single block using padding oracle."""
        # intermediate[i] = Dec_k(target_block)[i] (before XOR with prev)
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            pad_value = block_size - byte_pos  # desired padding byte

            # Build prefix: random bytes for positions before byte_pos
            prefix = bytearray(os.urandom(byte_pos))

            # Build suffix: XOR intermediate with desired padding for known bytes
            suffix = bytearray(
                intermediate[j] ^ pad_value
                for j in range(byte_pos + 1, block_size)
            )

            found = False
            for guess in range(256):
                # Construct manipulated previous block
                crafted = prefix + bytes([guess]) + bytes(suffix)
                payload = bytes(crafted) + target_block

                if self.query(payload):
                    # Verify it's the right padding byte (not accidental match)
                    if byte_pos > 0 and pad_value == 1:
                        # Flip a prior byte to confirm
                        verify = bytearray(crafted)
                        verify[byte_pos - 1] ^= 1
                        if not self.query(bytes(verify) + target_block):
                            continue

                    intermediate[byte_pos] = guess ^ pad_value
                    found = True
                    break

            if not found:
                log.error(f"Failed to find byte at position {byte_pos}")
                raise RuntimeError(f"Padding oracle failed at position {byte_pos}")

        # plaintext = intermediate XOR original prev_block
        plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(block_size))
        return plaintext

    def attack(self, iv: bytes, ct: bytes, block_size: int = 16) -> bytes:
        """Decrypt full CBC ciphertext via padding oracle.

        Args:
            iv: Initialization vector
            ct: Ciphertext (without IV)
            block_size: Block size in bytes (default 16 for AES)

        Returns:
            Decrypted plaintext (with padding)
        """
        import os

        if self.conn is None:
            self.connect()

        assert len(ct) % block_size == 0, "Ciphertext length must be multiple of block_size"
        num_blocks = len(ct) // block_size
        log.info(f"CBC padding oracle: {num_blocks} blocks, {num_blocks * block_size * 256} queries worst case")

        blocks = [iv] + [ct[i:i + block_size] for i in range(0, len(ct), block_size)]
        plaintext = b""

        for i in range(1, len(blocks)):
            log.info(f"  Decrypting block {i}/{num_blocks}")
            pt_block = self._decrypt_block(blocks[i - 1], blocks[i], block_size)
            plaintext += pt_block

        # Remove PKCS7 padding
        pad_len = plaintext[-1]
        if 1 <= pad_len <= block_size and plaintext[-pad_len:] == bytes([pad_len]) * pad_len:
            plaintext = plaintext[:-pad_len]

        log.success(f"Decrypted {len(plaintext)} bytes")
        return plaintext


# ============================================================
# Usage Example (uncomment and customize for your challenge)
# ============================================================
#
# class MyOracle(RSAParityOracle):
#     def query(self, ct_bytes):
#         self.conn.sendlineafter(b'> ', ct_bytes.hex().encode())
#         resp = self.conn.recvline()
#         return b'even' in resp
#
# if __name__ == '__main__':
#     HOST = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
#     PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
#
#     oracle = MyOracle(HOST, PORT, verbose=True)
#     oracle.connect()
#     # Read n, e, ct from server...
#     # n = int(oracle.conn.recvline())
#     # e = int(oracle.conn.recvline())
#     # ct = int(oracle.conn.recvline())
#     # plaintext = oracle.attack(n, e, ct)
#     # print(long_to_bytes(plaintext))
#     oracle.close()
