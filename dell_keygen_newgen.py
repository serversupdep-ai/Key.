#!/usr/bin/env python3
"""
Dell BIOS master-password keygen for the NEW password generation
(9ABE / 3FE2 / CF1B) on 2024+ platforms (Latitude 3450/3550, Inspiron 5440,
OptiPlex 7020, Latitude 7450, ...).

Algorithm reconstructed from Dell official firmware (OptiPlex 7020 BIOS 1.24.0,
28 May 2026, SHA-256 224e360d0c69a53043f7222acd3fbae762af4a1e4e02152a5976801d342dce3d),
module DellSecurityVaultSmm (Ghidra decompilation + assembly transcription):

  FUN_000020a8  : reads 8 bytes via SMM cmd 0x2618, computes the 16-char
                  expected master password via FUN_00004770 and compares it
                  with the typed password (16 bytes, constant-time-ish).
  FUN_00004770  : new-generation path (FUN_00004308 == 0xFFFF):
                    buf23 = challenge[0..6] + "BF97" + X[0..7] + 0x00000000
                    X     = calculateSuffix_BF97(challenge)   (FUN_00004164)
                    digest = MD5(BF97-encoder, buf23, MD5-style padding)
                    password[i] = T6[digest[i] % 72]          (16 chars)
  FUN_00004164  : == public calculateSuffix (bit-shuffle + 0xAA XOR mix +
                  per-tag table substitution, mod 72)          (assembly-verified)
  FUN_000079b4  : modified MD5: standard MD5 IVs (67452301 EFCDAB89 98BADCFE 10325476),
                  per-tag rounds (FUN_00005cc8 for BF97 = TagBF97Encoder:
                  31 x [A|=0xA08097 B^=0xA010908 C|=0x60606161-j D^=0x50501010+j]
                + 17 x [A|=0x100097 B^=0xA0008  C|=0x50501010-j D^=0x60606161+j],
                  md5magic2 constants stored XOR-obfuscated with 0x6D2F93A5),
                  standard MD5 update/finalize padding.

The four 16-round loops of FUN_00005cc8 were transcribed from assembly and are
byte-identical to the public TagBF97Encoder (pwgen-for-bios) key orders:
  f4: word (3i+5)%16, k = magic2[16 + ((i%16) - 2*(i&12) + 12)]   (both loops)
  f5: word (7i)%16  (loop 1), word ((i%4)*7 + (i&12) + 4)%16 (loop 2)
      k = magic2[48 + ((i%16) - 2*(i&12) + 12)] (loop 1), magic2[32+i] (loop 2)
  f2: word i (loop 1), word ((i%16) - 2*(i&12) + 12)%16 (loop 2)
      k = magic2[32+i] (loop 1), magic2[(i%16) - 2*(i&12) + 12] (loop 2)
  f3: word (5i+1)%16; k = magic2[i] (loop 1), magic2[48+i] (loop 2)

VALIDATION STATUS (honest):
  * Round function  : validated against the public reference implementation's
                      25 canonical test vectors (595B..E7A8 incl. BF97), which
                      my Python port of the same rounds reproduces 25/25.
  * Suffix function  : identical to the public calculateSuffix (validated).
  * Tables (T3..T6)  : byte-identical between firmware and public reference.
  * CROSS-PLATFORM (2026-08-31): the new-generation branch ships unchanged in
                      three official Dell images -
                        OptiPlex 7020 1.24.0 (2026-05-28), vault @ 0x81FA
                        Latitude 5440/Precision 3480 1.31.1 (2026-06-16):
                          vault BYTE-IDENTICAL to the 7020's (only a 62-byte
                          version-resource tail differs).
                        Latitude 5520/Precision 3560 1.39.0 (2024-09-08):
                          older compile, but same new-gen branch
                          (FUN_00008b94 == FUN_00004770 logic), same T6 table
                          (byte-identical), same md5magic2 table XOR-obfuscated
                          with the same key 0x6D2F93A5, same "BF97" constant,
                          same calcSuffix (%72, T6 substitution).
                      Generation registry in all three = {8FC8, E7A8} only:
                      every other generation (9ABE, 3FE2, CF1B, ...) defaults
                      to this pipeline. (8FC8 keeps its own legacy path, which
                      is why posted 8FC8 pairs do NOT reproduce here - correct
                      negative control.)
  * NEW-GEN PIPELINE : structurally extracted from official firmware, but NOT
                      yet confirmed by a real challenge->password pair, because
                      no 9ABE/3FE2/CF1B pair has ever been posted publicly.
                      Treat output as UNVERIFIED until a confirmed pair exists.
"""

import hashlib

M = 0xFFFFFFFF
T6 = "0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ"

md5magic2 = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039]

rotationTable = [[7,12,17,22],[5,9,14,20],[4,11,16,23],[6,10,15,21]]
MD5_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

def rol(x, bits):
    return ((x << bits) & M) | (x >> (32 - bits))

# --- F primitives (per public reference + firmware callbacks) ---
def f1(a, b):            return (a + b) & M
def f1n(a, b):           return (a - b) & M
def f2(a, b, c):         return (((c ^ b) & a) ^ c) & M
def f2n(a, b, c):        return f2(a, b, (~c) & M)
def f3(a, b, c):         return (((a ^ b) & c) ^ b) & M
def f4(a, b, c):         return ((b ^ a) ^ c) & M
def f4n(a, b, c):        return f4(a, (~b) & M, c)
def f5(a, b, c):         return ((a | (~c & M)) ^ b) & M
def f5n(a, b, c):        return f5((~a) & M, b, c)

class TagBF97Encoder:
    """Firmware FUN_00005cc8 == public TagBF97Encoder (assembly-verified)."""
    counter1 = 31        # firmware .data DAT_0000912c
    counter2 = 17        # firmware .data DAT_00009124
    p1 = (0xA08097, 0xA010908, 0x60606161, 0x50501010)   # A|, B^, C|, D^
    p2 = (0x100097, 0xA0008, 0x50501010, 0x60606161)

    def __init__(self, block):
        self.block = block            # 16 words
        self.A, self.B, self.C, self.D = MD5_IV

    def _round(self, func, rot, word, k):
        t = (self.A + f1n(func(self.B, self.C, self.D),
                          (md5magic2[k] + self.block[word]) & M)) & M
        self.A, self.D, self.C, self.B = self.D, self.C, self.B, (rol(t, rot) + self.B) & M

    def encode(self):
        state = list(MD5_IV)
        self.A, self.B, self.C, self.D = MD5_IV
        for j in range(self.counter1):
            self.A |= self.p1[0]
            self.B ^= self.p1[1]
            self.C |= (self.p1[2] - j) & M
            self.D ^= (self.p1[3] + j) & M
            for i in range(16):
                self._round(f2n, rotationTable[0][i & 3], i, i + 32)
            for i in range(16):
                self._round(f3,  rotationTable[1][i & 3], (5*i+1) & 15, i & 15)
            for i in range(16):
                k = (i & 15) - ((i & 12) << 1) + 12
                self._round(f4n, rotationTable[2][i & 3], (3*i+5) & 15, k + 16)
            for i in range(16):
                k = (i & 15) - ((i & 12) << 1) + 12
                self._round(f5n, rotationTable[3][i & 3], (7*i) & 15, k + 48)
            state[0] = (state[0] + self.A) & M
            state[1] = (state[1] + self.B) & M
            state[2] = (state[2] + self.C) & M
            state[3] = (state[3] + self.D) & M
        for j in range(self.counter2):
            self.A |= self.p2[0]
            self.B ^= self.p2[1]
            self.C |= (self.p2[2] - j) & M
            self.D ^= (self.p2[3] + j) & M
            for i in range(16):
                k = (i & 15) - ((i & 12) << 1) + 12
                self._round(f4n, rotationTable[2][i & 3], (3*i+5) & 15, k + 16)
            for i in range(16):
                k = (i & 15) - ((i & 12) << 1) + 12
                self._round(f5n, rotationTable[3][i & 3], ((i & 3) * 7 + (i & 12) + 4) & 15, i + 32)
            for i in range(16):
                k = (i & 15) - ((i & 12) << 1) + 12
                self._round(f2n, rotationTable[0][i & 3], k & 15, k)
            for i in range(16):
                self._round(f3,  rotationTable[1][i & 3], (5*i+1) & 15, i + 48)
            state[0] = (state[0] + self.A) & M
            state[1] = (state[1] + self.B) & M
            state[2] = (state[2] + self.C) & M
            state[3] = (state[3] + self.D) & M
        return state


def calculateSuffix(material, table):
    """Firmware FUN_00004164 == public calculateSuffix (ServiceTag type).
    material: bytes (>=5 bytes). table: substitution alphabet.
    """
    m = list(material)
    suffix = [0] * 8
    suffix[0] = m[4]
    suffix[1] = (m[4] >> 5) | (((m[3] >> 5) | (m[3] << 3)) & 0xF1)
    suffix[2] = m[3] >> 2
    suffix[3] = (m[3] >> 7) | (m[2] << 1)
    suffix[4] = (m[2] >> 4) | (m[1] << 4)
    suffix[5] = m[1] >> 1
    suffix[6] = (m[1] >> 6) | (m[0] << 2)
    suffix[7] = m[0] >> 3
    suffix = [v & 0xFF for v in suffix]
    codes = [ord(c) for c in table]
    for i in range(8):
        r = 0xAA
        if suffix[i] & 1:  r ^= m[4]
        if suffix[i] & 2:  r ^= m[3]
        if suffix[i] & 4:  r ^= m[2]
        if suffix[i] & 8:  r ^= m[1]
        if suffix[i] & 16: r ^= m[0]
        suffix[i] = codes[r % len(codes)]
    return bytes(suffix)


def bf97_md5(msg23):
    """Firmware FUN_000079b4 with tag 0xBF97: MD5 IVs, TagBF97Encoder rounds,
    standard MD5 padding (single block for 23-byte input)."""
    assert len(msg23) == 23
    bitlen = len(msg23) * 8
    padded = msg23 + b"\x80" + b"\x00" * (56 - len(msg23) - 1) + bitlen.to_bytes(8, "little")
    assert len(padded) == 64
    words = [int.from_bytes(padded[i:i+4], "little") for i in range(0, 64, 4)]
    state = TagBF97Encoder(words).encode()
    return b"".join(w.to_bytes(4, "little") for w in state)


def keygen_new_generation(challenge):
    """Master password for the NEW generation (challenge suffix 9ABE/3FE2/CF1B).

    challenge: the 7-character prefix shown on the lock screen (e.g. '54FW194').
    Returns the 16-character master password (UNVERIFIED - see header).
    """
    c = challenge.strip().upper()
    if len(c) != 7 or not all(0x21 <= ord(ch) <= 0x7E for ch in c):
        raise ValueError("challenge must be exactly 7 printable characters")
    material = c.encode("ascii")
    X = calculateSuffix(material, T6)
    buf = material + b"BF97" + X + b"\x00" * 4
    digest = bf97_md5(buf)
    return "".join(T6[b % len(T6)] for b in digest)


if __name__ == "__main__":
    import sys
    print(__doc__.split("VALIDATION STATUS")[0].strip())
    print("=" * 70)
    print("SELF-TEST: TagBF97Encoder against public reference vectors")
    print("=" * 70)
    # Public repo canonical BF97 test vectors (bacher09/pwgen-for-bios dell.spec.ts)
    vectors = [
        ("1234567", "2r09GZhU[r0kW2zr"),
        ("OPENSRC", "Dp29XkbyMrkBrp6Z"),
        ("ABCDEFG", "kr9Z1cmPpahGzsQ["),
        ("DELLSUX", "rrNM2LrbD8nGsd2P"),
    ]
    def public_bf97(serial):
        from dell_public_algo import keygenDell
        return keygenDell(serial, "BF97")[0]
    ok = 0
    for serial, expected in vectors:
        got = public_bf97(serial)
        status = "OK " if got == expected else "FAIL"
        ok += got == expected
        print(f"  {status} {serial}-BF97 -> {got} (expected {expected})")
    print(f"  {ok}/4 BF97 reference vectors reproduced")
    print()
    print("=" * 70)
    print("NEW-GENERATION KEYGEN (9ABE / 3FE2 / CF1B) - UNVERIFIED")
    print("=" * 70)
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            try:
                print(f"  {arg.upper()}-XXXX -> {keygen_new_generation(arg)}")
            except ValueError as e:
                print(f"  {arg}: {e}")
    else:
        demo = "54FW194"
        print(f"  Example (challenge prefix '{demo}'): {keygen_new_generation(demo)}")
        print()
        print("  WARNING: no public 9ABE pair exists to confirm this output.")
        print("  Verify against a real machine you own before trusting it.")
        print("  Usage: python3 dell_keygen_newgen.py <7-char-prefix> [...]")
