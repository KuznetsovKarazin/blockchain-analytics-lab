"""Independent two-dimensional sponge oracle for the phase 9 offline audit.

Rotation offsets and round constants are generated, unlike the producer's
table-based implementation. The permutation is checked against stdlib SHA3-256
with domain 0x06 before the Ethereum domain 0x01 is used. Not cryptographic
library certification and not a verification of RPC Merkle proofs.
"""
import hashlib
import random


def digest256(message, domain=1):
    mask = (1 << 64) - 1
    rotation = {(0, 0): 0}
    x, y = 1, 0
    for t in range(24):
        rotation[x, y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    constants = []
    lfsr = 1
    for _ in range(24):
        rc = 0
        for j in range(7):
            if lfsr & 1:
                rc ^= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ (0x71 if lfsr & 0x80 else 0)) & 255
        constants.append(rc)
    padded = bytearray(message)
    padded.append(domain)
    padded.extend(bytes((-len(padded)) % 136))
    padded[-1] ^= 128
    state = [[0 for _ in range(5)] for _ in range(5)]
    def rotate(value, n):
        return ((value << n) | (value >> ((64 - n) % 64))) & mask
    for offset in range(0, len(padded), 136):
        for lane in range(17):
            state[lane % 5][lane // 5] ^= int.from_bytes(padded[offset + lane * 8:offset + lane * 8 + 8], "little")
        for rc in constants:
            parity = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            delta = [parity[(x - 1) % 5] ^ rotate(parity[(x + 1) % 5], 1) for x in range(5)]
            permuted = [[0 for _ in range(5)] for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    permuted[y][(2 * x + 3 * y) % 5] = rotate(state[x][y] ^ delta[x], rotation[x, y])
            for x in range(5):
                for y in range(5):
                    state[x][y] = permuted[x][y] ^ ((~permuted[(x + 1) % 5][y]) & permuted[(x + 2) % 5][y])
            state[0][0] ^= rc
    return b"".join(state[lane % 5][lane // 5].to_bytes(8, "little") for lane in range(4))


def verify_oracle():
    lengths = list(range(146)) + [271, 272, 273, 407, 408, 409, 1024, 6348, 22157]
    rng = random.Random(9262026)
    for length in lengths:
        message = rng.randbytes(length)
        assert digest256(message, 6) == hashlib.sha3_256(message).digest(), length
    assert digest256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert digest256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    return {"sha3_stdlib_vectors": len(lengths), "ethereum_known_vectors": 2, "seed": 9262026}


if __name__ == "__main__":
    print(verify_oracle())
