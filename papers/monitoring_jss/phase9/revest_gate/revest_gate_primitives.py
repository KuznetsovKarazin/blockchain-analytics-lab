"""Small dependency-free Ethereum Keccak/slot helpers; not SHA3-256."""
MASK = (1 << 64) - 1
ROUNDS = [0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK

def keccak256(data):
    if not isinstance(data, bytes):
        raise TypeError("bytes required")
    padded = bytearray(data)
    padded.append(1)
    padded.extend(b"\0" * ((-len(padded)) % 136))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        block = padded[offset:offset+136]
        for i in range(17):
            state[i] ^= int.from_bytes(block[8*i:8*i+8], "little")
        for rc in ROUNDS:
            c = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
            d = [c[(x-1)%5] ^ rol(c[(x+1)%5], 1) for x in range(5)]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y+5*((2*x+3*y)%5)] = rol(state[x+5*y] ^ d[x], ROT[x][y])
            for x in range(5):
                for y in range(5):
                    state[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
            state[0] ^= rc
    return b"".join(x.to_bytes(8, "little") for x in state)[:32]

def registry_keys(names, dex_count=8):
    result = {"owner": "0x" + (0).to_bytes(32,"big").hex(), "next_dex": "0x" + (1).to_bytes(32,"big").hex()}
    for name in names:
        key = name.encode("ascii").ljust(32, b"\0")
        if len(key) != 32:
            raise ValueError("invalid bytes32 mapping name")
        result[name] = "0x" + keccak256(key + (2).to_bytes(32, "big")).hex()
    for index in range(dex_count):
        result["dex_" + str(index)] = "0x" + keccak256(index.to_bytes(32,"big") + (3).to_bytes(32,"big")).hex()
    return result

def selftest():
    vectors = {b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"}
    for data, expected in vectors.items():
        assert keccak256(data).hex() == expected
    assert keccak256(b"owner()").hex()[:8] == "8da5cb5b"
    assert keccak256(b"transfer(address,uint256)").hex()[:8] == "a9059cbb"
    return True

if __name__ == "__main__":
    selftest()
    print("Keccak known-vector checks passed")
