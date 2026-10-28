import std/unittest
import lz4/private/xxhash32
import datagen

proc pattern(n: int): seq[byte] =
  # uint wraps instead of overflowing on 32-bit systems; the low 8 bits,
  # all that is kept, are the same.
  for i in 0'u ..< uint(n):
    result.add byte(((i * 7 + 3) * (i shr 3) + i) and 0xFF)

suite "XXH32":
  test "specification vectors":
    check xxh32(toBytes("")) == 0x02CC5D05'u32
    check xxh32(toBytes("abc")) == 0x32D153FF'u32
    check xxh32(toBytes("Nobody inspects the spammish repetition")) == 0xE2293B2F'u32

  test "vectors from xxh32sum (every tail length class)":
    const vectors = [
      (1, 0xcf65b03e'u32),
      (4, 0x80691e66'u32),
      (15, 0xc9c92844'u32),
      (16, 0x24242273'u32),
      (17, 0x6b326d88'u32),
      (31, 0x66c06db4'u32),
      (32, 0xbebd20cc'u32),
      (33, 0xbb072bed'u32),
      (64, 0xde876f87'u32),
      (100, 0x78a041f0'u32),
      (1000, 0xdc69d706'u32),
      (4096, 0x10a7b5be'u32),
      (100003, 0x68e6f055'u32),
    ]
    for (n, h) in vectors:
      check xxh32(pattern(n)) == h

  test "seeds (xxh32sum -s)":
    const vectors = [
      (0, 0x36b78ae7'u32, 0x0b2cb792'u32),
      (3, 0x24302793'u32, 0xb5a3bb4a'u32),
      (16, 0xc34d70d8'u32, 0x6ddf6c35'u32),
      (100, 0x76150a15'u32, 0x2171862e'u32),
    ]
    for (n, h1, h2) in vectors:
      check xxh32(pattern(n), 2654435761'u32) == h1
      check xxh32(pattern(n), 1) == h2
      var s = initXxh32(1)
      s.update(pattern(n))
      check s.digest() == h2

  test "streaming in any chunking equals one-shot":
    var r = initRng(41)
    for n in [0, 1, 15, 16, 17, 47, 48, 49, 1000, 70_000]:
      let data = randomBytes(n, uint64(n) + 1)
      let expected = xxh32(data)
      for trial in 0 ..< 20:
        var s = initXxh32()
        var p = 0
        while p < n:
          let k = min(
            n - p,
            if trial == 0:
              1
            else:
              r.below(40),
          )
          s.update(data.toOpenArray(p, p + k - 1))
          p += k
        check s.digest() == expected
        # digest does not change the state.
        check s.digest() == expected

  test "the safe and the fast versions agree":
    var r = initRng(42)
    for i in 0 ..< 2000:
      let data = randomBytes(r.below(300), r.next())
      let seed = uint32(r.next() and 0xFFFF_FFFF'u64)
      check xxh32Safe(data, seed) == xxh32Fast(data, seed)
      check xxh32(data, seed) == xxh32Safe(data, seed)
