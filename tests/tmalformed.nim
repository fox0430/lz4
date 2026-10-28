## Hand-made invalid inputs, and the error kind each one must raise.

import std/[strutils, unittest]
import lz4, lz4/private/xxhash32
import datagen, blockutil, errorcheck

proc blockOf(parts: varargs[seq[byte]]): seq[byte] =
  for p in parts:
    result.add p

suite "malformed blocks":
  test "0-byte block":
    expectKind ekMalformed:
      discard decompressBlock([], 100)
    var dst: array[16, byte]
    expectKind ekMalformed:
      discard decompressBlockInto([], dst)

  test "block ending with a match (termination rule 1)":
    let blk = seqBytes([1'u8, 2, 3, 4], 4, 8)
    expectKind ekMalformed:
      discard decompressBlock(blk, 1000)
    var dst: array[100, byte]
    expectKind ekMalformed:
      discard decompressBlockInto(blk, dst)

  test "offset 0":
    let blk = blockOf(seqBytes([1'u8, 2, 3, 4], 0, 8), seqBytes([], 0, 0, last = true))
    try:
      discard decompressBlock(blk, 1000)
      fail()
    except Lz4Error as e:
      check e.kind == ekMalformed
      check "offset 0" in e.msg

  test "offset before the start of the output":
    for (nlit, offset) in [(0, 1), (4, 5), (4, 65535), (100, 101)]:
      let blk =
        blockOf(seqBytes(randomBytes(nlit), offset, 8), seqBytes([], 0, 0, last = true))
      expectKind ekMalformed:
        discard decompressBlock(blk, 1000)
      var dst: array[1000, byte]
      expectKind ekMalformed:
        discard decompressBlockInto(blk, dst)

  test "literals running past the end of the input":
    var blk = seqBytes(randomBytes(20), 0, 0, last = true)
    for cut in 1 ..< blk.len:
      expectKind ekMalformed:
        discard decompressBlock(blk.toOpenArray(0, cut - 1), 1000)
    # A literal length far beyond the input, with many extension bytes.
    var huge = @[0xF0'u8]
    for _ in 0 ..< 100:
      huge.add 255
    huge.add 0
    expectKind ekMalformed:
      discard decompressBlock(huge, high(int))

  test "truncated offset and match length":
    let full =
      blockOf(seqBytes([1'u8, 2, 3, 4], 4, 300), seqBytes([5'u8], 0, 0, last = true))
    # Cut inside the offset or the match length extension (the token of the
    # last sequence would otherwise be the end).
    for cut in 5 .. 7:
      expectKind ekMalformed:
        discard decompressBlock(full.toOpenArray(0, cut), 1000)

  test "an invalid block gives the same error whatever the output size":
    # Both decode past 2000 bytes before they turn out invalid: one ends
    # with a match, the other has a match before the start of the data.
    # They used to give ekLimitExceeded or ekOutputTooSmall below that.
    let endsWithMatch = seqBytes([1'u8, 2, 3, 4], 4, 3000)
    let badOffset = blockOf(
      seqBytes([1'u8, 2, 3, 4], 4, 3000),
      seqBytes([5'u8], 5000, 4),
      seqBytes([6'u8], 0, 0, last = true),
    )
    let dict = textLike(100)
    for blk in [endsWithMatch, badOffset]:
      for limit in [high(int), 2000]:
        expectKind ekMalformed:
          discard decompressBlock(blk, limit)
        expectKind ekMalformed:
          discard decompressBlock(blk, dict, limit)
      for size in [10_000, 2000]:
        var dst = newSeq[byte](size)
        expectKind ekMalformed:
          discard decompressBlockInto(blk, dst)
        expectKind ekMalformed:
          discard decompressBlockInto(blk, dict, dst)

  test "match running past the output":
    let blk =
      blockOf(seqBytes([1'u8, 2, 3, 4], 4, 100), seqBytes([9'u8], 0, 0, last = true))
    expectKind ekLimitExceeded:
      discard decompressBlock(blk, 104)
    var dst: array[104, byte]
    expectKind ekOutputTooSmall:
      discard decompressBlockInto(blk, dst)

  test "huge match length cannot overflow":
    var blk = @[0x1F'u8, 7, 1, 0]
    for _ in 0 ..< 10_000:
      blk.add 255
    blk.add 0
    blk.add 0x10
    blk.add 9
    expectKind ekLimitExceeded:
      discard decompressBlock(blk, 1000)
    var dst: array[1000, byte]
    expectKind ekOutputTooSmall:
      discard decompressBlockInto(blk, dst)
    when sizeof(int) == 4:
      # Without a limit, a length beyond high(int) (about 8.4 MB of 255s)
      # must be reported, not overflow.
      var long = @[0x1F'u8, 7, 1, 0]
      for _ in 0 ..< 8_421_600:
        long.add 255
      long.add [0'u8, 0x10, 9]
      expectKind ekLimitExceeded:
        discard decompressBlock(long, high(int))
      expectKind ekLimitExceeded:
        discard decompressBlock(long, [1'u8, 2, 3], high(int))

  test "negative maxOutputSize":
    expectKind ekInvalidArgument:
      discard decompressBlock([0x00'u8], -1)

  test "bad offsets are reported before the length check":
    # The length scan of decompressBlock checks offsets too, so it agrees
    # with decompressBlockInto, and nothing is allocated for an invalid block.
    var zero = @[0x1F'u8, 7, 0, 0]
    for _ in 0 ..< 10:
      zero.add 255
    zero.add [0'u8, 0x00]
    try:
      discard decompressBlock(zero, 1000)
      fail()
    except Lz4Error as e:
      check e.kind == ekMalformed
      check "offset 0" in e.msg
    var far = @[0x1F'u8, 7, 2, 0]
    for _ in 0 ..< 10:
      far.add 255
    far.add [0'u8, 0x00]
    expectKind ekMalformed:
      discard decompressBlock(far, 1000)
    var dst: array[1000, byte]
    expectKind ekMalformed:
      discard decompressBlockInto(far, dst)
    # A huge match behind offset 0 must not allocate maxOutputSize first.
    var huge = @[0x1F'u8, 7, 0, 0]
    for _ in 0 ..< 4_000_000:
      huge.add 255
    huge.add [0'u8, 0x00]
    expectKind ekMalformed:
      discard decompressBlock(huge, 1 shl 30)

  test "block cut off inside a match length is malformed":
    var blk = @[0x1F'u8, 7, 1, 0]
    for _ in 0 ..< 10:
      blk.add 255
    expectKind ekMalformed:
      discard decompressBlock(blk, 1000)
    var dst: array[1000, byte]
    expectKind ekMalformed:
      discard decompressBlockInto(blk, dst)

proc rawBlock(data: openArray[byte]): seq[byte] =
  result = le32(uint32(data.len) or 0x8000_0000'u32)
  result.add data

proc frameWith(flg: byte, blocks: varargs[seq[byte]]): seq[byte] =
  ## A frame with BD = 64 KiB, the given blocks and an end mark (plus the
  ## content checksum of nothing when FLG asks for one... callers that care
  ## build the tail themselves).
  result = frameHeader(flg, 0x40)
  for b in blocks:
    result.add b
  result.add le32(0)

suite "malformed frames":
  let good = compressFrame(textLike(3000), FrameOptions(blockChecksum: true))

  test "unknown magic and trailing bytes":
    expectKind ekMalformed:
      discard decompressFrame([1'u8, 2, 3, 4], high(int))
    for extra in 1 .. 3:
      var s = good
      for i in 0 ..< extra:
        s.add 0
      expectKind ekMalformed:
        discard decompressFrame(s, high(int))
    var s = good
    s.add [1'u8, 2, 3, 4, 5, 6, 7, 8]
    expectKind ekMalformed:
      discard decompressFrame(s, high(int))

  test "truncated anywhere":
    let f = compressFrame(
      mixed(200_000), FrameOptions(blockChecksum: true, writeContentSize: true)
    )
    var r = initRng(51)
    for cut in [1, 3, 4, 5, 6, 10, 14, 15, 18, 19, 22, f.len - 5, f.len - 4, f.len - 1]:
      expectKind ekMalformed:
        discard decompressFrame(f.toOpenArray(0, cut - 1), high(int))
    for _ in 0 ..< 200:
      let cut = 1 + r.below(f.len - 1)
      expectKind ekMalformed:
        discard decompressFrame(f.toOpenArray(0, cut - 1), high(int))

  test "version, reserved bits and block size id":
    for flg in [0x00'u8, 0x80, 0xC0, 0x62]: # version 00, 10, 11; reserved bit 1
      expectKind ekMalformed:
        discard decompressFrame(frameWith(flg), high(int))
    for bd in [0x00'u8, 0x10, 0x20, 0x30, 0xC0, 0x41, 0x48, 0x4F]:
      var f = frameHeader(0x60, bd)
      f.add le32(0)
      expectKind ekMalformed:
        discard decompressFrame(f, high(int))

  test "header checksum mismatch":
    var f = frameWith(0x60)
    f[6] = f[6] xor 1
    expectKind ekChecksum:
      discard decompressFrame(f, high(int))

  test "block larger than the block maximum size":
    var f = frameHeader(0x60, 0x40)
    f.add le32(65537 or 0x8000_0000'u32)
    f.add newSeq[byte](65537)
    f.add le32(0)
    expectKind ekMalformed:
      discard decompressFrame(f, high(int))
    # Compressed, small when stored but larger than 64 KiB once decoded.
    var g = frameHeader(0x60, 0x40)
    let c = compressBlock(zeros(70_000))
    g.add le32(uint32(c.len))
    g.add c
    g.add le32(0)
    expectKind ekMalformed:
      discard decompressFrame(g, high(int))

  test "a limit does not change the error of an invalid block":
    # Each block decodes past the limit before it turns out invalid: larger
    # than 64 KiB once decoded, or a match before the start of the data.
    # They used to give ekLimitExceeded below the point of failure.
    let tooLarge = compressBlock(zeros(70_000))
    let badOffset = blockOf(
      seqBytes([1'u8, 2, 3, 4], 4, 3000),
      seqBytes([5'u8], 5000, 4),
      seqBytes([6'u8], 0, 0, last = true),
    )
    for blk in [tooLarge, badOffset]:
      var f = frameHeader(0x60, 0x40)
      f.add le32(uint32(blk.len))
      f.add blk
      f.add le32(0)
      for limit in [high(int), 2000]:
        expectKind ekMalformed:
          discard decompressFrame(f, limit)
    # A valid block over the limit is still ekLimitExceeded.
    let valid = compressBlock(zeros(60_000))
    var v = frameHeader(0x60, 0x40)
    v.add le32(uint32(valid.len))
    v.add valid
    v.add le32(0)
    expectKind ekLimitExceeded:
      discard decompressFrame(v, 2000)
    check decompressFrame(v, 60_000) == zeros(60_000)

  test "block, content checksum and content size mismatches":
    var f = good
    f[12] = f[12] xor 0x10 # inside the first block: block checksum
    expectKind ekChecksum:
      discard decompressFrame(f, high(int))
    let data = textLike(500)
    var h = frameHeader(0x64, 0x40)
    h.add rawBlock(data)
    h.add le32(0)
    h.add le32(xxh32(data) xor 1)
    expectKind ekChecksum:
      discard decompressFrame(h, high(int))
    for cs in [499'i64, 501, 1]:
      var g = frameHeader(0x68, 0x40, contentSize = cs)
      g.add rawBlock(data)
      g.add le32(0)
      expectKind ekMalformed:
        discard decompressFrame(g, high(int))

  test "independent blocks cannot refer to the previous block":
    let first = textLike(1000)
    var f = frameHeader(0x60, 0x40)
    f.add rawBlock(first)
    # A block made of one match into `first`.
    let blk = @[0x0F'u8, 0xE8, 0x03, 0x00, 0x00] # offset 1000, length 19
    f.add le32(uint32(blk.len))
    f.add blk
    f.add le32(0)
    expectKind ekMalformed:
      discard decompressFrame(f, high(int))
    # The same as linked blocks is fine.
    var g = frameHeader(0x40, 0x40)
    g.add rawBlock(first)
    g.add le32(uint32(blk.len))
    g.add blk
    g.add le32(0)
    check decompressFrame(g, high(int)).len == 1019

  test "a frame cannot refer to the previous frame":
    let blk = @[0x0F'u8, 0x0A, 0x00, 0x00, 0x00] # offset 10, length 19
    var s = compressFrame(textLike(100))
    var f = frameHeader(0x40, 0x40)
    f.add le32(uint32(blk.len))
    f.add blk
    f.add le32(0)
    s.add f
    expectKind ekMalformed:
      discard decompressFrame(s, high(int))

  test "a missing dictionary is ekUnsupported only with a Dict-ID":
    let blk = @[0x0F'u8, 0x0A, 0x00, 0x00, 0x00] # refers before the frame
    for (flg, kind) in [
      (0x61'u8, ekUnsupported),
      (0x41'u8, ekUnsupported),
      (0x60'u8, ekMalformed),
      (0x40'u8, ekMalformed),
    ]:
      var f =
        if (flg and 1) != 0:
          frameHeader(flg, 0x40, dictId = 7)
        else:
          frameHeader(flg, 0x40)
      f.add le32(uint32(blk.len))
      f.add blk
      f.add le32(0)
      expectKind kind:
        discard decompressFrame(f, high(int))
    # Offset 0 stays ekMalformed.
    var g = frameHeader(0x61, 0x40, dictId = 7)
    let z = @[0x0F'u8, 0x00, 0x00, 0x00, 0x00]
    g.add le32(uint32(z.len))
    g.add z
    g.add le32(0)
    expectKind ekMalformed:
      discard decompressFrame(g, high(int))

  test "truncated skippable frames, wherever they are":
    var skip = le32(0x184D2A50'u32)
    skip.add le32(100)
    skip.add newSeq[byte](10)
    var full = le32(0x184D2A51'u32)
    full.add le32(2)
    full.add [0'u8, 0]
    for prefix in [newSeq[byte](), full, good]:
      var s = prefix
      s.add skip
      expectKind ekMalformed:
        discard decompressFrame(s, high(int))
    var huge = le32(0x184D2A50'u32)
    huge.add le32(0xFFFF_FFFF'u32)
    expectKind ekMalformed:
      discard decompressFrame(huge, high(int))
    expectKind ekMalformed:
      discard decompressFrame(le32(0x184D2A50'u32) & @[1'u8, 0], high(int))

  test "legacy frames: empty block, oversized block, truncation":
    var f = le32(0x184C2102'u32)
    f.add le32(0)
    expectKind ekMalformed:
      discard decompressFrame(f, high(int))
    # The feed that reads the size rejects it: no more input completes it.
    var d = initFrameDecoder(high(int))
    var output: seq[byte]
    check d.feed(f, output) == 4
    expectKind ekMalformed:
      discard d.feed(f.toOpenArray(4, f.high), output)
    # More than 8 MiB once decoded.
    let c = compressBlock(zeros(8 * 1024 * 1024 + 1))
    var g = le32(0x184C2102'u32)
    g.add le32(uint32(c.len))
    g.add c
    expectKind ekMalformed:
      discard decompressFrame(g, high(int))
    var h = le32(0x184C2102'u32)
    h.add le32(100)
    h.add [1'u8, 2, 3]
    expectKind ekMalformed:
      discard decompressFrame(h, high(int))
    var k = le32(0x184C2102'u32)
    k.add [1'u8, 2]
    expectKind ekMalformed:
      discard decompressFrame(k, high(int))

  test "legacy blocks are independent and ignore the dictionary":
    let blk = @[0x0F'u8, 0x0A, 0x00, 0x00, 0x00] # refers before the block
    var f = le32(0x184C2102'u32)
    f.add le32(uint32(blk.len))
    f.add blk
    expectKind ekMalformed:
      discard decompressFrame(f, textLike(100), high(int))

  test "negative maxOutputSize":
    expectKind ekInvalidArgument:
      discard decompressFrame(good, -1)
