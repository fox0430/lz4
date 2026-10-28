## Frame format: one-shot compression and decompression.

import std/[os, strutils, unittest]
import lz4, lz4/private/xxhash32
import datagen, blockutil, errorcheck

suite "frame round trip":
  test "every option combination":
    let inputs =
      [newSeq[byte](), textLike(1000), mixed(300_000), zeros(70_000), randomBytes(5000)]
    for opts in allFrameOptions():
      for data in inputs:
        for c in [compressFrame(data, opts), encodeFrame(data, opts)]:
          check decompressFrame(c, high(int)) == data

  test "standard inputs with the defaults and linked blocks":
    for (name, data) in standardInputs():
      check decompressFrame(compressFrame(data), high(int)) == data
      check decompressFrame(
        encodeFrame(data, FrameOptions(blockIndependent: false)), high(int)
      ) == data

  test "levels":
    let data = mixed(200_000)
    for level in [low(int), -1000, -1, 0, 1, 2, 9, 12, high(int)]:
      check decompressFrame(compressFrame(data, FrameOptions(level: level)), high(int)) ==
        data

  test "string API":
    let s = "hello hello hello hello hello, LZ4 frame"
    check decompress(compress(s), high(int)) == s
    check decompress(compress(""), high(int)) == ""
    check compress("abc").len > 0

suite "frame layout":
  test "FLG and BD follow the options":
    # In a streaming frame (compressFrame changes the block size and mode
    # of a one-block input, see below).
    for opts in allFrameOptions():
      let c = encodeFrame(textLike(100), opts)
      var flg = 0x40'u8
      if opts.blockIndependent:
        flg = flg or 0x20
      if opts.blockChecksum:
        flg = flg or 0x10
      if opts.writeContentSize:
        flg = flg or 0x08
      if opts.contentChecksum:
        flg = flg or 0x04
      check c[4] == flg
      check c[5] == byte((ord(opts.blockSize) + 4) shl 4)

  test "an input that fits in one block gets a block of its size":
    # As LZ4F_compressFrame does, so that decoders need less memory: the
    # smallest block size that holds the input, up to the one asked for,
    # and independent blocks, since there is one.
    for (len, want) in [
      (0, bs64KiB),
      (100, bs64KiB),
      (65536, bs64KiB),
      (65537, bs256KiB),
      (262144, bs256KiB),
      (262145, bs1MiB),
      (1 shl 20 + 1, bs4MiB),
    ]:
      let data = textLike(len, 31)
      for indep in [true, false]:
        let opts = FrameOptions(blockSize: bs4MiB, blockIndependent: indep)
        for f in [compressFrame(data, opts), compressFrame(data, data, opts)]:
          var info: FrameInfo
          check readFrameInfo(f, info) == 7
          check info.blockSize == want
          check info.blockIndependent
        check decompressFrame(compressFrame(data, opts), high(int)) == data
    # A larger input keeps the options as given.
    let data = textLike(300_000, 32)
    for (bs, indep) in [(bs256KiB, false), (bs256KiB, true), (bs64KiB, false)]:
      let f = compressFrame(data, FrameOptions(blockSize: bs, blockIndependent: indep))
      var info: FrameInfo
      check readFrameInfo(f, info) == 7
      check info.blockSize == bs
      check info.blockIndependent == indep

  test "MaxHeaderSize bytes hold the longest header":
    let f = compressFrame(
      textLike(1000), FrameOptions(writeContentSize: true, dictId: 0x12345678)
    )
    var info: FrameInfo
    check readFrameInfo(f.toOpenArray(0, MaxHeaderSize - 2), info) == 0
    check readFrameInfo(f.toOpenArray(0, MaxHeaderSize - 1), info) == MaxHeaderSize
    check info.contentSize == 1000
    check info.dictId == 0x12345678

  test "an empty input has no content size":
    let c = compressFrame([], FrameOptions(writeContentSize: true))
    check c[4] == 0x64
    check c.len == 7 + 4 + 4
    check decompressFrame(c, high(int)).len == 0

  test "content size is written when asked":
    let c = compressFrame(textLike(1234), FrameOptions(writeContentSize: true))
    check c[4] == 0x6C
    var info: FrameInfo
    check readFrameInfo(c, info) == 15
    check info.hasContentSize
    check info.contentSize == 1234

  test "incompressible blocks are stored uncompressed":
    let data = randomBytes(100)
    let c = compressFrame(data)
    # header (7) + block header with the uncompressed bit + data
    check c[7 .. 10] == le32(0x8000_0064'u32)
    check c[11 .. 110] == data

  test "linked blocks refer to the previous block":
    # 40000 random bytes repeated: the start of the second 64 KiB block
    # repeats data of the first one, 40000 bytes back. Linked blocks can
    # refer to it, independent blocks have to store it again.
    let part = randomBytes(40_000)
    var data: seq[byte]
    for _ in 0 ..< 4:
      data.add part
    let linked = compressFrame(data, FrameOptions(blockIndependent: false))
    let indep = compressFrame(data)
    check linked.len < indep.len - 30_000
    check decompressFrame(linked, high(int)) == data

suite "frame decompression":
  test "an empty input gives an empty output":
    check decompressFrame([], high(int)).len == 0

  test "maxOutputSize exactly and one below":
    let data = textLike(200_000)
    for opts in [
      FrameOptions(),
      FrameOptions(blockIndependent: false),
      FrameOptions(writeContentSize: true),
    ]:
      let c = compressFrame(data, opts)
      check decompressFrame(c, data.len) == data
      expectKind ekLimitExceeded:
        discard decompressFrame(c, data.len - 1)

  test "maxOutputSize covers all the frames together":
    let a = compressFrame(textLike(1000))
    var both = a
    both.add a
    check decompressFrame(both, 2000).len == 2000
    expectKind ekLimitExceeded:
      discard decompressFrame(both, 1999)

  test "content size above maxOutputSize fails before decoding":
    let c = compressFrame(textLike(5000), FrameOptions(writeContentSize: true))
    expectKind ekLimitExceeded:
      discard decompressFrame(c, 4999)

  test "a false content size is not allocated before the blocks decode":
    # A header announcing 4 GiB, then 17 MB of junk whose first block header
    # is too large. The output used to be reserved from the content size
    # (up to 255 times the rest of the input) before the first block.
    when sizeof(int) == 8 and declared(getMaxMem) and not defined(useMalloc):
      var f = frameHeader(0x48, 0x40, contentSize = 4'i64 shl 30)
      f.setLen(f.len + 17_000_000)
      for i in f.len - 17_000_000 ..< f.len:
        f[i] = 0xFF
      let before = getMaxMem()
      expectKind ekMalformed:
        discard decompressFrame(f, high(int))
      check getMaxMem() - before < 1 shl 30

  test "a block is decoded again when it needs more than the output has":
    # A one-shot result grows towards the end of the frame as the content
    # size or the ratio of the blocks so far announces (at most 4 times the
    # input left), and a block that may produce more is first decoded in
    # what there is. Here it does not fit: zeros after little input, after
    # random bytes, and a linked block that copies the previous one.
    let t = textLike(60_000)
    let cases = [
      (zeros(60_000), FrameOptions(writeContentSize: true)),
      (randomBytes(65536) & zeros(65536), FrameOptions()),
      (t & t, FrameOptions(blockIndependent: false)),
    ]
    for (data, opts) in cases:
      let f = encodeFrame(data, opts)
      check decompressFrame(f, high(int)) == data
      check decompress(toString(f), high(int)) == toString(data)
      var d = initFrameDecoder(high(int64))
      var o: seq[byte]
      var pos = 0
      while pos < f.len:
        pos += d.feed(f.toOpenArray(pos, f.high), o)
      d.finish()
      check o == data
    # A content size one short: the block does not fit in the room made for
    # the content size, and the error is the one it gives without that
    # first try, ekLimitExceeded when maxOutputSize stops it.
    let blk = compressBlock(zeros(60_000))
    let g =
      frameHeader(0x68, 0x40, contentSize = 59_999) & le32(uint32(blk.len)) & blk &
      le32(0)
    expectKind ekMalformed:
      discard decompressFrame(g, high(int))
    expectKind ekLimitExceeded:
      discard decompressFrame(g, 59_999)

  test "content size 0 means unknown":
    var f = frameHeader(0x6C, 0x40, contentSize = 0)
    let data = textLike(500)
    f.add le32(uint32(data.len) or 0x8000_0000'u32)
    f.add data
    f.add le32(0)
    f.add le32(xxh32(data))
    check decompressFrame(f, high(int)) == data

  test "the 0x80000000 block is empty, not the end mark":
    var f = frameHeader(0x60, 0x40)
    f.add le32(0x8000_0000'u32)
    f.add le32(3 or 0x8000_0000'u32)
    f.add [1'u8, 2, 3]
    f.add le32(0)
    check decompressFrame(f, high(int)) == @[1'u8, 2, 3]

  test "concatenated and skippable frames":
    let a = textLike(3000, 1)
    let b = mixed(100_000, 2)
    var stream = compressFrame(a)
    stream.add le32(0x184D2A50'u32)
    stream.add le32(5)
    stream.add [9'u8, 9, 9, 9, 9]
    stream.add compressFrame(b, FrameOptions(blockIndependent: false))
    stream.add le32(0x184D2A5F'u32)
    stream.add le32(0)
    var expected = a
    expected.add b
    check decompressFrame(stream, high(int)) == expected

  test "a stream of skippable frames only":
    var s = le32(0x184D2A57'u32)
    s.add le32(2)
    s.add [1'u8, 2]
    check decompressFrame(s, high(int)).len == 0

  test "legacy frames":
    # Hand-made: two blocks, compressed independently.
    let a = textLike(10_000, 3)
    let b = textLike(500, 4)
    var f = le32(0x184C2102'u32)
    for part in [a, b]:
      let c = compressBlock(part)
      f.add le32(uint32(c.len))
      f.add c
    var expected = a
    expected.add b
    check decompressFrame(f, high(int)) == expected
    # A normal frame right after it (its magic is read as a too-large block
    # size and handed back).
    f.add compressFrame(a)
    expected.add a
    check decompressFrame(f, high(int)) == expected

  test "Dict-ID frames that do not use the dictionary decode without it":
    let data = textLike(3000)
    var f = frameHeader(0x65, 0x40, dictId = 1234)
    let c = compressBlock(data)
    f.add le32(uint32(c.len))
    f.add c
    f.add le32(0)
    f.add le32(xxh32(data))
    check decompressFrame(f, high(int)) == data
    var info: FrameInfo
    check readFrameInfo(f, info) == 11
    check info.hasDictId and info.dictId == 1234

suite "dictionaries (decompressFrame with dict)":
  let dict = textLike(100_000, 91)
  # A block that copies 300 bytes from 1000 bytes before its start, then
  # has 5 literals.
  var blk = seqBytes([], 1000, 300)
  blk.add seqBytes([1'u8, 2, 3, 4, 5], 0, 0, last = true)
  let fromDict = dict[dict.len - 1000 ..< dict.len - 700] & @[1'u8, 2, 3, 4, 5]

  proc twoBlocks(flg: byte, contentSize = -1'i64): seq[byte] =
    result = frameHeader(flg, 0x40, contentSize)
    for _ in 0 ..< 2:
      result.add le32(uint32(blk.len))
      result.add blk
    result.add le32(0)

  test "independent blocks: every block starts from the dictionary":
    let f = twoBlocks(0x60)
    check decompressFrame(f, dict, high(int)) == fromDict & fromDict
    expectKind ekMalformed:
      discard decompressFrame(f, high(int))

  test "linked blocks: the dictionary, then the frame's own output":
    let f = twoBlocks(0x40)
    # The second block's offset 1000 reaches back over the first block's
    # 305 bytes into the dictionary.
    let all = dict & fromDict
    let second = all[all.len - 1000 ..< all.len - 700] & @[1'u8, 2, 3, 4, 5]
    check decompressFrame(f, dict, high(int)) == fromDict & second
    # With a content size (the output is reserved with the dictionary).
    check decompressFrame(twoBlocks(0x48, 610), dict, high(int)) == fromDict & second

  test "only the last 64 KiB of the dictionary matter":
    for flg in [0x60'u8, 0x40]:
      let f = twoBlocks(flg)
      check decompressFrame(f, dict, high(int)) ==
        decompressFrame(f, dict[dict.len - 65536 .. ^1], high(int))

  test "concatenated frames restart from the dictionary":
    for flg in [0x60'u8, 0x40]:
      let f = twoBlocks(flg)
      let one = decompressFrame(f, dict, high(int))
      check decompressFrame(f & f & f, dict, high(int)) == one & one & one

  test "a short dictionary limits how far back blocks can refer":
    expectKind ekMalformed:
      discard decompressFrame(twoBlocks(0x60), zeros(999), high(int))
    check decompressFrame(twoBlocks(0x60), zeros(1000), high(int)).len == 610

suite "frames with high compression and dictionaries":
  test "HC frames round trip (every option, some levels)":
    let data = mixed(300_000, 171)
    for level in [2, 9, 12]:
      for opts in allFrameOptions():
        var o = opts
        o.level = level
        if o.blockSize > bs256KiB:
          continue
        check decompressFrame(compressFrame(data, o), high(int)) == data

  test "a dictionary id is written and read back":
    let f = compressFrame(textLike(1000), FrameOptions(dictId: 0xCAFE))
    check (f[4] and 1) == 1
    var info: FrameInfo
    check readFrameInfo(f, info) == 11
    check info.hasDictId and info.dictId == 0xCAFE
    check decompressFrame(f, high(int)) == textLike(1000)

  test "compressFrame with a dictionary, independent and linked, fast and HC":
    let dict = textLike(100_000, 172)
    var data = dict[20_000 ..< 90_000]
    data.add textLike(150_000, 173)
    for level in [0, -2, 2, 3, 9, 12]:
      for indep in [true, false]:
        let opts = FrameOptions(blockIndependent: indep, level: level)
        let f = compressFrame(data, dict, opts)
        check decompressFrame(f, dict, high(int)) == data
        # The dictionary pays off.
        check f.len < compressFrame(data, opts).len
        # Without it the frame does not decode (lz4 -D style: no Dict-ID).
        expectKind ekMalformed:
          discard decompressFrame(f, high(int))
    # With a Dict-ID, the missing dictionary is reported as such.
    let g = compressFrame(data, dict, FrameOptions(dictId: 7))
    expectKind ekUnsupported:
      discard decompressFrame(g, high(int))
    check decompressFrame(g, dict, high(int)) == data

  test "concatenated dictionary frames":
    let dict = textLike(70_000, 174)
    let a = dict[1000 ..< 30_000]
    let f = encodeFrame(a, dict, FrameOptions(blockIndependent: false, level: 9))
    check decompressFrame(f & f, dict, high(int)) == a & a

suite "legacy frame compression":
  test "round trips, empty input and several 8 MiB blocks":
    check compressLegacyFrame([]) == @[0x02'u8, 0x21, 0x4C, 0x18]
    check decompressFrame(compressLegacyFrame([]), high(int)).len == 0
    for data in [
      textLike(1000), mixed(8 * 1024 * 1024 + 5000, 201), zeros(8 * 1024 * 1024)
    ]:
      for level in [0, 9]:
        let f = compressLegacyFrame(data, level)
        check f[0 .. 3] == @[0x02'u8, 0x21, 0x4C, 0x18]
        check decompressFrame(f, high(int)) == data
    # Followed by a normal frame.
    let a = textLike(5000, 202)
    check decompressFrame(compressLegacyFrame(a) & compressFrame(a), high(int)) == a & a
    # The string API.
    check decompress(compressLegacy("hello hello hello hello"), high(int)) ==
      "hello hello hello hello"

  test "levels are read as lz4 -l reads them":
    # Fast below 3 with acceleration -level, HC from 3 on: one block equals
    # compressBlock at the matching level.
    let data = mixed(200_000, 203)
    for (level, blockLevel) in [
      (-5, -4), (-1, 0), (0, 0), (1, 0), (2, 0), (3, 3), (9, 9)
    ]:
      let f = compressLegacyFrame(data, level)
      let blk = compressBlock(data, blockLevel)
      check f[8 .. ^1] == blk
      check decompressFrame(f, high(int)) == data

  test "an input too large for one buffer raises ekLimitExceeded":
    # Only the length is looked at, before any byte is read, so the
    # openArray needs no memory behind it.
    var b: byte
    let p = cast[ptr UncheckedArray[byte]](b.addr)
    expectKind ekLimitExceeded:
      discard compressLegacyFrame(p.toOpenArray(0, high(int) - 1))
    expectKind ekLimitExceeded:
      discard compressFrame(p.toOpenArray(0, high(int) - 1))

suite "one-shot results":
  test "a result does not keep the room of the worst case":
    # Made in a buffer of about the input's length, a much shorter result
    # moves to one of its own size.
    let data = zeros(1 shl 20)
    let dict = textLike(1000)
    let s = toString(data)
    template tight(call: untyped) =
      block:
        let r = call
        check r.len < data.len div 100
        check r.capacity < 2 * r.len

    tight(compressFrame(data))
    tight(compressFrame(data, dict))
    tight(compress(s))
    tight(compress(s, toString(dict)))
    tight(compressBlock(data))
    tight(compressBlock(data, dict))
    tight(compressBlock(s))
    tight(compressBlock(s, toString(dict)))
    tight(compressLegacyFrame(data))
    tight(compressLegacy(s))

  test "a decompressed result does not keep the room of a whole block":
    # Without a content size, a block gets room for the most it may
    # produce (here 1.4 MB).
    let data = textLike(10_000)
    let dict = textLike(1000, 5)
    for cs in [false, true]:
      let opts = FrameOptions(blockSize: bs4MiB, writeContentSize: cs)
      let f = encodeFrame(data, opts)
      let fd = encodeFrame(data, dict, opts)
      for r in [decompressFrame(f, high(int)), decompressFrame(fd, dict, high(int))]:
        check r == data
        check r.capacity < 2 * r.len
      for r in [
        decompress(toString(f), high(int)),
        decompress(toString(fd), toString(dict), high(int)),
      ]:
        check r == toString(data)
        check r.capacity < 2 * r.len

  test "a decompression that fails frees what it decoded":
    # Each call fails after about 1 MB has been decoded: at the content
    # checksum, at the end of a truncated frame, or at maxOutputSize. Nim
    # (ORC) does not free a string result filled before a raise.
    let data = textLike(1 shl 20)
    let dict = textLike(1000, 5)
    let (f, fd) = (compressFrame(data), compressFrame(data, dict))
    var (bad, badD) = (f, fd)
    bad[^1] = bad[^1] xor 1
    badD[^1] = badD[^1] xor 1
    # Everything the loop reads is made before measuring, and read in
    # place: refc, which scans the stack, may keep the copies a loop makes.
    proc failing(kind: Lz4ErrorKind, c, cd: seq[byte], limit: int): auto =
      (kind: kind, c: c, cd: cd, s: toString(c), sd: toString(cd), limit: limit)

    let cases = [
      failing(ekChecksum, bad, badD, high(int)),
      failing(ekMalformed, f[0 ..< f.len - 4], fd[0 ..< fd.len - 4], high(int)),
      failing(ekLimitExceeded, f, fd, data.len - 1),
    ]
    let sdict = toString(dict)
    GC_fullCollect()
    let before = getOccupiedMem()
    for i in 0 ..< cases.len:
      for _ in 1 .. 5:
        expectKind cases[i].kind:
          discard decompress(cases[i].s, cases[i].limit)
        expectKind cases[i].kind:
          discard decompress(cases[i].sd, sdict, cases[i].limit)
        expectKind cases[i].kind:
          discard decompressFrame(cases[i].c, cases[i].limit)
        expectKind cases[i].kind:
          discard decompressFrame(cases[i].cd, dict, cases[i].limit)
    GC_fullCollect()
    # getOccupiedMem is always 0 with -d:useMalloc; in an ASan build of the
    # tests, LeakSanitizer reports the leak at exit instead.
    when not defined(useMalloc):
      check getOccupiedMem() - before < data.len

suite "block size boundaries and corpus files":
  test "inputs of one block size, one byte less and one byte more":
    for (bs, n) in [(bs64KiB, 65536), (bs256KiB, 262144), (bs4MiB, 4194304)]:
      for len in [n - 1, n, n + 1]:
        let data = mixed(len, uint64(len))
        for indep in [true, false]:
          let f =
            compressFrame(data, FrameOptions(blockSize: bs, blockIndependent: indep))
          check decompressFrame(f, high(int)) == data

  test "files in tests/data (for example the Silesia corpus), if any":
    # tests/data is not in git; put a corpus there to test it.
    var files = 0
    for f in walkDirRec(currentSourcePath().parentDir / "data"):
      let name = f.extractFilename
      # Not the README, hidden files or archives of the corpus itself.
      if name == "README.md" or name.startsWith(".") or
          f.splitFile.ext.toLowerAscii in
          [".zip", ".gz", ".tgz", ".xz", ".bz2", ".lz4", ".zst", ".7z"]:
        continue
      let data = readBytes(f)
      for opts in [FrameOptions(), FrameOptions(blockIndependent: false, level: 3)]:
        for c in [compressFrame(data, opts), encodeFrame(data, opts)]:
          check decompressFrame(c, high(int)) == data
      inc files
    if files == 0:
      skip()
