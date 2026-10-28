## Streaming compression and decompression.

import std/[importutils, unittest]
import lz4, lz4/private/xxhash32
from lz4/private/common import readLE32
from lz4/private/frameimpl import FrameCompressor
import datagen, blockutil, fuzzutil, errorcheck

proc encodeInChunks(
    data: openArray[byte],
    opts: FrameOptions,
    r: var Rng,
    flushes = false,
    contentSize = -1'i64,
): seq[byte] =
  var e = initFrameEncoder(opts, contentSize)
  var p = 0
  while p < data.len:
    let k = min(data.len - p, [1, 7, 100, 4096, 65536, 70_000, 1 shl 20][r.below(7)])
    e.write(data.toOpenArray(p, p + k - 1), result)
    p += k
    if flushes and r.below(3) == 0:
      e.flush(result)
  e.finish(result)

proc decodeInChunks(
    stream: openArray[byte],
    r: var Rng,
    maxChunk = 100_000,
    clearOutput = false,
    dict: seq[byte] = @[],
    useDict = false,
): seq[byte] =
  ## Feeds `stream` in random pieces of up to `maxChunk` bytes.
  var chunks: seq[int]
  for _ in 0 ..< 16:
    chunks.add 1 + r.below(maxChunk)
  let res = decodeStream(
    stream, chunks, dict = dict, useDict = useDict, clearOutput = clearOutput
  )
  if not res.ok:
    checkpoint "decoding failed: " & $res.kind & ": " & res.msg
  check res.ok
  res.data

proc feedAll(d: var FrameDecoder, input: openArray[byte], output: var seq[byte]) =
  ## Feeds all of `input` (feed stops after each frame header and at each
  ## frame end).
  var pos = 0
  while pos < input.len:
    pos += d.feed(input.toOpenArray(pos, input.high), output)

suite "FrameEncoder":
  test "without flush the output equals compressFrame (with its options)":
    var r = initRng(71)
    let inputs = [
      newSeq[byte](),
      textLike(100),
      mixed(300_000),
      textLike(65536),
      repeating(200_000, 5),
    ]
    for bs in BlockSizeId:
      for indep in [true, false]:
        for bc in [false, true]:
          let opts =
            FrameOptions(blockSize: bs, blockIndependent: indep, blockChecksum: bc)
          for data in inputs:
            let c = compressFrame(data, opts)
            check encodeInChunks(data, usedOptions(c, opts), r) == c

  test "inputs above 4 MiB (independent and linked)":
    var r = initRng(72)
    let data = mixed(4_500_000, 73)
    for opts in [
      FrameOptions(),
      FrameOptions(blockIndependent: false),
      FrameOptions(blockIndependent: false, blockSize: bs4MiB),
      FrameOptions(blockSize: bs1MiB, level: -3),
    ]:
      check encodeInChunks(data, opts, r) == compressFrame(data, opts)

  test "a write that completes the pending block and holds whole ones":
    # The pending block takes less or more than 64 KiB of the write; the
    # whole blocks after it are compressed where they are.
    let data = mixed(2_000_000, 76)
    let dict = textLike(70_000, 77)
    for level in [0, 2, 9]:
      for bs in [bs256KiB, bs1MiB]:
        for first in [100, 200_000]:
          for useDict in [false, true]:
            let opts =
              FrameOptions(blockSize: bs, blockIndependent: false, level: level)
            var e =
              if useDict:
                initFrameEncoder(dict, opts)
              else:
                initFrameEncoder(opts)
            var c: seq[byte]
            e.write(data.toOpenArray(0, first - 1), c)
            e.write(data.toOpenArray(first, data.high), c)
            e.finish(c)
            if useDict:
              check c == compressFrame(data, dict, opts)
            else:
              check c == compressFrame(data, opts)

  test "with content size":
    var r = initRng(74)
    let data = textLike(150_000)
    let opts = FrameOptions(writeContentSize: true)
    check encodeInChunks(data, opts, r, contentSize = data.len) ==
      compressFrame(data, opts)
    # 0 writes no content size, like compressFrame of an empty input.
    check encodeInChunks([], opts, r, contentSize = 0) == compressFrame([], opts)

  test "flush makes short blocks that still decode":
    var r = initRng(75)
    let data = mixed(500_000)
    for opts in [FrameOptions(), FrameOptions(blockIndependent: false)]:
      for _ in 0 ..< 5:
        let c = encodeInChunks(data, opts, r, flushes = true)
        check decompressFrame(c, high(int)) == data

  test "flush with nothing pending writes nothing":
    var e = initFrameEncoder()
    var output: seq[byte]
    e.flush(output)
    check output.len == 0
    e.write(toBytes("abc"), output)
    let afterWrite = output.len
    e.flush(output)
    let afterFlush = output.len
    check afterFlush > afterWrite
    e.flush(output)
    check output.len == afterFlush
    e.finish(output)
    check decompressFrame(output, high(int)) == toBytes("abc")

  test "content size and writeContentSize must agree":
    expectKind ekInvalidArgument:
      discard initFrameEncoder(FrameOptions(writeContentSize: true))
    expectKind ekInvalidArgument:
      discard initFrameEncoder(FrameOptions(writeContentSize: true), -5)
    expectKind ekInvalidArgument:
      discard initFrameEncoder(FrameOptions(), 10)

  test "more or less data than the content size":
    # Rejected before anything changes, so the encoder can go on: they
    # used to fail it for good, with a truncated frame in the output.
    let opts = FrameOptions(writeContentSize: true)
    var output: seq[byte]
    var e = initFrameEncoder(opts, 10)
    e.write(zeros(6), output)
    expectKind ekInvalidArgument:
      e.write(zeros(5), output)
    expectKind ekInvalidArgument:
      e.finish(output)
    e.write(zeros(4), output)
    e.finish(output)
    check output == compressFrame(zeros(10), opts)
    var f = initFrameEncoder(opts, 10)
    var o: seq[byte]
    f.write(zeros(9), o)
    expectKind ekInvalidArgument:
      f.finish(o)
    f.write(zeros(1), o)
    f.finish(o)
    check o == output

  test "nothing may follow finish":
    var output: seq[byte]
    var e = initFrameEncoder()
    e.finish(output)
    check decompressFrame(output, high(int)).len == 0
    let n = output.len
    expectKind ekInvalidArgument:
      e.write(zeros(1), output)
    expectKind ekInvalidArgument:
      e.flush(output)
    expectKind ekInvalidArgument:
      e.finish(output)
    check output.len == n

  test "an encoder that initFrameEncoder did not make":
    # Its block size was 0: write used to loop forever and finish to write
    # a frame no decoder accepts.
    var zeroed: FrameEncoder
    for e0 in [zeroed, FrameEncoder()]:
      var e = e0
      var output: seq[byte]
      expectKind ekInvalidArgument:
        e.write(zeros(0), output)
      expectKind ekInvalidArgument:
        e.write(zeros(100), output)
      expectKind ekInvalidArgument:
        e.flush(output)
      expectKind ekInvalidArgument:
        e.finish(output)
      check output.len == 0

  test "strings and slices of them":
    let s = toString(textLike(300_000))
    let opts = FrameOptions(blockIndependent: false)
    var e = initFrameEncoder(opts)
    var fromStrings: string
    for (a, b) in [(0, 99), (100, 70_099), (70_100, s.high)]:
      e.write(s.toOpenArray(a, b), fromStrings)
    e.finish(fromStrings)
    check fromStrings == compress(s, opts)
    var d = initFrameDecoder(high(int64))
    var output: string
    var pos = 0
    while pos < fromStrings.len:
      let n = min(fromStrings.len - pos, 1000)
      pos += d.feed(fromStrings.toOpenArray(pos, pos + n - 1), output)
    d.finish()
    check output == s

  test "options declared without a value":
    # Zeros, not the defaults: 64 KiB linked blocks without a content
    # checksum, which used to be an invalid block size.
    var opts: FrameOptions
    opts.level = 9
    let data = textLike(200_000)
    let f = compressFrame(data, opts)
    var info: FrameInfo
    check readFrameInfo(f, info) > 0
    check info.blockSize == bs64KiB
    check not info.blockIndependent and not info.contentChecksum
    check decompressFrame(f, high(int)) == data

suite "FrameDecoder":
  test "random splits, all options":
    var r = initRng(81)
    let data = mixed(400_000, 82)
    for bs in [bs64KiB, bs256KiB, bs4MiB]:
      for indep in [true, false]:
        for bc in [false, true]:
          for ws in [false, true]:
            let opts = FrameOptions(
              blockSize: bs,
              blockIndependent: indep,
              blockChecksum: bc,
              writeContentSize: ws,
            )
            let c = encodeFrame(data, opts)
            check decodeInChunks(c, r) == data
            check decodeInChunks(c, r, maxChunk = 300) == data

  test "one byte at a time":
    var r = initRng(83)
    let data = mixed(150_000, 84)
    for opts in [
      FrameOptions(blockChecksum: true, writeContentSize: true),
      FrameOptions(blockIndependent: false),
    ]:
      check decodeInChunks(compressFrame(data, opts), r, maxChunk = 1) == data

  test "linked blocks with the output emptied between calls":
    var r = initRng(85)
    let data = mixed(1_000_000, 86)
    for bs in [bs64KiB, bs1MiB]:
      let c = encodeFrame(data, FrameOptions(blockIndependent: false, blockSize: bs))
      check decodeInChunks(c, r, clearOutput = true) == data
      check decodeInChunks(c, r, maxChunk = 1000, clearOutput = true) == data

  test "random streams of normal, skippable and legacy frames":
    var r = initRng(87)
    for i in 0 ..< 200:
      let (stream, content) = randomStream(r, 100_000)
      check decodeInChunks(stream, r, maxChunk = 1 + r.below(70_000)) == content

  test "stops after each frame header and at each frame end; atFrameEnd":
    let a = compressFrame(textLike(1000))
    var skip = le32(0x184D2A53'u32)
    skip.add le32(3)
    skip.add [1'u8, 2, 3]
    let b = compressFrame(textLike(2000, 9))
    var stream = a & skip & b & toBytes("trailer")
    var d = initFrameDecoder(high(int64))
    check not d.atFrameEnd
    var output: seq[byte]
    var info: FrameInfo
    var pos = d.feed(stream, output)
    check pos == readFrameInfo(a, info)
    check not d.atFrameEnd
    check output.len == 0
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == a.len
    check d.atFrameEnd
    check output == textLike(1000)
    # A skippable frame: its magic number and size, then its data.
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == a.len + 8
    check not d.atFrameEnd
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == a.len + skip.len
    check d.atFrameEnd
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == a.len + skip.len + readFrameInfo(b, info)
    check not d.atFrameEnd
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == a.len + skip.len + b.len
    check d.atFrameEnd
    # A container stops here; the rest is its own data.
    check stream[pos .. ^1] == toBytes("trailer")
    d.finish()

  test "finish without feeding anything, and after a frame":
    var d = initFrameDecoder(high(int64))
    d.finish()
    var e = initFrameDecoder(high(int64))
    var output: seq[byte]
    let f = compressFrame(textLike(100))
    e.feedAll(f, output)
    e.finish()

  test "finish inside a frame":
    let data = mixed(100_000)
    let f = compressFrame(data, FrameOptions(blockChecksum: true))
    var r = initRng(88)
    for _ in 0 ..< 100:
      let cut = 1 + r.below(f.len - 1)
      var d = initFrameDecoder(high(int64))
      var output: seq[byte]
      var pos = 0
      while pos < cut:
        pos += d.feed(f.toOpenArray(pos, cut - 1), output)
      expectKind ekMalformed:
        d.finish()
      # That changes nothing: the rest of the input completes the frame.
      while pos < f.len:
        pos += d.feed(f.toOpenArray(pos, f.high), output)
      d.finish()
      check output == data

  test "a decoder that initFrameDecoder did not make":
    # It used to fail with a misleading ekLimitExceeded (maxOutputSize 0).
    var zeroed: FrameDecoder
    let f = compressFrame(textLike(100))
    for d0 in [zeroed, FrameDecoder()]:
      var d = d0
      var output: seq[byte]
      expectKind ekInvalidArgument:
        discard d.feed(f, output)
      expectKind ekInvalidArgument:
        discard d.feed(zeros(0), output)
      expectKind ekInvalidArgument:
        d.finish()
      check output.len == 0

  test "the decoder goes on after finish":
    # The end of a frame frees a block buffer larger than 64 KiB; the next
    # frame makes it again.
    let a = textLike(300_000, 89)
    let f = encodeFrame(a, FrameOptions(blockSize: bs1MiB, blockIndependent: false))
    var d = initFrameDecoder(high(int64))
    var output: seq[byte]
    for i in 0 ..< 3:
      # Cut in two, so that a block goes through the decoder's own buffer.
      let cut = f.len div 2
      d.feedAll(f.toOpenArray(0, cut - 1), output)
      d.feedAll(f.toOpenArray(cut, f.high), output)
      d.finish()
    check output == a & a & a

  test "legacy frames: finish on a block boundary, then a normal frame":
    let a = textLike(10_000, 3)
    let b = textLike(5_000, 4)
    var legacy = le32(0x184C2102'u32)
    for part in [a, b]:
      let c = compressBlock(part)
      legacy.add le32(uint32(c.len))
      legacy.add c
    var d = initFrameDecoder(high(int64))
    var output: seq[byte]
    check d.feed(legacy, output) == 4
    check output.len == 0
    check d.feed(legacy.toOpenArray(4, legacy.high), output) == legacy.len - 4
    check not d.atFrameEnd
    d.finish()
    check output == a & b
    # Followed by a normal frame whose magic arrives in two pieces.
    let f = compressFrame(a)
    let stream = legacy & f
    for split in [legacy.len + 1, legacy.len + 2, legacy.len + 3]:
      var e = initFrameDecoder(high(int64))
      var o: seq[byte]
      var pos = 0
      for stop in [split, stream.len]:
        while pos < stop:
          pos += e.feed(stream.toOpenArray(pos, stop - 1), o)
      e.finish()
      check o == a & b & a

  test "a content size of 2^31 or more is not rejected up front":
    # maxOutputSize is an int64, so only the data decides.
    var d = initFrameDecoder(high(int64))
    var output: seq[byte]
    let h = frameHeader(0x68, 0x40, contentSize = (1'i64 shl 31) + 5)
    check d.feed(h, output) == h.len
    expectKind ekMalformed:
      d.finish()
    var e = initFrameDecoder(maxOutputSize = 1'i64 shl 31)
    expectKind ekLimitExceeded:
      discard e.feed(h, output)

  test "a false content size grows output by what the frame decoded":
    # 8 MiB already in output, then a frame announcing 1 GiB with a block
    # of 10 bytes. The output used to grow by its whole length (to 16 MiB)
    # rather than as Nim grows it for 10 bytes (1.5 times).
    const before = 8 shl 20
    var output = newSeq[byte](before)
    var d = initFrameDecoder(high(int64))
    let h = frameHeader(0x68, 0x40, contentSize = 1'i64 shl 30)
    check d.feed(h, output) == h.len
    let blk = le32(10 or 0x8000_0000'u32) & newSeq[byte](10)
    check d.feed(blk, output) == blk.len
    check output.len == before + 10
    check output.capacity < 2 * before

  test "maxOutputSize covers all frames":
    let f = compressFrame(textLike(1000))
    var d = initFrameDecoder(maxOutputSize = 1999)
    var output: seq[byte]
    d.feedAll(f, output)
    expectKind ekLimitExceeded:
      d.feedAll(f, output)
    check output.len == 1000
    expectKind ekInvalidArgument:
      discard initFrameDecoder(maxOutputSize = -1)

  test "a block buffer grows with the data, not with the block header":
    privateAccess(FrameDecoder)
    # A block header announcing 8 MiB (legacy) or 4 MiB, then one byte.
    let legacy = le32(0x184C2102'u32) & le32(8 shl 20) & @[0x11'u8]
    let normal = frameHeader(0x60, 0x70) & le32(4 shl 20) & @[0x11'u8]
    for input in [legacy, normal]:
      var d = initFrameDecoder(maxOutputSize = 16)
      var output: seq[byte]
      d.feedAll(input, output)
      check d.blk.len < 100
      let more = zeros(100_000)
      check d.feed(more, output) == more.len
      check d.blk.len <= 2 * (1 + more.len)

  test "an uncompressed block over the limit fails at its header":
    let f = frameHeader(0x60, 0x40) & le32(1000 or 0x8000_0000'u32)
    var d = initFrameDecoder(maxOutputSize = 999)
    var output: seq[byte]
    expectKind ekLimitExceeded:
      d.feedAll(f, output)
    var e = initFrameDecoder(maxOutputSize = 1000)
    e.feedAll(f, output)

  test "with a block checksum, an uncompressed block is checked before the limit":
    # As a compressed block is: a corrupted block is ekChecksum, whatever
    # the limit.
    let data = textLike(1000, 94)
    let h = frameHeader(0x70, 0x40) & le32(1000 or 0x8000_0000'u32)
    let f = h & data & le32(xxh32(data))
    var bad = f
    bad[h.len] = bad[h.len] xor 1
    for limit in [999'i64, 1000]:
      var d = initFrameDecoder(maxOutputSize = limit)
      var output: seq[byte]
      d.feedAll(h, output) # the header alone does not fail
      expectKind ekChecksum:
        d.feedAll(bad.toOpenArray(h.len, bad.high), output)
      var e = initFrameDecoder(maxOutputSize = limit)
      if limit < 1000:
        expectKind ekLimitExceeded:
          e.feedAll(f, output)
        check output.len == 0
      else:
        e.feedAll(f, output)
        check output == data

  test "frameInfo gives the header of the frame of the last feed":
    let dict = textLike(10_000, 95)
    let normal = compressFrame(
      textLike(1000), dict, FrameOptions(dictId: 7, writeContentSize: true)
    )
    let skippable = le32(0x184D2A53'u32) & le32(3) & @[1'u8, 2, 3]
    let legacy = compressLegacyFrame(textLike(100))
    var d = initFrameDecoder(dict, high(int64))
    var info: FrameInfo
    var output: seq[byte]
    check not d.frameInfo(info)
    # Byte by byte: nothing until the header is complete, then feed stops
    # before the content.
    var want: FrameInfo
    let n = readFrameInfo(normal, want)
    for i in 0 ..< n - 1:
      check d.feed(normal.toOpenArray(i, i), output) == 1
      check not d.frameInfo(info)
    check d.feed(normal.toOpenArray(n - 1, normal.high), output) == 1
    check output.len == 0
    check d.frameInfo(info)
    check info == want
    check info.dictId == 7 and info.contentSize == 1000
    check d.feed(normal.toOpenArray(n, normal.high), output) == normal.len - n
    check d.atFrameEnd
    check d.frameInfo(info)
    check info == want
    for (frame, kind) in [(skippable, fkSkippable), (legacy, fkLegacy)]:
      d.feedAll(frame, output)
      check d.frameInfo(info)
      check readFrameInfo(frame, want) > 0
      check info == want
      check info.kind == kind
    # The legacy frame ends with the next frame's magic number. Then no
    # header is known while the next one is read, nor after it fails.
    var bad = normal
    bad[n - 1] = bad[n - 1] xor 1
    check d.feed(bad, output) == 4
    check d.frameInfo(info)
    check info.kind == fkLegacy
    check d.feed(bad.toOpenArray(4, 5), output) == 2
    check not d.frameInfo(info)
    check info == FrameInfo()
    expectKind ekChecksum:
      discard d.feed(bad.toOpenArray(6, bad.high), output)
    check not d.frameInfo(info)
    # After the end of a frame, from the first byte of the next one.
    var e = initFrameDecoder(dict, high(int64))
    e.feedAll(normal, output)
    check e.frameInfo(info)
    check e.feed(normal.toOpenArray(0, 1), output) == 2
    check not e.frameInfo(info)

  test "the dictionary id can be checked before any content is decoded":
    let dictA = textLike(10_000, 96)
    let dictB = textLike(10_000, 97)
    let f = compressFrame(
      textLike(5000, 98), dictB, FrameOptions(dictId: 2, contentChecksum: false)
    )
    var d = initFrameDecoder(dictA, high(int64))
    var output: seq[byte]
    var info: FrameInfo
    check d.feed(f, output) == readFrameInfo(f, info)
    check output.len == 0
    check d.frameInfo(info)
    check info.hasDictId and info.dictId == 2

  test "one feed decodes one frame: a legacy frame, then a normal frame":
    let a = textLike(3000, 99)
    let b = textLike(2000, 100)
    let legacy = compressLegacyFrame(a)
    let normal = compressFrame(b)
    let stream = legacy & normal
    var want: FrameInfo
    let n = readFrameInfo(normal, want)
    var d = initFrameDecoder(high(int64))
    var output: seq[byte]
    var info: FrameInfo
    # The magic number is the whole header of a legacy frame.
    var pos = d.feed(stream, output)
    check pos == 4
    check output.len == 0
    check d.frameInfo(info)
    check info.kind == fkLegacy
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == legacy.len + 4
    check output == a
    check d.frameInfo(info)
    check info.kind == fkLegacy
    check not d.atFrameEnd
    output.setLen(0)
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == legacy.len + n
    check output.len == 0
    check d.frameInfo(info)
    check info == want
    pos += d.feed(stream.toOpenArray(pos, stream.high), output)
    check pos == stream.len
    check output == b
    d.finish()

  test "an error leaves only the completed blocks in output":
    # Second block corrupted (offset before the start of the block), in an
    # independent frame (decoded straight into output) and a linked frame
    # (decoded through the window buffer).
    let good = textLike(1000)
    let c = compressBlock(good)
    let bad = @[0x0F'u8, 0xE8, 0x03, 0x00, 0x00] # offset 1000 > 0 in block
    let bad2 = @[0x0F'u8, 0xFF, 0x0F, 0x00, 0x00] # offset 4095 > 1000
    for (flg, badBlock) in [(0x60'u8, bad), (0x40'u8, bad2)]:
      var f = frameHeader(flg, 0x40)
      f.add le32(uint32(c.len))
      f.add c
      f.add le32(uint32(badBlock.len))
      f.add badBlock
      f.add le32(0)
      var d = initFrameDecoder(high(int64))
      var output = toBytes("previous")
      expectKind ekMalformed:
        d.feedAll(f, output)
      check output == toBytes("previous") & good
      # Sticky: the same error again.
      expectKind ekMalformed:
        discard d.feed([0'u8], output)
      expectKind ekMalformed:
        d.finish()
      check output == toBytes("previous") & good

  test "a frame whose blocks overflow the content size is cut back":
    var f = frameHeader(0x48, 0x40, contentSize = 10)
    f.add le32(6 or 0x8000_0000'u32)
    f.add [1'u8, 2, 3, 4, 5, 6]
    f.add le32(6 or 0x8000_0000'u32)
    f.add [7'u8, 8, 9, 10, 11, 12]
    f.add le32(0)
    var d = initFrameDecoder(high(int64))
    var output: seq[byte]
    expectKind ekMalformed:
      d.feedAll(f, output)
    check output == @[1'u8, 2, 3, 4, 5, 6]

  test "dictionary frames (hand-made), independent and linked":
    let dict = textLike(100_000, 91)
    # A block that copies 300 bytes from 1000 bytes before its start, i.e.
    # from the dictionary, then 5 literals.
    var blk = seqBytes([], 1000, 300)
    blk.add seqBytes([1'u8, 2, 3, 4, 5], 0, 0, last = true)
    let expected = dict[dict.len - 1000 ..< dict.len - 700] & @[1'u8, 2, 3, 4, 5]
    for flg in [0x60'u8, 0x40]:
      var f = frameHeader(flg, 0x40)
      for _ in 0 ..< 2:
        f.add le32(uint32(blk.len))
        f.add blk
      f.add le32(0)
      var r = initRng(92)
      # Independent: each block starts from the dictionary. Linked: the
      # second block's offset 1000 lands in the first block's output and
      # the dictionary before it.
      let want =
        if flg == 0x60:
          expected & expected
        else:
          var w = expected
          var all = dict & expected
          var second: seq[byte]
          let start = all.len - 1000
          for i in 0 ..< 300:
            second.add all[start + i]
          w & second & @[1'u8, 2, 3, 4, 5]
      check decompressFrame(f, dict, high(int)) == want
      check decodeInChunks(f, r, maxChunk = 7, dict = dict, useDict = true) == want
      check decodeInChunks(
        f, r, maxChunk = 7, clearOutput = true, dict = dict, useDict = true
      ) == want
      # Without the dictionary: malformed (no Dict-ID).
      expectKind ekMalformed:
        discard decompressFrame(f, high(int))
      # Concatenated: every frame starts from the dictionary again.
      check decompressFrame(f & f, dict, high(int)) == want & want
      check decodeInChunks(f & f, r, dict = dict, useDict = true) == want & want

  test "a linked block reaching 64 KiB back past a short one into the dictionary":
    # The first block's output is short: the second block's longest offset
    # lands deep in the dictionary, which the decoder keeps for the blocks
    # after a feed that stops inside the frame.
    let dict = textLike(100_000, 93)
    let lits = textLike(100, 94)
    let first = seqBytes(lits, 0, 0, last = true)
    var second = seqBytes([], 65535, 50)
    second.add seqBytes([1'u8, 2, 3, 4, 5], 0, 0, last = true)
    var f = frameHeader(0x40, 0x40)
    for blk in [first, second]:
      f.add le32(uint32(blk.len))
      f.add blk
    f.add le32(0)
    let hist = dict[dict.len - 65536 ..< dict.len] & lits
    let at = hist.len - 65535
    let want = lits & hist[at ..< at + 50] & @[1'u8, 2, 3, 4, 5]
    check decompressFrame(f, dict, high(int)) == want
    var r = initRng(95)
    for maxChunk in [1, 7, 200]:
      check decodeInChunks(
        f, r, maxChunk = maxChunk, clearOutput = true, dict = dict, useDict = true
      ) == want

  test "a missing dictionary with a Dict-ID: ekUnsupported":
    var blk = seqBytes([], 10, 30)
    blk.add seqBytes([1'u8], 0, 0, last = true)
    for flg in [0x61'u8, 0x41]:
      var f = frameHeader(flg, 0x40, dictId = 99)
      f.add le32(uint32(blk.len))
      f.add blk
      f.add le32(0)
      var d = initFrameDecoder(high(int64))
      var output: seq[byte]
      expectKind ekUnsupported:
        d.feedAll(f, output)
      # An empty dictionary is none.
      var e = initFrameDecoder(newSeq[byte](), high(int64))
      expectKind ekUnsupported:
        e.feedAll(f, output)
      expectKind ekUnsupported:
        discard decompressFrame(f, newSeq[byte](), high(int))
      expectKind ekUnsupported:
        discard decompress(toString(f), "", high(int))
      check decompressFrame(f, zeros(10), high(int)).len == 31

suite "readFrameInfo":
  test "one byte at a time up to the end of the header":
    # The encoder writes the options as given (compressFrame would pick 64
    # KiB independent blocks for this input).
    let f = encodeFrame(
      textLike(5000),
      FrameOptions(writeContentSize: true, blockSize: bs1MiB, blockIndependent: false),
    )
    var info: FrameInfo
    for n in 0 ..< 15:
      check readFrameInfo(f.toOpenArray(0, n - 1), info) == 0
      # The defaults, even for a variable declared without a value.
      check info == FrameInfo()
    check readFrameInfo(f.toOpenArray(0, 14), info) == 15
    check info.blockSize == bs1MiB
    check not info.blockIndependent
    check info.hasContentSize and info.contentSize == 5000
    check info.contentChecksum and not info.blockChecksum

  test "skippable and legacy frames":
    var info: FrameInfo
    var s = le32(0x184D2A5A'u32)
    s.add le32(0xFFFF_FFF0'u32)
    check readFrameInfo(s.toOpenArray(0, 6), info) == 0
    check readFrameInfo(s, info) == 8
    check info.kind == fkSkippable
    check info.skippableSize == 0xFFFF_FFF0'u32
    check info.blockMaxSize == 0
    var l = le32(0x184C2102'u32)
    check readFrameInfo(l, info) == 4
    check info.kind == fkLegacy
    check info.blockIndependent
    check info.blockMaxSize == 8 shl 20
    # A header read before: replaced, then reset when nothing is read.
    check readFrameInfo(compressFrame(textLike(10)), info) == 7
    check info.blockMaxSize == 64 shl 10
    check readFrameInfo(l.toOpenArray(0, 2), info) == 0
    check info == FrameInfo()

  test "errors":
    var info: FrameInfo
    expectKind ekMalformed:
      discard readFrameInfo([1'u8, 2, 3, 4], info)
    var h = frameHeader(0x60, 0x40)
    check readFrameInfo(h, info) == 7
    h[6] = h[6] xor 0xFF
    info.blockChecksum = true
    expectKind ekChecksum:
      discard readFrameInfo(h, info)
    check info == FrameInfo()
    expectKind ekMalformed:
      discard readFrameInfo(frameHeader(0x60, 0x30), info)
    expectKind ekMalformed:
      discard readFrameInfo(frameHeader(0x80, 0x40), info)

  test "a huge skippable frame does not overflow":
    var s = le32(0x184D2A50'u32)
    s.add le32(0xFFFF_FFFF'u32)
    s.add zeros(100)
    expectKind ekMalformed:
      discard decompressFrame(s, high(int))
    var d = initFrameDecoder(high(int64))
    var output: seq[byte]
    check d.feed(s, output) == 8
    check d.feed(s.toOpenArray(8, s.high), output) == s.len - 8
    expectKind ekMalformed:
      d.finish()
    # An empty skippable frame.
    var z = le32(0x184D2A50'u32)
    z.add le32(0)
    check decompressFrame(z, high(int)).len == 0
    var e = initFrameDecoder(high(int64))
    check e.feed(z, output) == 8
    check e.atFrameEnd

suite "regressions":
  test "an empty uncompressed block in every kind of frame":
    for flg in [0x60'u8, 0x40, 0x70, 0x50]:
      var f = frameHeader(flg, 0x40)
      f.add le32(0x8000_0000'u32)
      if (flg and 0x10) != 0:
        f.add le32(xxh32([]))
      f.add le32(3 or 0x8000_0000'u32)
      f.add [1'u8, 2, 3]
      if (flg and 0x10) != 0:
        f.add le32(xxh32([1'u8, 2, 3]))
      f.add le32(0)
      check decompressFrame(f, high(int)) == @[1'u8, 2, 3]
      var r = initRng(93)
      check decodeInChunks(f, r) == @[1'u8, 2, 3]
      check decodeInChunks(f, r, maxChunk = 1) == @[1'u8, 2, 3]

  test "many tiny linked blocks and flushes":
    # Each flush makes a block of a few bytes; the history buffers only
    # move every 64 KiB, so this stays fast.
    let data = textLike(300_000, 94)
    var e = initFrameEncoder(FrameOptions(blockIndependent: false))
    var c: seq[byte]
    var p = 0
    while p < data.len:
      let k = min(data.len - p, 3)
      e.write(data.toOpenArray(p, p + k - 1), c)
      e.flush(c)
      p += k
    e.finish(c)
    check decompressFrame(c, high(int)) == data
    var r = initRng(95)
    check decodeInChunks(c, r) == data
    check decodeInChunks(c, r, clearOutput = true) == data

suite "streaming with high compression and dictionaries":
  test "the HC encoder matches compressFrame":
    var r = initRng(181)
    let big = mixed(4_500_000, 182)
    for opts in [
      FrameOptions(level: 9),
      FrameOptions(level: 9, blockIndependent: false),
      FrameOptions(level: 2, blockIndependent: false),
      FrameOptions(level: 10, blockIndependent: false, blockSize: bs256KiB),
      FrameOptions(level: 3, blockSize: bs1MiB),
    ]:
      check encodeInChunks(big, opts, r) == compressFrame(big, opts)
    let small = textLike(300_000, 183)
    for level in [2, 11, 12]:
      for indep in [true, false]:
        let opts = FrameOptions(level: level, blockIndependent: indep)
        check encodeInChunks(small, opts, r) == compressFrame(small, opts)

  test "HC with flushes still decodes":
    var r = initRng(184)
    let data = mixed(500_000, 185)
    for indep in [true, false]:
      let c = encodeInChunks(
        data, FrameOptions(level: 9, blockIndependent: indep), r, flushes = true
      )
      check decompressFrame(c, high(int)) == data

  test "encoder with a dictionary":
    var r = initRng(186)
    let dict = textLike(80_000, 187)
    var data = dict[5_000 ..< 70_000]
    data.add mixed(400_000, 188)
    let prepared = initFrameDict(dict)
    for level in [0, 2, 9]:
      for indep in [true, false]:
        let opts = FrameOptions(level: level, blockIndependent: indep)
        var e = initFrameEncoder(dict, opts)
        var f = initFrameEncoder(prepared, opts)
        var c, fc: seq[byte]
        var p = 0
        while p < data.len:
          let k = min(data.len - p, 1 + r.below(100_000))
          e.write(data.toOpenArray(p, p + k - 1), c)
          f.write(data.toOpenArray(p, p + k - 1), fc)
          p += k
        e.finish(c)
        f.finish(fc)
        check c == compressFrame(data, dict, opts)
        check fc == c
        check decodeInChunks(c, r, dict = dict, useDict = true) == data
        check decodeInChunks(
          c, r, maxChunk = 3000, clearOutput = true, dict = dict, useDict = true
        ) == data

  test "short HC blocks with a dictionary find its matches":
    # Up to 4 KiB, an independent HC block searches the dictionary's state
    # instead of copying it (C's dictCtx). Pieces of the dictionary must
    # still compress to almost nothing, at every HC level.
    let dict = textLike(65536, 193)
    var r = initRng(194)
    for level in [2, 3, 9, 10, 12]:
      let opts = FrameOptions(level: level)
      var e = initFrameEncoder(dict, opts)
      var plain = initFrameEncoder(opts)
      var c, p: seq[byte]
      var data: seq[byte]
      for i in 0 ..< 40:
        let at = r.below(dict.len - 4096)
        let piece = dict[at ..< at + 200 + r.below(3800)]
        data.add piece
        e.write(piece, c)
        e.flush(c)
        plain.write(piece, p)
        plain.flush(p)
      e.finish(c)
      plain.finish(p)
      check decompressFrame(c, dict, high(int)) == data
      check c.len * 10 < p.len

  test "independent blocks with a dictionary do not depend on the blocks before":
    # Every block starts from the dictionary's state, while the encoder
    # reuses its tables: a short one searches that state (as LZ4F does at
    # the HC levels up to 4 KiB, and at level 2 always), a longer one copies
    # it. Each block is the one a frame of its piece alone holds.
    let dict = textLike(70_000, 195)
    let prepared = initFrameDict(dict)
    var r = initRng(196)
    for (level, usePrepared) in [
      (0, false),
      (-3, false),
      (2, false),
      (9, false),
      (10, false),
      (0, true),
      (-3, true),
      (2, true),
      (9, true),
      (10, true),
    ]:
      var e =
        if usePrepared:
          initFrameEncoder(prepared, FrameOptions(level: level))
        else:
          initFrameEncoder(dict, FrameOptions(level: level))
      var c: seq[byte]
      var pieces: seq[seq[byte]]
      var all: seq[byte]
      for i in 0 ..< 40:
        let n = 1 + r.below([1100, 5000, 9000][r.below(3)])
        let piece =
          if r.below(4) == 0:
            mixed(n, r.next())
          else:
            let at = r.below(dict.len - n)
            dict[at ..< at + n]
        pieces.add piece
        all.add piece
        e.write(piece, c)
        e.flush(c)
      e.finish(c)
      var p = 7 # after the header
      for piece in pieces:
        let size = int(readLE32(c, p) and 0x7FFF_FFFF'u32)
        # A 7-byte header, the block, the end mark.
        let alone =
          compressFrame(piece, dict, FrameOptions(level: level, contentChecksum: false))
        check c[p ..< p + 4 + size] == alone[7 ..< alone.len - 4]
        p += 4 + size
      check decompressFrame(c, dict, high(int)) == all

  test "a FrameDict gives the frames of its dictionary":
    # One-shot (new and reused encoders) and streamed, with and without
    # flushes, at every level: the frames of the dictionary as it is.
    var r = initRng(370)
    var e: FrameEncoder
    for dictLen in [1, 7, 100, 3000, 65536, 90_000]:
      let dict = textLike(dictLen, r.next())
      let prepared = initFrameDict(dict)
      for level in [-3, 0, 1, 2, 3, 6, 9, 10, 11, 12]:
        for indep in [true, false]:
          let n = [0, 3, 13, 200, 4096, 4097, 20_000, 150_000][r.below(8)]
          if level >= 11 and n > 20_000:
            continue # (slow)
          var data = textLike(n, r.next())
          if n > 1000:
            # Pieces of the dictionary, which its state finds.
            for k in 0 ..< 5:
              let at = r.below(n - 100)
              let start = r.below(dictLen)
              let m = min(100, dictLen - start)
              data[at ..< at + m] = dict[start ..< start + m]
          let opts = FrameOptions(
            level: level,
            blockIndependent: indep,
            writeContentSize: r.below(2) == 0,
            contentChecksum: r.below(2) == 0,
          )
          checkpoint $dictLen & " " & $opts & " " & $n
          let want = compressFrame(data, dict, opts)
          check compressFrame(data, prepared, opts) == want
          check e.compressFrame(data, prepared, opts) == want
          let size = if opts.writeContentSize: n.int64 else: -1
          var a = initFrameEncoder(dict, opts, size)
          var b = initFrameEncoder(prepared, opts, size)
          var ca, cb: seq[byte]
          var p = 0
          while p < n:
            let k = min(n - p, [1, 100, 3000, 70_000][r.below(4)])
            a.write(data.toOpenArray(p, p + k - 1), ca)
            b.write(data.toOpenArray(p, p + k - 1), cb)
            if r.below(4) == 0:
              a.flush(ca)
              b.flush(cb)
            p += k
          a.finish(ca)
          b.finish(cb)
          check cb == ca
          check decompressFrame(want, dict, high(int)) == data
    # The string API, and no dictionary: an empty one or none prepared.
    let s = toString(textLike(5000, 371))
    let d = toString(textLike(3000, 372))
    let pd = initFrameDict(d.toOpenArrayByte(0, d.high))
    for level in [0, 9]:
      let opts = FrameOptions(level: level)
      check compress(s, pd, opts) == compress(s, d, opts)
      check e.compress(s, pd, opts) == compress(s, d, opts)
      let data = toBytes(s)
      for none in [FrameDict(), initFrameDict(zeros(0))]:
        check compressFrame(data, none, opts) == compressFrame(data, opts)
        check e.compressFrame(data, none, opts) == compressFrame(data, opts)
        var f = initFrameEncoder(none, opts)
        var o: seq[byte]
        f.write(data, o)
        f.finish(o)
        check o ==
          compressFrame(data, FrameOptions(level: level, blockIndependent: true))

  test "an encoder keeps the FrameDict it was started with":
    # Until finish, whatever happens to the caller's FrameDict.
    let dict = textLike(70_000, 373)
    let data = textLike(200_000, 374)
    proc started(opts: FrameOptions): FrameEncoder =
      let prepared = initFrameDict(dict)
      initFrameEncoder(prepared, opts)

    for level in [0, 9]:
      for indep in [true, false]:
        let opts = FrameOptions(level: level, blockIndependent: indep)
        var e = started(opts)
        var c: seq[byte]
        e.write(data.toOpenArray(0, 99_999), c)
        var e2 = e # (a copy keeps it too)
        var c2 = c
        e = initFrameEncoder(opts) # (drops the copy's)
        e2.write(data.toOpenArray(100_000, data.high), c2)
        e2.finish(c2)
        check c2 == compressFrame(data, dict, opts)

  test "a copy of an encoder continues the frame on its own":
    # The copies used to share the HC state, and then wrote corrupt frames.
    let dict = textLike(80_000, 189)
    let a = textLike(100_000, 190)
    let b = textLike(150_000, 191)
    let c = mixed(150_000, 192)
    let prepared = initFrameDict(dict)
    for level in [0, 2, 9, 12]:
      for indep in [true, false]:
        for (useDict, usePrepared) in [(false, false), (true, false), (true, true)]:
          let opts = FrameOptions(level: level, blockIndependent: indep)
          var e1 =
            if usePrepared:
              initFrameEncoder(prepared, opts)
            elif useDict:
              initFrameEncoder(dict, opts)
            else:
              initFrameEncoder(opts)
          # A copy made before any data, then one made part way.
          var e0 = e1
          var o0, o1: seq[byte]
          e1.write(a, o1)
          var e2 = e1
          var o2 = o1
          e1.write(b, o1)
          e2.write(c, o2)
          e0.write(b, o0)
          e1.finish(o1)
          e2.finish(o2)
          e0.finish(o0)
          if useDict:
            check o1 == compressFrame(a & b, dict, opts)
            check o2 == compressFrame(a & c, dict, opts)
            check o0 == compressFrame(b, dict, opts)
          else:
            check o1 == compressFrame(a & b, opts)
            check o2 == compressFrame(a & c, opts)
            check o0 == compressFrame(b, opts)

suite "reusing a FrameEncoder":
  proc tableMarksHold(e: FrameEncoder, started: bool): bool =
    ## Whether the fast table of `e` holds what its marks say (see
    ## FrameCompressor): next16 is 0 only for a clear table, otherwise above
    ## its 16-bit entries; nextCtx is 0 or above its entries. With
    ## `started`, a linked frame at a fast level has just started, with a
    ## clear table.
    privateAccess(FrameEncoder)
    privateAccess(FrameCompressor)
    let c = e.comp.addr
    let t32 = cast[ptr UncheckedArray[uint32]](c.table.addr)
    let t16 = cast[ptr UncheckedArray[uint16]](c.table.addr)
    let n32 = sizeof(c.table) div 4
    result = true
    if c.next16 == 0 or started and c.linked and c.level < 2:
      for i in 0 ..< n32:
        result = result and t32[i] == 0
    elif c.next16 > 0:
      for i in 0 ..< 2 * n32:
        result = result and int(t16[i]) < c.next16
    if c.nextCtx > 0:
      for i in 0 ..< n32:
        result = result and int(t32[i]) < c.nextCtx

  type
    DictUse = enum
      ## How a frame gets its dictionary. The two prepared ones and the one
      ## as it is differ, so that a frame taking another one's copy left
      ## in the encoder's buffer would give other bytes.
      duNone
      duBytes # `a` as it is
      duPrepared # `b` prepared
      duPreparedA # `a` prepared

    Dicts = object
      a, b: seq[byte]
      pa, pb: FrameDict

  proc initDicts(seed: uint64): Dicts =
    # As long as each other (more than 64 KiB: the last 64 KiB are used).
    result.a = textLike(70_000, seed)
    result.b = textLike(70_000, seed + 1)
    result.pa = initFrameDict(result.a)
    result.pb = initFrameDict(result.b)

  proc oneShot(
      d: Dicts, use: DictUse, src: openArray[byte], opts: FrameOptions
  ): seq[byte] =
    ## The frame of a new encoder, with the dictionary as it is.
    case use
    of duNone:
      compressFrame(src, opts)
    of duBytes, duPreparedA:
      compressFrame(src, d.a, opts)
    of duPrepared:
      compressFrame(src, d.b, opts)

  proc reused(
      e: var FrameEncoder,
      d: Dicts,
      use: DictUse,
      src: openArray[byte],
      opts: FrameOptions,
  ): seq[byte] =
    case use
    of duNone:
      e.compressFrame(src, opts)
    of duBytes:
      e.compressFrame(src, d.a, opts)
    of duPrepared:
      e.compressFrame(src, d.pb, opts)
    of duPreparedA:
      e.compressFrame(src, d.pa, opts)

  proc resetWith(
      e: var FrameEncoder, d: Dicts, use: DictUse, opts: FrameOptions, size = -1'i64
  ) =
    case use
    of duNone:
      e.reset(opts, size)
    of duBytes:
      e.reset(d.a, opts, size)
    of duPrepared:
      e.reset(d.pb, opts, size)
    of duPreparedA:
      e.reset(d.pa, opts, size)

  proc fresh(
      d: Dicts, use: DictUse, src: openArray[byte], opts: FrameOptions, size = -1'i64
  ): seq[byte] =
    ## `src` streamed through a new encoder (with the dictionary as it is).
    var f =
      case use
      of duNone:
        initFrameEncoder(opts, size)
      of duBytes, duPreparedA:
        initFrameEncoder(d.a, opts, size)
      of duPrepared:
        initFrameEncoder(d.b, opts, size)
    f.write(src, result)
    f.finish(result)

  proc streamed(
      e: var FrameEncoder,
      d: Dicts,
      use: DictUse,
      data: openArray[byte],
      opts: FrameOptions,
      r: var Rng,
  ): seq[byte] =
    ## `data` through `e` after reset, in random pieces.
    let size = if opts.writeContentSize: data.len.int64 else: -1
    e.resetWith(d, use, opts, size)
    var p = 0
    while p < data.len:
      let k = min(data.len - p, [1, 100, 4096, 70_000][r.below(4)])
      e.write(data.toOpenArray(p, p + k - 1), result)
      p += k
    e.finish(result)

  test "the frames of new encoders, whatever the frames before":
    # One encoder through frames of every kind in random order, so that
    # each kind follows the others: short and long independent blocks
    # (the 16-bit table reused or not), linked ones, dictionaries (as they
    # are and prepared), the HC levels (lz4mid, hash chains, the optimal
    # parser).
    let d = initDicts(301)
    let pool = textLike(400_000, 302) & mixed(200_000, 303)
    var r = initRng(304)
    var e, s: FrameEncoder
    for round in 0 ..< 400:
      let level = [-3, 0, 0, 1, 2, 3, 9, 10, 12][r.below(9)]
      let size = [0, 5, 200, 900, 1500, 20_000, 70_000, 300_000][r.below(8)]
      if level >= 9 and size > 70_000:
        continue # (slow)
      let at = r.below(pool.len - size)
      let data = pool[at ..< at + size]
      let opts = FrameOptions(
        level: level,
        blockIndependent: r.below(2) == 0,
        blockSize: [bs64KiB, bs256KiB][r.below(2)],
        contentChecksum: r.below(2) == 0,
        writeContentSize: r.below(2) == 0,
      )
      let use = [duNone, duNone, duBytes, duPrepared, duPreparedA][r.below(5)]
      checkpoint $round & ": " & $opts & " " & $size & " " & $use
      check e.reused(d, use, data, opts) == d.oneShot(use, data, opts)
      # The encoder's options as given, as compressFrame gives them to an
      # input that fits in one block.
      let want = d.fresh(use, data, opts, if opts.writeContentSize: size else: -1)
      check s.streamed(d, use, data, opts, r) == want

  test "each kind of frame after each other kind, on the same data":
    # Entries that a frame left in the tables stand for positions of the
    # next frame unless they are cleared or out of reach; with the same
    # data, they find matches (ahead of the position, in a linked block).
    # So does the copy of a dictionary that a frame left in the buffer.
    type Kind = tuple[level: int, indep: bool, use: DictUse, size: int]
    let d = initDicts(312)
    let data = textLike(300_000, 313)
    var kinds: seq[Kind]
    for indep in [true, false]:
      for use in DictUse:
        # `a` prepared tells a copy of `b` left in the buffer from its own,
        # which only independent HC blocks leave there: at the fast levels
        # and in linked frames, it is `b` prepared again.
        let other = use == duPreparedA
        if other and not indep:
          continue
        if not other:
          for size in [200, 1500, 70_000, 200_000, 300_000]:
            kinds.add (0, indep, use, size)
        for level in [2, 9, 10]:
          for size in [200, 5000]:
            kinds.add (level, indep, use, size)
    proc optsOf(k: Kind): FrameOptions =
      FrameOptions(
        level: k.level,
        blockIndependent: k.indep,
        # (200 KB: one block, which the 32-bit table indexes from 0)
        blockSize: if k.size > 70_000: bs256KiB else: bs64KiB,
      )

    var oneShot, streamed: seq[seq[byte]]
    for k in kinds:
      let src = data[0 ..< k.size]
      oneShot.add d.oneShot(k.use, src, optsOf(k))
      streamed.add d.fresh(k.use, src, optsOf(k))
    var e, s: FrameEncoder
    for i, k1 in kinds:
      for j, k2 in kinds:
        if k1.level == 0 != (k2.level == 0) and
            not (
              k1.use in {duPrepared, duPreparedA} and k2.use in {
                duPrepared, duPreparedA
              }
            ):
          # Other tables, and no copy of the same prepared dictionary to
          # leave in the buffer, or to overwrite.
          continue
        for (k, n) in [(k1, i), (k2, j)]:
          let src = data[0 ..< k.size]
          checkpoint $k1 & " then " & $k2
          check e.reused(d, k.use, src, optsOf(k)) == oneShot[n]
          s.resetWith(d, k.use, optsOf(k))
          check e.tableMarksHold(started = false)
          check s.tableMarksHold(started = true)
          var o: seq[byte]
          s.write(src, o)
          s.finish(o)
          check o == streamed[n]
          check s.tableMarksHold(started = false)

  test "strings":
    let s = toString(textLike(5000, 305))
    var e: FrameEncoder
    for level in [0, 9]:
      let opts = FrameOptions(level: level)
      check e.compress(s, opts) == compress(s, opts)
      check e.compress(s, s, opts) == compress(s, s, opts)

  test "reset drops the frame in progress, and is checked first":
    let a = textLike(100_000, 306)
    let b = textLike(30_000, 307)
    for level in [0, 9]:
      for indep in [true, false]:
        let opts = FrameOptions(level: level, blockIndependent: indep)
        var e = initFrameEncoder(opts)
        var o: seq[byte]
        e.write(a, o)
        # A content size the options do not write: nothing changes.
        expectKind ekInvalidArgument:
          e.reset(opts, contentSize = 10)
        expectKind ekInvalidArgument:
          e.reset(FrameOptions(writeContentSize: true))
        e.write(b, o)
        e.finish(o)
        check o == compressFrame(a & b, opts)
        # Part way into a frame again, then a new one.
        var p: seq[byte]
        e.reset(opts)
        e.write(a, p)
        e.reset(opts)
        var q: seq[byte]
        e.write(b, q)
        e.finish(q)
        var f = initFrameEncoder(opts)
        var fq: seq[byte]
        f.write(b, fq)
        f.finish(fq)
        check q == fq

  test "an encoder that initFrameEncoder did not make":
    var e: FrameEncoder
    let data = textLike(3000, 308)
    e.reset(FrameOptions(level: 9))
    var o: seq[byte]
    e.write(data, o)
    e.finish(o)
    check o == compressFrame(data, FrameOptions(level: 9))
    var e2: FrameEncoder
    check e2.compressFrame(data) == compressFrame(data)

  test "a copy of a reused encoder goes on on its own":
    let a = textLike(100_000, 309)
    let b = textLike(80_000, 310)
    let c = mixed(80_000, 311)
    for level in [0, 2, 9]:
      let opts = FrameOptions(level: level, blockIndependent: false)
      var e: FrameEncoder
      discard e.compressFrame(c, opts)
      e.reset(opts)
      var o1: seq[byte]
      e.write(a, o1)
      var e2 = e
      var o2 = o1
      e.write(b, o1)
      e2.write(c, o2)
      e.finish(o1)
      e2.finish(o2)
      check o1 == compressFrame(a & b, opts)
      check o2 == compressFrame(a & c, opts)

suite "string outputs":
  test "the encoder and the decoder write the same bytes to a string":
    var r = initRng(91)
    let data = mixed(300_000, 92)
    for opts in [
      FrameOptions(),
      FrameOptions(blockIndependent: false, blockChecksum: true, contentChecksum: true),
      FrameOptions(level: 9, blockSize: bs64KiB),
    ]:
      # The same pieces and flushes into a seq and into a string.
      var e1 = initFrameEncoder(opts)
      var e2 = initFrameEncoder(opts)
      var a: seq[byte]
      var b: string
      var p = 0
      while p < data.len:
        let k = min(data.len - p, 1 + r.below(100_000))
        e1.write(data.toOpenArray(p, p + k - 1), a)
        e2.write(data.toOpenArray(p, p + k - 1), b)
        if r.below(3) == 0:
          e1.flush(a)
          e2.flush(b)
        p += k
      e1.finish(a)
      e2.finish(b)
      check b == toString(a)
      # Decoded into a string, in pieces (linked blocks keep their history
      # in it).
      var d = initFrameDecoder(high(int64))
      var s: string
      p = 0
      while p < a.len:
        let k = min(a.len - p, 1 + r.below(70_000))
        p += d.feed(a.toOpenArray(p, p + k - 1), s)
      d.finish()
      check s == toString(data)

  test "the string API gives the bytes of the seq API":
    let data = mixed(200_000, 93)
    let s = toString(data)
    check compress(s) == toString(compressFrame(data))
    check compressLegacy(s, 3) == toString(compressLegacyFrame(data, 3))
    check decompress(compress(s), maxOutputSize = s.len) == s
    expectKind ekLimitExceeded:
      discard decompress(compress(s), maxOutputSize = s.len - 1)
    # With a dictionary.
    let dict = textLike(50_000, 94)
    let sd = toString(dict)
    let opts = FrameOptions(level: 9, dictId: 5)
    check compress(s, sd) == toString(compressFrame(data, dict))
    check compress(s, sd, opts) == toString(compressFrame(data, dict, opts))
    check decompress(compress(s, sd, opts), sd, maxOutputSize = s.len) == s
    expectKind ekLimitExceeded:
      discard decompress(compress(s, sd), sd, maxOutputSize = s.len - 1)
