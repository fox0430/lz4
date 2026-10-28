## Cross-checks against liblz4 (through tests/clz4.nim).

import std/[os, strutils, unittest]
import lz4, lz4/private/blockimpl
import blockutil, clz4, datagen, fuzzutil

const expectedVersion = 11000 # 1.10.0

let libVersion = LZ4_versionNumber()
let versionOk = libVersion == expectedVersion
if not versionOk:
  if existsEnv("CI"):
    quit "liblz4 " & $libVersion & " found, " & $expectedVersion & " required", 1
  echo "liblz4 ",
    libVersion, " is not 1.10.0: the tests that depend on ",
    "its exact behaviour will be skipped"

template withExactVersion(body: untyped) =
  ## Runs `body` only when liblz4 is 1.10.0, and marks the test skipped
  ## otherwise. Every test that relies on behaviour checked against 1.10.0
  ## is wrapped in it.
  if versionOk:
    body
  else:
    skip()

suite "liblz4 binding":
  test "round trip through liblz4 itself":
    for (name, data) in standardInputs():
      let c = libCompress(data)
      let (ok, d) = libDecompress(c, data.len)
      check ok
      check d == data

suite "liblz4 compressed blocks -> decompressBlock":
  test "LZ4_compress_fast, several accelerations":
    for (name, data) in standardInputs():
      for accel in [1, 2, 17, 65537]:
        let c = libCompress(data, accel)
        check decompressBlock(c, data.len) == data
        var dst = newSeq[byte](data.len)
        check decompressBlockInto(c, dst) == data.len
        check dst == data

  test "LZ4_compress_HC, levels 1 to 12":
    for (name, data) in standardInputs():
      if data.len > 200_000:
        continue
      for level in 1 .. 12:
        let c = libCompressHC(data, level)
        check decompressBlock(c, data.len) == data

  test "corpus files":
    for f in corpusFiles():
      let data = readBytes(f)
      for c in [libCompress(data), libCompressHC(data, 9)]:
        check decompressBlock(c, data.len) == data

suite "differential against LZ4_decompress_safe":
  test "random and mutated blocks: liblz4 success implies ours":
    withExactVersion:
      # One direction only: when liblz4 decodes a block into a buffer of a
      # given capacity, so must we, with the same result.
      # Offset 0, which liblz4 accepts and we reject, is the one exception.
      var r = initRng(21)
      var libOk, bothOk = 0
      for i in 0 ..< 30_000:
        let (blk, data) = randomBlock(r, 3000)
        let m =
          if i mod 4 == 0:
            blk
          else:
            mutate(r, blk)
        let cap =
          case r.below(3)
          of 0:
            data.len
          of 1:
            r.below(data.len + 1)
          else:
            data.len + r.below(100)
        let (ok, expected) = libDecompress(m, cap)
        if not ok:
          continue
        inc libOk
        var dst = newSeq[byte](cap)
        try:
          let n = decompressBlockInto(m, dst)
          check n == expected.len
          check dst[0 ..< n] == expected
          inc bothOk
        except Lz4Error as e:
          if "offset 0" notin e.msg:
            checkpoint "liblz4 accepted, we raised " & $e.kind & ": " & e.msg
            fail()
      check libOk > 1000

suite "compressBlock -> liblz4":
  test "LZ4_decompress_safe decodes our blocks":
    for (name, data) in standardInputs():
      for level in [0, -1, -50]:
        let c = compressBlock(data, level)
        let (ok, d) = libDecompress(c, data.len)
        check ok
        check d == data
    for f in corpusFiles():
      let data = readBytes(f)
      let (ok, d) = libDecompress(compressBlock(data), data.len)
      check ok
      check d == data

  test "compression ratio within 1 % of LZ4_compress_default":
    # Whole inputs (the 32-bit table) and 64 KiB pieces (the 16-bit table),
    # at accelerations 1 and 8. The outputs are not required to be
    # identical; how many are is printed for information.
    var inputs: seq[seq[byte]]
    for f in corpusFiles(200):
      inputs.add readBytes(f)
    inputs.add textLike(1 shl 20)
    inputs.add mixed(4 shl 20)
    for level in [0, -7]:
      var ours, lib, same, total = 0
      for data in inputs:
        var pieces = @[data]
        var p = 0
        while p < data.len:
          pieces.add data[p ..< min(data.len, p + 65536)]
          p += 65536
        for piece in pieces:
          let c = compressBlock(piece, level)
          let l = libCompress(piece, accelerationOf(level))
          ours += c.len
          lib += l.len
          inc total
          if c == l:
            inc same
      echo "    level ",
        level, ": ours ", ours, " bytes, liblz4 ", lib, " bytes; ", same, " of ", total,
        " outputs identical"
      check float(ours) <= float(lib) * 1.01

suite "frames and LZ4F_decompress":
  test "LZ4F_decompress decodes our frames (every option)":
    let data = mixed(300_000, 61)
    for opts in allFrameOptions():
      for f in [compressFrame(data, opts), encodeFrame(data, opts)]:
        let (ok, consumed, d) = libDecompressFrame(f)
        check ok
        check consumed == f.len
        check d == data

  test "random and mutated frames: LZ4F success implies ours":
    withExactVersion:
      var r = initRng(62)
      var libOk = 0
      for i in 0 ..< 3000:
        let (stream, content) = randomStream(r, 20_000)
        let m =
          if i mod 4 == 0:
            stream
          else:
            mutate(r, stream)
        let (ok, consumed, expected) = libDecompressFrame(m)
        if not ok:
          continue
        inc libOk
        try:
          check decompressFrame(m.toOpenArray(0, consumed - 1), high(int)) == expected
        except Lz4Error as e:
          if "offset 0" notin e.msg:
            checkpoint "LZ4F accepted, we raised " & $e.kind & ": " & e.msg
            fail()
      check libOk > 500

suite "FrameEncoder and LZ4F's compression":
  test "the frames of LZ4F_compressUpdate and LZ4F_flush":
    # Writes shorter than a block, which LZ4F compresses one after the other
    # in its own buffer (it compresses longer ones where they are, and its
    # linked blocks then search their history in other ways). Flushes,
    # except in linked frames with a dictionary at the fast levels (see
    # README). The pieces of the dictionary that run into its end tell
    # apart the ways a block can search it: a short first block searches
    # the dictionary's state, a longer one a copy of it.
    withExactVersion:
      var r = initRng(142)
      for i in 0 ..< 240:
        let dictLen = [0, 100, 2000, 20_000, 65536, 70_000][r.below(6)]
        let dict = textLike(dictLen, r.next())
        let n = [50, 1000, 4096, 4097, 20_000, 70_000, 150_000][r.below(7)]
        let text = textLike(n + 100, r.next())
        var data: seq[byte]
        while data.len < n:
          if dictLen > 0 and r.below(2) == 0:
            data.add dict[dictLen - 1 - r.below(min(dictLen, 300)) ..< dictLen]
          else:
            let s = r.below(n)
            data.add text[s ..< s + 1 + r.below(99)]
        data.setLen(n)
        let level = [-3, 0, 2, 3, 6, 9, 10, 12][i mod 8]
        let linked = r.below(3) != 0
        let flushes = not (linked and dictLen > 0 and level < 2)
        var writes: seq[tuple[len: int, flush: bool]]
        var p = 0
        while p < n:
          let k = min(n - p, 1 + r.below(if r.below(2) == 0: 5000 else: 65535))
          writes.add (k, flushes and r.below(2) == 0)
          p += k
        let opts = FrameOptions(blockIndependent: not linked, level: level)
        # With the dictionary as it is, and prepared (LZ4F_createCDict
        # prepares it for every frame).
        var e = initFrameEncoder(dict, opts)
        var f = initFrameEncoder(initFrameDict(dict), opts)
        var frame, prepared: seq[byte]
        p = 0
        for w in writes:
          e.write(data.toOpenArray(p, p + w.len - 1), frame)
          f.write(data.toOpenArray(p, p + w.len - 1), prepared)
          if w.flush:
            e.flush(frame)
            f.flush(prepared)
          p += w.len
        e.finish(frame)
        f.finish(prepared)
        let lib = libCompressFrameStream(data, dict, writes, level, linked)
        check frame == lib
        check prepared == lib

suite "dictionaries and liblz4":
  test "blocks compressed with LZ4_loadDict decode with decompressBlock":
    var r = initRng(131)
    for i in 0 ..< 200:
      let dict = textLike(r.below(150_000), r.next())
      var data = dict[r.below(dict.len + 1) ..< dict.len]
      data.add textLike(r.below(100_000), r.next())
      let c = libCompressDict(data, dict)
      check decompressBlock(c, dict, data.len) == data
      for level in [2, 9]:
        let h = libCompressHCDict(data, dict, level)
        check decompressBlock(h, dict, data.len) == data

  test "blocks with a dictionary equal LZ4_loadDict(HC) and *_continue":
    # compressBlock with a dictionary, a BlockCompressor and a BlockDict
    # alike, at every level: dictionaries from a few bytes to beyond 64 KiB,
    # blocks on both sides of the sizes where a short block searches the
    # dictionary's table (fast levels) or leaves the compressor a copy of
    # its state (HC levels, used by the second block).
    withExactVersion:
      var r = initRng(133)
      for i in 0 ..< 400:
        let dictLen = [1, 7, 8, 100, 3000, 40_000, 65536, 90_000][r.below(8)]
        let dict =
          if r.below(3) == 0:
            mixed(dictLen, r.next())
          else:
            textLike(dictLen, r.next())
        let n = [13, 200, 1024, 1025, 4096, 4097, 20_000, 70_000][r.below(8)]
        var data = dict[r.below(dict.len) ..< dict.len]
        data.add mixed(n, r.next())
        data.setLen(n)
        let level = [-9, -1, 0, 2, 3, 6, 8, 9, 10, 11, 12][i mod 11]
        let lib =
          if level < 2:
            libCompressDict(data, dict, accelerationOf(level))
          else:
            libCompressHCDict(data, dict, level)
        var dst = newSeq[byte](compressBound(n))
        check dst[0 ..< compressBlockInto(data, dict, dst, level)] == lib
        var c: BlockCompressor
        check dst[0 ..< c.compressBlockInto(data, dict, dst, level)] == lib
        let prepared = initBlockDict(dict, level)
        for k in 0 ..< 2:
          check dst[0 ..< c.compressBlockInto(data, prepared, dst)] == lib

  test "differential with LZ4_decompress_safe_usingDict":
    withExactVersion:
      var r = initRng(132)
      for i in 0 ..< 10_000:
        let dict = randomBytes(r.below(70_000), r.next())
        let usable = dict[max(0, dict.len - 65536) .. ^1]
        let (blk, data) = randomBlock(r, 2000, usable)
        let m =
          if i mod 2 == 0:
            blk
          else:
            mutate(r, blk)
        let cap = data.len + r.below(50)
        let (ok, expected) = libDecompressDict(m, dict, cap)
        if not ok:
          continue
        var dst = newSeq[byte](cap)
        try:
          let n = decompressBlockInto(m, dict, dst)
          check n == expected.len
          check dst[0 ..< n] == expected
          check decompressBlock(m, dict, cap) == expected
        except Lz4Error as e:
          if "offset 0" notin e.msg:
            checkpoint "liblz4 accepted, we raised " & $e.kind & ": " & e.msg
            fail()

suite "high compression and liblz4":
  test "LZ4_decompress_safe decodes our HC blocks; sizes within 1 % of LZ4_compress_HC":
    var inputs: seq[seq[byte]]
    for f in corpusFiles(60):
      inputs.add readBytes(f)
    inputs.add textLike(300_000)
    inputs.add mixed(300_000)
    for level in [2, 3, 6, 9, 10, 11, 12]:
      var ours, lib, same = 0
      for data in inputs:
        let c = compressBlock(data, level)
        let (ok, d) = libDecompress(c, data.len)
        check ok
        check d == data
        let l = libCompressHC(data, level)
        ours += c.len
        lib += l.len
        if c == l:
          inc same
      echo "    level ",
        level, ": ours ", ours, " bytes, liblz4 ", lib, " bytes; ", same, " of ",
        inputs.len, " outputs identical"
      check float(ours) <= float(lib) * 1.01

  test "dictionary blocks decode with LZ4_decompress_safe_usingDict":
    var r = initRng(161)
    for i in 0 ..< 60:
      let dict = textLike(r.below(150_000) + 1000, r.next())
      var data = dict[r.below(dict.len) ..< dict.len]
      data.add textLike(r.below(50_000), r.next())
      for level in [0, 2, 9, 12]:
        var dst = newSeq[byte](compressBound(data.len))
        let n = compressBlockInto(data, dict, dst, level)
        let (ok, d) = libDecompressDict(dst.toOpenArray(0, n - 1), dict, data.len)
        check ok
        check d == data
