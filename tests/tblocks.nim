## Block format: hand-made blocks and boundary values.

import std/unittest
import lz4, lz4/private/[blockimpl, common, hc]
import datagen, blockutil, fuzzutil, errorcheck

suite "block decompression":
  test "empty block":
    check decompressBlock([0x00'u8], 100).len == 0
    var dst: array[4, byte]
    check decompressBlockInto([0x00'u8], dst) == 0

  test "literal-only blocks of every length class":
    for n in [0, 1, 14, 15, 16, 269, 270, 271, 524, 525, 1000, 70000]:
      let data = randomBytes(n, uint64(n))
      let blk = seqBytes(data, 0, 0, last = true)
      check decompressBlock(blk, n) == data
      var dst = newSeq[byte](n)
      check decompressBlockInto(blk, dst) == n
      check dst == data

  test "overlapping matches (offset 1 to 7, many lengths)":
    for offset in 1 .. 7:
      for matchLen in [
        4, 5, 7, 8, 9, 15, 16, 18, 19, 20, 31, 32, 33, 64, 273, 274, 275, 1000
      ]:
        let lits = randomBytes(offset, uint64(offset))
        var blk = seqBytes(lits, offset, matchLen)
        let tail = randomBytes(5, 99)
        blk.add seqBytes(tail, 0, 0, last = true)
        var expected = expand(lits, offset, matchLen, @[])
        expected.add tail
        check decompressBlock(blk, expected.len) == expected

  test "non-overlapping matches and offset 65535":
    let lits = randomBytes(65535, 5)
    var blk = seqBytes(lits, 65535, 100)
    blk.add seqBytes([1'u8, 2, 3, 4, 5], 0, 0, last = true)
    var expected = expand(lits, 65535, 100, @[])
    expected.add [1'u8, 2, 3, 4, 5]
    check decompressBlock(blk, expected.len) == expected

  test "match length extension boundaries":
    for matchLen in [18, 19, 20, 273, 274, 275, 529, 530, 100_000]:
      let lits = [7'u8, 8, 9]
      var blk = seqBytes(lits, 3, matchLen)
      blk.add seqBytes([], 0, 0, last = true)
      let expected = expand(lits, 3, matchLen, @[])
      check decompressBlock(blk, expected.len) == expected

  test "termination rules 2 and 3 are not enforced":
    # A match that ends right before a 0-length final literal run.
    let lits = [1'u8, 2, 3, 4]
    var blk = seqBytes(lits, 4, 4)
    blk.add seqBytes([], 0, 0, last = true)
    check decompressBlock(blk, 8) == @[1'u8, 2, 3, 4, 1, 2, 3, 4]

  test "maxOutputSize exactly and one below":
    let data = textLike(5000)
    let blk = seqBytes(data, 0, 0, last = true)
    check decompressBlock(blk, 5000) == data
    expectKind ekLimitExceeded:
      discard decompressBlock(blk, 4999)

  test "dst exactly and one too small":
    let lits = [1'u8, 2, 3]
    var blk = seqBytes(lits, 3, 30)
    blk.add seqBytes([9'u8], 0, 0, last = true)
    var dst = newSeq[byte](34)
    check decompressBlockInto(blk, dst) == 34
    var small = newSeq[byte](33)
    expectKind ekOutputTooSmall:
      discard decompressBlockInto(blk, small)

  test "random valid blocks":
    var r = initRng(11)
    for i in 0 ..< 2000:
      let (blk, data) = randomBlock(r, if i mod 10 == 0: 70_000 else: 2000)
      check decompressBlock(blk, data.len) == data
      var dst = newSeq[byte](data.len)
      check decompressBlockInto(blk, dst) == data.len
      check dst == data

  test "mutated blocks raise Lz4Error or decode":
    # Short version of fuzz/fuzz_mutate.nim: anything but success or
    # Lz4Error (a Defect from a missing check) fails the test.
    var r = initRng(12)
    for i in 0 ..< 20_000:
      let (blk, data) = randomBlock(r, 3000)
      let m = mutate(r, blk)
      try:
        discard decompressBlock(m, 1 shl 20)
      except Lz4Error:
        discard
      var dst = newSeq[byte](r.below(data.len + 64))
      try:
        let n = decompressBlockInto(m, dst)
        check n <= dst.len
      except Lz4Error:
        discard

const levels = [low(int), -65537, -65536, -100, -2, -1, 0, 1, 2, 9, 12, 13, high(int)]

suite "block compression":
  test "compressBound":
    check compressBound(0) == 16
    check compressBound(1) == 17
    check compressBound(255) == 255 + 1 + 16
    check compressBound(-1) == 0
    check compressBound(low(int)) == 0
    check compressBound(0x7E000000) == 0x7E000000 + 0x7E000000 div 255 + 16
    check compressBound(0x7E000001) == 0
    check compressBound(high(int)) == 0

  test "empty input is a single 0x00 token":
    check compressBlock(newSeq[byte]()) == @[0x00'u8]
    var dst: array[1, byte]
    check compressBlockInto(newSeq[byte](), dst) == 1
    var none: array[0, byte]
    check compressBlockInto(newSeq[byte](), none) == 0

  test "inputs shorter than 13 bytes are stored as literals":
    for n in 1 .. 12:
      let data = zeros(n)
      let c = compressBlock(data)
      check c.len == n + 1
      check c[0] == byte(n shl 4)
    # 13 bytes is the first length that can hold a match.
    check compressBlock(zeros(13)).len < 14

  test "round trip at every level":
    for (name, data) in standardInputs():
      for level in levels:
        let c = compressBlock(data, level)
        check c.len <= compressBound(data.len)
        if decompressBlock(c, data.len) != data:
          checkpoint name & " level " & $level
          fail()

  test "string API":
    let data = textLike(100_000)
    let dict = textLike(1000, 5)
    let (s, sdict) = (toString(data), toString(dict))
    for level in [0, 9]:
      let c = compressBlock(s, level)
      check c == toString(compressBlock(data, level))
      check decompressBlock(c, s.len) == s
      let cd = compressBlock(s, sdict, level)
      check cd == toString(compressBlock(data, dict, level))
      check decompressBlock(cd, sdict, s.len) == s
    check decompressBlock(compressBlock(""), 0) == ""
    expectKind ekLimitExceeded:
      discard decompressBlock(compressBlock(s), s.len - 1)
    expectKind ekMalformed:
      discard decompressBlock(compressBlock(s, sdict), s.len)

  test "a dst of compressBound bytes is always enough":
    var r = initRng(31)
    for i in 0 ..< 300:
      let data =
        case i mod 3
        of 0:
          randomBytes(r.below(5000), r.next())
        of 1:
          textLike(r.below(5000), r.next())
        else:
          mixed(r.below(20000), r.next())
      var dst = newSeq[byte](compressBound(data.len))
      let n = compressBlockInto(data, dst)
      check n > 0
      check decompressBlock(dst.toOpenArray(0, n - 1), data.len) == data

  test "a small dst gives 0 or a valid block, never more than dst.len":
    var r = initRng(32)
    for i in 0 ..< 2000:
      let data = mixed(r.below(3000), r.next())
      let full = compressBlock(data)
      let cap = r.below(full.len + 20)
      var dst = newSeq[byte](cap)
      let n = compressBlockInto(data, dst)
      check n <= cap
      if n > 0:
        check decompressBlock(dst.toOpenArray(0, n - 1), data.len) == data
      if cap >= full.len:
        check n > 0

  test "BlockCompressor: long input, then short ones":
    # A table left over from the long input would point past the end of the
    # short one. With runtime checks on, that is an IndexDefect here.
    var c: BlockCompressor
    for data in [
      textLike(60_000),
      textLike(1000, 9),
      textLike(100_000, 5),
      repeating(50, 3),
      zeros(20),
      textLike(70_000, 6),
      textLike(13, 2),
    ]:
      var dst = newSeq[byte](compressBound(data.len))
      let n = c.compressBlockInto(data, dst)
      check n > 0
      check decompressBlock(dst.toOpenArray(0, n - 1), data.len) == data
      # The same output as a fresh compressor: nothing is carried over.
      check dst[0 ..< n] == compressBlock(data)

  test "BlockCompressor: short inputs reuse the table, with the same result":
    # Inputs below 1 KiB keep the old entries of the 16-bit table instead
    # of clearing it; longer ones, inputs on the 32-bit table and
    # dictionaries in between make it start again.
    var r = initRng(116)
    var c: BlockCompressor
    for i in 0 ..< 3000:
      let n =
        case r.below(20)
        of 0:
          Limit64K + r.below(20_000)
        of 1, 2:
          1024 + r.below(30_000)
        else:
          r.below(1024)
      let data =
        if r.below(2) == 0:
          textLike(n, r.next())
        else:
          repeating(n, 1 + r.below(30), r.next())
      let level = [0, 0, 1, -1, -20][r.below(5)]
      var dst = newSeq[byte](compressBound(n))
      if r.below(30) == 0:
        let dict = textLike(r.below(70_000), r.next())
        let k = c.compressBlockInto(data, dict, dst, level)
        check decompressBlock(dst.toOpenArray(0, k - 1), dict, data.len) == data
      else:
        let k = c.compressBlockInto(data, dst, level)
        check dst[0 ..< k] == compressBlock(data, level)

  test "a prepared dictionary gives the blocks of the dictionary overloads":
    # One BlockDict per (dictionary, level), shared by two compressors used
    # in turn; inputs on both sides of the dictCtx sizes (DictCtxMax) and of
    # those after which HC puts the dictionary's state back (RestoreMax).
    var r = initRng(118)
    var a, b: BlockCompressor
    for dictLen in [0, 1, 700, 65536, 100_000]:
      let dict = textLike(dictLen, r.next())
      for level in [0, -3, 1, 2, 3, 9, 10, 12]:
        let prepared = initBlockDict(dict, level)
        for size in [0, 12, 13, 300, 1024, 1025, 4096, 4097, 70_000]:
          if level >= 10 and size > 4097:
            continue # (slow)
          let data = textLike(size, r.next())
          var x = newSeq[byte](compressBound(size))
          var y = newSeq[byte](compressBound(size))
          let nx = compressBlockInto(data, dict, x, level)
          let ny =
            if r.below(2) == 0:
              a.compressBlockInto(data, prepared, y)
            else:
              b.compressBlockInto(data, prepared, y)
          check ny == nx and y[0 ..< ny] == x[0 ..< nx]
          check decompressBlock(y.toOpenArray(0, ny - 1), dict, size) == data

  test "a prepared dictionary between other blocks gives the same blocks":
    # Inputs up to 1 KiB keep their entries in the compressor's table from
    # one call to the next and search the prepared table besides; blocks
    # of other kinds in between must not change any result.
    var r = initRng(119)
    var c: BlockCompressor
    let dict = textLike(30_000, r.next())
    let levels = [0, -2]
    let prepared = [initBlockDict(dict, levels[0]), initBlockDict(dict, levels[1])]
    for i in 0 ..< 2000:
      let n =
        case r.below(10)
        of 0:
          1025 + r.below(70_000)
        of 1:
          r.below(13)
        else:
          r.below(1025)
      let data = textLike(n, r.next())
      let k = r.below(2)
      var x = newSeq[byte](compressBound(n))
      var y = newSeq[byte](compressBound(n))
      let nx = compressBlockInto(data, dict, x, levels[k])
      case r.below(5)
      of 0:
        let ny = c.compressBlockInto(data, y, levels[k])
        check y[0 ..< ny] == compressBlock(data, levels[k])
      of 1:
        let ny = c.compressBlockInto(data, dict, y, levels[k])
        check ny == nx and y[0 ..< ny] == x[0 ..< nx]
      else:
        let ny = c.compressBlockInto(data, prepared[k], y)
        check ny == nx and y[0 ..< ny] == x[0 ..< nx]

  test "HC blocks after a prepared dictionary between other blocks":
    # Short blocks leave a copy of the dictionary's state in the compressor
    # (hcRestore), also when the output is too small; blocks of other kinds,
    # other dictionaries and copies of the compressor in between must not
    # change any result.
    var r = initRng(120)
    var c: BlockCompressor
    let dicts = [textLike(30_000, r.next()), textLike(65536, r.next())]
    var prepared: seq[tuple[k, level: int, d: BlockDict]]
    for k in 0 ..< dicts.len:
      for level in [2, 3, 9, 10]:
        prepared.add (k, level, initBlockDict(dicts[k], level))
    var j = 0
    for i in 0 ..< 600:
      if r.below(4) == 0:
        j = r.below(prepared.len)
      let (k, level, d) = prepared[j]
      let n =
        case r.below(8)
        of 0:
          4097 + r.below(5000)
        of 1:
          r.below(13)
        else:
          r.below(4097)
      let data =
        if r.below(2) == 0:
          textLike(n, r.next())
        else:
          mixed(n, r.next())
      let bound = compressBound(n)
      let cap =
        if r.below(5) == 0:
          r.below(bound + 1)
        else:
          bound
      var x = newSeq[byte](cap)
      var y = newSeq[byte](cap)
      let nx = compressBlockInto(data, dicts[k], x, level)
      case r.below(8)
      of 0:
        let ny = c.compressBlockInto(data, y, level)
        check ny == compressBlockInto(data, x, level) and y[0 ..< ny] == x[0 ..< ny]
      of 1:
        let ny = c.compressBlockInto(data, dicts[k], y, level)
        check ny == nx and y[0 ..< ny] == x[0 ..< nx]
      of 2:
        var e = c
        let ny = e.compressBlockInto(data, d, y)
        check ny == nx and y[0 ..< ny] == x[0 ..< nx]
      else:
        let ny = c.compressBlockInto(data, d, y)
        check ny == nx and y[0 ..< ny] == x[0 ..< nx]

  test "BlockCompressor with a dictionary gives the same blocks":
    var r = initRng(117)
    var c: BlockCompressor
    for i in 0 ..< 200:
      let dict = textLike(r.below(80_000), r.next())
      let data = textLike(r.below(5000), r.next())
      let level = [0, -3, 2, 3, 9, 10, 12][r.below(7)]
      var a = newSeq[byte](compressBound(data.len))
      var b = newSeq[byte](compressBound(data.len))
      let na = compressBlockInto(data, dict, a, level)
      let nb = c.compressBlockInto(data, dict, b, level)
      check na == nb and a[0 ..< na] == b[0 ..< nb]
      check decompressBlock(b.toOpenArray(0, nb - 1), dict, data.len) == data
      # And without a dictionary in between.
      discard c.compressBlockInto(data, b, level)

  test "level to acceleration":
    check accelerationOf(low(int)) == 65537
    check accelerationOf(-65537) == 65537
    check accelerationOf(-65536) == 65537
    check accelerationOf(-65535) == 65536
    check accelerationOf(-2) == 3
    check accelerationOf(-1) == 2
    for level in [0, 1, 2, 3, 9, 10, 12, 13, 100, high(int)]:
      check accelerationOf(level) == 1

  test "an input above LZ4_MAX_INPUT_SIZE raises ekLimitExceeded":
    # newSeqUninit does not touch the pages, so this does not need 2 GiB of
    # memory; the check happens before any byte is read.
    when sizeof(int) == 8:
      let big = newSeqUninit[byte](0x7E000001)
      expectKind ekLimitExceeded:
        discard compressBlock(big)
      var dst = newSeq[byte](16)
      expectKind ekLimitExceeded:
        discard compressBlockInto(big, dst)
      var c: BlockCompressor
      expectKind ekLimitExceeded:
        discard c.compressBlockInto(big, dst)

suite "safe and fast versions":
  test "the decoders agree on valid, mutated and dictionary blocks":
    var r = initRng(111)
    for i in 0 ..< 20_000:
      let prefix =
        if i mod 3 == 0:
          randomBytes(r.below(70_000), r.next())
        else:
          newSeq[byte]()
      let (blk, data) = randomBlock(r, 3000, prefix)
      let m =
        if i mod 2 == 0:
          blk
        else:
          mutate(r, blk)
      let cap =
        case r.below(4)
        of 0:
          data.len
        of 1:
          r.below(data.len + 1)
        of 2:
          data.len + r.below(40)
        else:
          data.len + 100
      checkSafeFastDecode(m, prefix, cap, r.next(), r.below(prefix.len + 1))

  test "the compressors agree, byte for byte":
    var r = initRng(112)
    for i in 0 ..< 600:
      let data =
        case i mod 4
        of 0:
          textLike(r.below(100_000), r.next())
        of 1:
          mixed(r.below(200_000), r.next())
        of 2:
          repeating(r.below(70_000), 1 + r.below(20), r.next())
        else:
          randomBytes(r.below(3000), r.next())
      let bound = compressBound(data.len)
      let cap =
        if r.below(3) == 0:
          r.below(bound + 1)
        else:
          bound
      let accel = [1, 1, 2, 9, 65537][r.below(5)]
      checkSafeFastCompress(data, cap, accel)
      if data.len > 20:
        checkSafeFastCompress(data, cap, accel, r.below(data.len))

  test "the 16-bit table is used below LZ4_64Klimit (65547 bytes)":
    for n in [65535, 65536, 65546, 65547, 65548, 70_000]:
      let data = textLike(n, uint64(n))
      var dst = newSeq[byte](compressBound(n))
      var t16: HashTable16
      var t32: HashTable
      let expected =
        if n < 65547:
          dst[0 ..< compressGeneric(t16, data, 0, n, 0, 0, dst, 1)]
        else:
          dst[0 ..< compressGeneric(t32, data, 0, n, 0, 0, dst, 1)]
      check compressBlock(data) == expected
      check decompressBlock(expected, n) == data

suite "block decompression with a dictionary":
  test "random blocks referring into the dictionary":
    var r = initRng(121)
    for i in 0 ..< 3000:
      let dict = randomBytes(r.below(100_000), r.next())
      let usable = dict[max(0, dict.len - 65536) .. ^1]
      let (blk, data) = randomBlock(r, 3000, usable)
      check decompressBlock(blk, dict, data.len) == data
      var dst = newSeq[byte](data.len)
      check decompressBlockInto(blk, dict, dst) == data.len
      check dst == data

  test "matches that start in the dictionary and go on in the output":
    # The dictionary is kept apart from the output: a match that starts in
    # it goes on from the first byte of the output, which it may be writing
    # itself.
    let dict = toBytes("abcdefgh")
    for (lits, offset, matchLen) in [
      ("XY", 6, 4),
      ("XY", 4, 4),
      ("XY", 4, 10),
      ("XYZW", 9, 30),
      ("", 8, 8),
      ("", 3, 20),
    ]:
      var blk = seqBytes(toBytes(lits), offset, matchLen)
      blk.add seqBytes(toBytes("!"), 0, 0, last = true)
      let full = expand(toBytes(lits), offset, matchLen, dict)
      let expected = full[dict.len .. ^1] & toBytes("!")
      check decompressBlock(blk, dict, expected.len + 10) == expected
      var dst = newSeq[byte](expected.len)
      check decompressBlockInto(blk, dict, dst) == expected.len
      check dst == expected

  test "limits and errors":
    let dict = textLike(1000)
    var blk = seqBytes([], 1000, 50)
    blk.add seqBytes([1'u8], 0, 0, last = true)
    check decompressBlock(blk, dict, 51) == dict[0 ..< 50] & @[1'u8]
    expectKind ekLimitExceeded:
      discard decompressBlock(blk, dict, 50)
    var small = newSeq[byte](50)
    expectKind ekOutputTooSmall:
      discard decompressBlockInto(blk, dict, small)
    # One byte too far back.
    expectKind ekMalformed:
      discard decompressBlock(blk, dict[1 .. ^1], 100)
    var dst = newSeq[byte](100)
    expectKind ekMalformed:
      discard decompressBlockInto(blk, dict[1 .. ^1], dst)
    # An empty dictionary is no dictionary.
    expectKind ekMalformed:
      discard decompressBlock(blk, newSeq[byte](), 100)
    expectKind ekInvalidArgument:
      discard decompressBlock(blk, dict, -1)

suite "high compression (levels 2 to 12)":
  test "round trip at every level":
    for (name, data) in standardInputs():
      let levels =
        if data.len > 300_000:
          @[3, 9]
        else:
          @[2, 3, 4, 6, 9, 10, 11, 12, 13, high(int)]
      for level in levels:
        let c = compressBlock(data, level)
        check c.len <= compressBound(data.len)
        if decompressBlock(c, data.len) != data:
          checkpoint name & " level " & $level
          fail()

  test "higher levels compress text better than the fast level":
    let data = textLike(300_000)
    let fast = compressBlock(data).len
    let l3 = compressBlock(data, 3).len
    let l12 = compressBlock(data, 12).len
    check l3 < fast
    check l12 < l3

  test "a small dst gives 0 or a valid block":
    var r = initRng(141)
    for i in 0 ..< 300:
      let data = mixed(r.below(5000), r.next())
      let level = [2, 3, 9, 10, 12][r.below(5)]
      let full = compressBlock(data, level)
      let cap = r.below(full.len + 20)
      var dst = newSeq[byte](cap)
      let n = compressBlockInto(data, dst, level)
      check n <= cap
      if n > 0:
        check decompressBlock(dst.toOpenArray(0, n - 1), data.len) == data
      if cap >= full.len:
        check n > 0

  test "BlockCompressor reuses its HC state without carrying data over":
    var c: BlockCompressor
    for (data, level) in [
      (textLike(60_000), 9),
      (textLike(1000, 9), 9),
      (textLike(100_000, 5), 12),
      (repeating(50, 3), 3),
      (zeros(20), 10),
      (textLike(70_000, 6), 0),
      (textLike(5000, 2), 11),
    ]:
      var dst = newSeq[byte](compressBound(data.len))
      let n = c.compressBlockInto(data, dst, level)
      check n > 0
      check dst[0 ..< n] == compressBlock(data, level)
      check decompressBlock(dst.toOpenArray(0, n - 1), data.len) == data

  test "HC indexes stay in an int32 for inputs up to LZ4_MAX_INPUT_SIZE":
    # Every history starts 64 KiB past the previous one. The indexes must
    # restart early enough for a block of MaxInputSize bytes to fit (32-bit
    # systems); `base` is the index of position 0.
    let s = newHcState()
    var highest = 0
    for i in 0 ..< 20_000:
      s[].hcStart(0, 9)
      highest = max(highest, s[].base)
    check highest <= int(high(int32)) - MaxInputSize - WindowSize

  test "an HcBox copies a carried state only, and never shares one":
    var linked = newHcBox(carried = true)
    linked[].hcStart(1000, 9)
    var a = linked
    check not a.isEmpty and a[].addr != linked[].addr
    check a[].base == linked[].base
    var scratch = newHcBox(carried = false)
    var b = scratch
    check b.isEmpty
    var c = newHcBox(carried = false)
    let own = c[].addr
    c = scratch
    check c[].addr == own
    c = linked
    check c[].addr == own and c[].base == linked[].base
    # A carried history does not stay behind in a box that is not carried.
    c = scratch
    check c.isEmpty

  test "a copy of a BlockCompressor compresses on its own":
    # Its HC states are not copied (each call starts them again): the copy
    # makes its own, so copies never write the same tables.
    let data = textLike(50_000, 144)
    let dict = textLike(20_000, 145)
    var c: BlockCompressor
    var dst = newSeq[byte](compressBound(data.len))
    for level in [0, 2, 9]:
      discard c.compressBlockInto(data, dst, level)
      discard c.compressBlockInto(data.toOpenArray(0, 999), dict, dst, level)
      var d = c
      for (a, b) in [(addr c, addr d), (addr d, addr c)]:
        let n = a[].compressBlockInto(data, dst, level)
        check dst[0 ..< n] == compressBlock(data, level)
        let m = b[].compressBlockInto(data.toOpenArray(0, 999), dict, dst, level)
        var want = newSeq[byte](compressBound(1000))
        let k = compressBlockInto(data.toOpenArray(0, 999), dict, want, level)
        check dst[0 ..< m] == want[0 ..< k]
  test "the HC output does not change when the indexes restart":
    # Every call moves the indexes on by more than 64 KiB, so they restart
    # about every 500 calls.
    var r = initRng(143)
    var c: BlockCompressor
    for i in 0 ..< 1500:
      let data = textLike(r.below(3000), r.next())
      let level = [2, 3, 9, 10, 12][r.below(5)]
      var dst = newSeq[byte](compressBound(data.len))
      let n = c.compressBlockInto(data, dst, level)
      check dst[0 ..< n] == compressBlock(data, level)

  test "the safe and fast HC compressors agree":
    var r = initRng(142)
    for i in 0 ..< 150:
      let data =
        case i mod 3
        of 0:
          textLike(r.below(60_000), r.next())
        of 1:
          mixed(r.below(60_000), r.next())
        else:
          repeating(r.below(20_000), 1 + r.below(8), r.next())
      let level = [2, 3, 5, 9, 10, 11, 12][r.below(7)]
      let bound = compressBound(data.len)
      let cap =
        if r.below(3) == 0:
          r.below(bound + 1)
        else:
          bound
      checkSafeFastHC(data, cap, level)
      # With part of the data as a dictionary in front.
      checkSafeFastHC(data, cap, level, r.below(data.len + 1))

  test "short HC blocks that search the dictionary's state (dictCtx)":
    var r = initRng(145)
    for i in 0 ..< 300:
      let dictLen = 1 + r.below(70_000)
      var data = textLike(dictLen, r.next())
      data.add(
        if r.below(2) == 0:
          textLike(r.below(4097), r.next())
        else:
          mixed(r.below(4097), r.next())
      )
      let level = [2, 3, 9, 10, 12][r.below(5)]
      let bound = compressBound(data.len - dictLen)
      let cap =
        if r.below(3) == 0:
          r.below(bound + 1)
        else:
          bound
      checkSafeFastHCDictCtx(data, dictLen, cap, level)

suite "block compression with a dictionary":
  test "fast and HC round trips":
    var r = initRng(151)
    for i in 0 ..< 200:
      let dict = textLike(r.below(100_000), r.next())
      var data = dict[r.below(dict.len + 1) ..< dict.len]
      data.add textLike(r.below(20_000), r.next())
      let level = [0, 0, -3, 2, 3, 9, 12][r.below(7)]
      var dst = newSeq[byte](compressBound(data.len))
      let n = compressBlockInto(data, dict, dst, level)
      check n > 0
      check decompressBlock(dst.toOpenArray(0, n - 1), dict, data.len) == data

  test "a dictionary makes related data smaller":
    let dict = textLike(65536, 152)
    let data = dict[10_000 ..< 30_000] & textLike(2000, 153)
    for level in [0, 9]:
      var withDict = newSeq[byte](compressBound(data.len))
      let n = compressBlockInto(data, dict, withDict, level)
      check n < compressBlock(data, level).len div 2

  test "an empty dictionary is the same as none":
    let data = textLike(10_000)
    for level in [0, 9]:
      var dst = newSeq[byte](compressBound(data.len))
      let n = compressBlockInto(data, newSeq[byte](), dst, level)
      check dst[0 ..< n] == compressBlock(data, level)

  test "a dictionary is never taken for the output":
    # The dictionary procs return a seq or take a dst after the dictionary;
    # the procs that write into a dst have another name, so a mutable
    # dictionary cannot stand for their dst.
    var dict = textLike(5000, 154)
    let saved = dict
    let data = dict[1000 ..< 3000] & textLike(500, 155)
    for level in [0, 9]:
      let blk = compressBlock(data, dict, level)
      var dst = newSeq[byte](compressBound(data.len))
      check blk == dst[0 ..< compressBlockInto(data, dict, dst, level)]
      check decompressBlock(blk, dict, data.len) == data
    check compressBlock(data, dict) == compressBlock(data, dict, 0)
    check dict == saved
    var c: BlockCompressor
    check not compiles(decompressBlock(compressBlock(data), dict))
    check not compiles(c.compressBlock(data, dict))
