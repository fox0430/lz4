## Random valid blocks and input mutations, shared by the tests that fuzz
## the decoders and by the harnesses in fuzz/.

import std/[importutils, sequtils]
import lz4, lz4/private/[blockimpl, common, hc]
import datagen, blockutil

export blockutil.le32

proc randomLength(r: var Rng): int =
  ## Mostly short lengths, sometimes long ones (to reach the extension
  ## bytes and the 255 boundaries).
  case r.below(5)
  of 0:
    r.below(4)
  of 1:
    r.below(16)
  of 2:
    r.below(40)
  of 3:
    14 + r.below(20)
  else:
    r.below(700)

proc randomBlock*(
    r: var Rng, maxOut: int, prefix: openArray[byte] = []
): tuple[blk, data: seq[byte]] =
  ## A valid block decoding to about `maxOut` bytes or fewer. Matches may
  ## refer into `prefix` (a dictionary or the previous blocks); `data` is the
  ## decoded block without the prefix.
  var all = @prefix
  let target = r.below(maxOut + 1)
  while all.len - prefix.len < target:
    var lits = randomBytes(randomLength(r), r.next())
    if all.len + lits.len == 0:
      lits = @[byte(r.below(256))]
    let avail = min(all.len + lits.len, 65535)
    # Prefer short offsets, which give overlapping matches.
    let offset =
      if r.below(2) == 0:
        1 + r.below(min(avail, 8))
      else:
        1 + r.below(avail)
    let matchLen = 4 + randomLength(r)
    result.blk.add seqBytes(lits, offset, matchLen)
    appendSequence(all, lits, offset, matchLen)
  let last = randomBytes(r.below(20), r.next())
  result.blk.add seqBytes(last, 0, 0, last = true)
  all.add last
  result.data = all[prefix.len .. ^1]

const interesting = [0'u8, 1, 4, 14, 15, 16, 0x0F, 0xF0, 0xFE, 0xFF]

proc mutate*(r: var Rng, s: openArray[byte]): seq[byte] =
  ## Applies 1 to 4 random mutations: bit flips, byte overwrites,
  ## truncation, insertion, deletion, duplication and 16-bit offsets.
  result = @s
  for _ in 0 .. r.below(4):
    let n = result.len
    case r.below(7)
    of 0:
      if n > 0:
        let i = r.below(n)
        result[i] = result[i] xor byte(1 shl r.below(8))
    of 1:
      if n > 0:
        result[r.below(n)] =
          if r.below(2) == 0:
            interesting[r.below(interesting.len)]
          else:
            byte(r.below(256))
    of 2:
      if n > 0:
        result.setLen(r.below(n))
    of 3:
      let at = r.below(n + 1)
      let extra = randomBytes(1 + r.below(8), r.next())
      result.insert(extra, at)
    of 4:
      if n > 0:
        let a = r.below(n)
        let b = min(n, a + 1 + r.below(16))
        result.delete(a ..< b)
    of 5:
      if n > 0:
        let a = r.below(n)
        let b = min(n, a + 1 + r.below(64))
        result.insert(result[a ..< b], r.below(n + 1))
    else:
      if n >= 2:
        let i = r.below(n - 1)
        let v = [0, 1, 2, 7, 8, 255, 256, 65535][r.below(8)]
        result[i] = byte(v and 0xFF)
        result[i + 1] = byte(v shr 8)

proc exactCopy*(s: openArray[byte]): seq[byte] =
  ## A copy whose allocation is exactly `s.len` bytes, so that ASan catches
  ## a read one byte past the end.
  result = newSeqUninit[byte](s.len)
  if s.len > 0:
    copyMem(result[0].addr, s[0].unsafeAddr, s.len)

proc checkDecoders(
    src: openArray[byte], cap: int, dict: openArray[byte], useDict: bool
) =
  ## Decodes `src` with `decompressBlock` and `decompressBlockInto` (with
  ## `dict` when `useDict`), with the same capacity (`maxOutputSize` =
  ## `dst.len` = `cap`), and checks that they agree: the same output on
  ## success, the same error otherwise (ekLimitExceeded for decompressBlock
  ## where decompressBlockInto says ekOutputTooSmall). The input and the
  ## output have exact-size allocations.
  let input = exactCopy(src)
  var viaSeq: seq[byte]
  var seqErr: ref Lz4Error
  try:
    viaSeq =
      if useDict:
        decompressBlock(input, dict, cap)
      else:
        decompressBlock(input, cap)
    doAssert viaSeq.len <= cap
  except Lz4Error as e:
    seqErr = e
  var dst = newSeq[byte](cap)
  var n = -1
  var dstErr: ref Lz4Error
  try:
    n =
      if useDict:
        decompressBlockInto(input, dict, dst)
      else:
        decompressBlockInto(input, dst)
    doAssert n <= cap
  except Lz4Error as e:
    dstErr = e
  if seqErr == nil:
    doAssert dstErr == nil, "only decompressBlockInto failed: " & dstErr.msg
    doAssert n == viaSeq.len and dst[0 ..< n] == viaSeq,
      "decompressBlock and decompressBlockInto decoded different data"
  else:
    doAssert dstErr != nil, "only decompressBlock failed: " & seqErr.msg
    let expected = if seqErr.kind == ekLimitExceeded: ekOutputTooSmall else: seqErr.kind
    doAssert dstErr.kind == expected and dstErr.msg == seqErr.msg,
      "decompressBlock and decompressBlockInto raised " & $seqErr.kind & " (" &
        seqErr.msg & ") and " & $dstErr.kind & " (" & dstErr.msg & ")"

proc checkBlockDecoders*(src: openArray[byte], cap: int) =
  ## See checkDecoders: without a dictionary.
  checkDecoders(src, cap, [], false)

proc checkBlockDecoders*(src: openArray[byte], cap: int, dict: openArray[byte]) =
  ## See checkDecoders: with a dictionary.
  checkDecoders(src, cap, dict, true)

proc checkCompress*(c: var BlockCompressor, data: openArray[byte], cap, level: int) =
  ## Compresses `data` into an exact-size `dst` of `cap` bytes and checks
  ## that the result is 0 (does not fit) or a block that decodes back to
  ## `data`, and that a `dst` of compressBound bytes always works. The
  ## result must be the one of new tables: nothing is carried over.
  let input = exactCopy(data)
  var dst = newSeq[byte](cap)
  let n = c.compressBlockInto(input, dst, level)
  doAssert n >= 0 and n <= cap
  if n > 0:
    doAssert decompressBlock(dst.toOpenArray(0, n - 1), input.len) == input,
      "round trip failed"
  if cap >= compressBound(input.len):
    doAssert n > 0, "compressBound was not enough"
  var fresh = newSeq[byte](cap)
  let m = compressBlockInto(input, fresh, level)
  doAssert m == n and fresh[0 ..< m] == dst[0 ..< n],
    "the compressor carried something over"

proc randomFrameOptions*(r: var Rng): FrameOptions =
  FrameOptions(
    blockSize: BlockSizeId(r.below(4)),
    blockIndependent: r.below(2) == 0,
    blockChecksum: r.below(2) == 0,
    contentChecksum: r.below(2) == 0,
    writeContentSize: r.below(2) == 0,
    level: [0, 0, 1, -1, -5][r.below(5)],
  )

proc usedOptions*(frame: openArray[byte], opts: FrameOptions): FrameOptions =
  ## `opts` with the block size and mode in the header of `frame`, which
  ## compressFrame changes for an input that fits in one block.
  var info: FrameInfo
  doAssert readFrameInfo(frame, info) > 0
  result = opts
  result.blockSize = info.blockSize
  result.blockIndependent = info.blockIndependent

proc randomContent*(r: var Rng, maxLen: int): seq[byte] =
  let n = r.below(maxLen + 1)
  case r.below(4)
  of 0:
    randomBytes(n, r.next())
  of 1:
    textLike(n, r.next())
  of 2:
    repeating(n, 1 + r.below(30), r.next())
  else:
    mixed(n, r.next())

proc randomStream*(r: var Rng, maxLen: int): tuple[stream, content: seq[byte]] =
  ## One to three frames (normal frames with random options, skippable
  ## frames, legacy frames) and the content they decode to.
  for _ in 0 .. r.below(3):
    case r.below(6)
    of 0:
      result.stream.add le32(SkippableMagicBase or uint32(r.below(16)))
      let n = r.below(20)
      result.stream.add le32(uint32(n))
      result.stream.add randomBytes(n, r.next())
    of 1:
      # A legacy frame of up to two blocks. It must be the last frame, or
      # be followed by a frame whose magic cannot be read as a block size
      # (any magic number is larger than LZ4_compressBound(8 MiB)).
      result.stream.add le32(LegacyMagic)
      for _ in 0 .. r.below(2):
        let data = randomContent(r, maxLen div 4)
        let c = compressBlock(data)
        result.stream.add le32(uint32(c.len))
        result.stream.add c
        result.content.add data
    else:
      let data = randomContent(r, maxLen)
      # With the options as given: compressFrame would make most of these
      # short inputs independent 64 KiB frames.
      result.stream.add encodeFrame(data, randomFrameOptions(r))
      result.content.add data

proc checkFrameDecode*(input: openArray[byte], maxOutputSize: int) =
  ## Decoding must succeed within `maxOutputSize` or raise an Lz4Error.
  let src = exactCopy(input)
  try:
    let d = decompressFrame(src, maxOutputSize)
    doAssert d.len <= maxOutputSize
  except Lz4Error:
    discard

proc decodeStream*(
    stream: openArray[byte],
    chunks: openArray[int],
    maxOutputSize = high(int64),
    dict: seq[byte] = @[],
    useDict = false,
    clearOutput = false,
): tuple[ok: bool, kind: Lz4ErrorKind, msg: string, data: seq[byte]] =
  ## Decodes `stream` with a FrameDecoder, feeding it in pieces whose sizes
  ## cycle through `chunks` (all >= 1), and finishes it. With
  ## `clearOutput`, the decoder's output is moved away after every piece,
  ## as a caller writing it to a file would do.
  var d =
    if useDict:
      initFrameDecoder(dict, maxOutputSize)
    else:
      initFrameDecoder(maxOutputSize)
  var output: seq[byte]
  var p = 0
  var k = 0
  try:
    while p < stream.len:
      let stop = min(stream.len, p + chunks[k mod chunks.len])
      inc k
      while p < stop:
        let n = d.feed(stream.toOpenArray(p, stop - 1), output)
        doAssert n >= 1, "feed consumed nothing"
        p += n
      if clearOutput:
        result.data.add output
        output.setLen(0)
    d.finish()
    result.ok = true
  except Lz4Error as e:
    result.ok = false
    result.kind = e.kind
    result.msg = e.msg
  result.data.add output

proc checkStreamMatchesOneShot*(
    input: openArray[byte], chunks: openArray[int], maxOutputSize: int
) =
  ## The streaming decoder must accept exactly what decompressFrame accepts,
  ## with the same output and the same error kind.
  let src = exactCopy(input)
  var oneShot: seq[byte]
  var err: ref Lz4Error
  try:
    oneShot = decompressFrame(src, maxOutputSize)
  except Lz4Error as e:
    err = e
  let s = decodeStream(src, chunks, maxOutputSize)
  if err == nil:
    doAssert s.ok, "only the streaming decoder failed: " & s.msg
    doAssert s.data == oneShot, "the decoders disagree on the output"
  else:
    doAssert not s.ok, "only decompressFrame failed: " & err.msg
    doAssert s.kind == err.kind,
      "error kinds differ: " & $err.kind & " (" & err.msg & ") / " & $s.kind & " (" &
        s.msg & ")"

proc fill(buf: var openArray[byte], seed: uint64) =
  ## Pseudo-random contents, so that a decoder reading bytes it has not
  ## written cannot match the expected output by luck.
  var r = initRng(seed)
  for i in 0 ..< buf.len:
    buf[i] = byte(r.next() and 0xFF)

proc checkSafeFastDecode*(
    blk: openArray[byte], prefix: openArray[byte], cap: int, seed: uint64, dictLen = 0
) =
  ## decodeBlock, safe and fast, must return the same status and,
  ## on success, the same bytes, for a block decoded after `prefix` into a
  ## buffer with room for `cap` bytes. The first `dictLen` bytes of the
  ## prefix are given as an external dictionary (an exact-size copy), the
  ## rest is in the buffer; the result must not depend on where they are.
  let src = exactCopy(blk)
  let dict = exactCopy(prefix.toOpenArray(0, dictLen - 1))
  let inBuf = prefix.len - dictLen
  var a = newSeq[byte](inBuf + cap)
  var b = newSeq[byte](inBuf + cap)
  var c = newSeq[byte](prefix.len + cap)
  fill(a, seed)
  fill(b, seed xor 0xFFFF)
  for i in 0 ..< inBuf:
    a[i] = prefix[dictLen + i]
    b[i] = prefix[dictLen + i]
  for i in 0 ..< prefix.len:
    c[i] = prefix[i]
  var ea, eb, ec = 0
  let sa = decodeBlock(src, a, dict, inBuf, 0, ea, fast = false)
  let sb = decodeBlock(src, b, dict, inBuf, 0, eb, fast = true)
  doAssert sa == sb, "safe and fast decoders disagree: " & $sa & " / " & $sb
  # The length scans, safe and fast, give the same status, and the length
  # of the data.
  var ta, tb = -1
  let la = decodedLength(src, prefix.len, cap, ta, fast = false)
  let lb = decodedLength(src, prefix.len, cap, tb, fast = true)
  doAssert la == sa and lb == sa,
    "the length scans disagree with the decoders: " & $la & " / " & $lb & " / " & $sa
  if sa == dsOk:
    doAssert ta == ea - inBuf and tb == ta, "the length scans give another length"
  # Neither may touch the history in front of the block.
  doAssert a[0 ..< inBuf] == prefix[dictLen ..< prefix.len] and
    b[0 ..< inBuf] == prefix[dictLen ..< prefix.len], "a decoder wrote into the prefix"
  if sa == dsOk:
    doAssert ea == eb and a[inBuf ..< ea] == b[inBuf ..< eb],
      "safe and fast decoders produced different data"
  if dictLen > 0:
    # The same block with the whole history in the buffer.
    let sc = decodeBlock(src, c, c.toOpenArray(0, -1), prefix.len, 0, ec, fast = false)
    doAssert sa == sc,
      "the external dictionary changed the result: " & $sa & " / " & $sc
    if sa == dsOk:
      doAssert a[inBuf ..< ea] == c[prefix.len ..< ec],
        "the external dictionary changed the data"

proc checkDictCompress(data: openArray[byte], cap, acceleration, dictLen: int) =
  ## The last 64 KiB (at most) of the first `dictLen` bytes of `data` as a
  ## dictionary: compressWithDict (safe and fast), with the dictionary in
  ## its own exact-size buffer, must give the result of compressGeneric on
  ## the whole buffer (with the base of the dictionary's table, and
  ## `split`). Every position is indexed for some inputs.
  let tail = dictTail(dictLen)
  let every = data.len mod 2 == 1
  let src = exactCopy(data)
  let dict = exactCopy(data.toOpenArray(tail, dictLen - 1))
  let rest = exactCopy(data.toOpenArray(dictLen, data.high))
  var a = newSeq[byte](cap)
  var b = newSeq[byte](cap)
  var c = newSeq[byte](cap)
  var ta, tb, tc: HashTable
  loadDictTable(ta, src.toOpenArray(tail, src.high), dict.len, every)
  loadDictTable(tb, dict, dict.len, every)
  tc = tb
  let na = compressGeneric(
    ta,
    src,
    dictLen,
    src.len,
    tail,
    tail + dictBase(dict.len),
    a,
    acceleration,
    split = true,
    fast = false,
  )
  let nb = compressWithDict(tb, rest, dict, b, acceleration, fast = false)
  let nc = compressWithDict(tc, rest, dict, c, acceleration, fast = true)
  doAssert na == nb and a[0 ..< na] == b[0 ..< nb],
    "the dictionary in its own buffer changed the result"
  doAssert nb == nc and b[0 ..< nb] == c[0 ..< nc],
    "safe and fast compressors disagree (external dictionary)"
  # The same without copying the dictionary's table (dictCtx), on tables
  # holding old entries, all below `first`.
  var dt: HashTable
  loadDictTable(dt, dict, dict.len, every)
  let first = 1 + (data.len * 7919) mod 100_000
  var td, te: HashTable
  for i in 0 ..< td.len:
    td[i] = uint32((i * 7919) mod first)
  te = td
  var d = newSeq[byte](cap)
  let nd = compressWithDictCtx(td, first, dt, rest, dict, d, acceleration, fast = false)
  let ne = compressWithDictCtx(te, first, dt, rest, dict, c, acceleration, fast = true)
  doAssert na == nd and a[0 ..< na] == d[0 ..< nd],
    "searching the dictionary's table changed the result"
  doAssert nd == ne and d[0 ..< nd] == c[0 ..< ne],
    "safe and fast compressors disagree (dictCtx)"

proc checkSafeFastCompress*(
    data: openArray[byte], cap, acceleration: int, linkedPrefix = 0
) =
  ## compressGeneric, safe and fast, must produce the same result, for both
  ## tables, and for a linked block after `linkedPrefix` bytes of `data`,
  ## which also serve as a dictionary kept apart.
  let src = exactCopy(data)
  var a = newSeq[byte](cap)
  var b = newSeq[byte](cap)
  if linkedPrefix > 0:
    checkDictCompress(data, cap, acceleration, linkedPrefix)
    var ta, tb: HashTable
    # Fill the tables from the prefix the way a previous block would.
    var scratch = newSeq[byte](compressBound(linkedPrefix))
    discard compressGeneric(
      ta, src, 0, linkedPrefix, 0, 0, scratch, acceleration, fast = false
    )
    discard compressGeneric(
      tb, src, 0, linkedPrefix, 0, 0, scratch, acceleration, fast = true
    )
    doAssert ta == tb, "the tables differ after the prefix"
    let na = compressGeneric(
      ta, src, linkedPrefix, src.len, 0, 0, a, acceleration, fast = false
    )
    let nb = compressGeneric(
      tb, src, linkedPrefix, src.len, 0, 0, b, acceleration, fast = true
    )
    doAssert na == nb and a[0 ..< na] == b[0 ..< nb],
      "safe and fast compressors disagree (linked)"
    return
  var ta, tb: HashTable
  let na = compressGeneric(ta, src, 0, src.len, 0, 0, a, acceleration, fast = false)
  let nb = compressGeneric(tb, src, 0, src.len, 0, 0, b, acceleration, fast = true)
  doAssert na == nb and a[0 ..< na] == b[0 ..< nb],
    "safe and fast compressors disagree (32-bit table)"
  # An independent block that does not start at 0 (start = base = lowLimit,
  # as frames compress their blocks).
  if src.len > 1:
    let start = src.len div 3
    var tc, td: HashTable
    let nc = compressGeneric(
      tc, src, start, src.len, start, start, a, acceleration, fast = false
    )
    let nd = compressGeneric(
      td, src, start, src.len, start, start, b, acceleration, fast = true
    )
    doAssert nc == nd and a[0 ..< nc] == b[0 ..< nd],
      "safe and fast compressors disagree (block inside a buffer)"
  if src.len < Limit64K:
    var ua, ub: HashTable16
    let ma = compressGeneric(ua, src, 0, src.len, 0, 0, a, acceleration, fast = false)
    let mb = compressGeneric(ub, src, 0, src.len, 0, 0, b, acceleration, fast = true)
    doAssert ma == mb and a[0 ..< ma] == b[0 ..< mb],
      "safe and fast compressors disagree (16-bit table)"

proc checkCompressDict*(
    c: var BlockCompressor, data, dict: openArray[byte], cap, level: int
) =
  ## compressBlockInto with a dictionary into an exact-size `dst` of `cap`
  ## bytes: 0 or a block that decodes back with the dictionary. `c` must
  ## give the same result.
  let input = exactCopy(data)
  let d = exactCopy(dict)
  var dst = newSeq[byte](cap)
  let n = compressBlockInto(input, d, dst, level)
  doAssert n >= 0 and n <= cap
  if n > 0:
    doAssert decompressBlock(dst.toOpenArray(0, n - 1), d, input.len) == input,
      "round trip with a dictionary failed"
  if cap >= compressBound(input.len):
    doAssert n > 0, "compressBound was not enough (dictionary)"
  var again = newSeq[byte](cap)
  let m = c.compressBlockInto(input, d, again, level)
  doAssert m == n and again[0 ..< m] == dst[0 ..< n],
    "BlockCompressor gave another result with a dictionary"
  let prepared = initBlockDict(d, level)
  for i in 0 ..< 2:
    # The second time from what the first left (see hcRestore).
    let k = c.compressBlockInto(input, prepared, again)
    doAssert k == n and again[0 ..< k] == dst[0 ..< n],
      "a prepared dictionary gave another result"

proc checkSafeFastHCDictCtx*(data: openArray[byte], dictLen, cap, level: int) =
  ## A block after a dictionary of `dictLen` bytes, compressed with a state
  ## of its own that also searches the dictionary's (dictCtx), as frames
  ## compress short blocks. The safe and fast versions must agree, and the
  ## block must decode with the dictionary.
  let src = exactCopy(data)
  # lz4mid searches a dictionary loaded as LZ4F loads it.
  let dictLevel = if usesChains(level): level else: Lz4fDictLevel
  let d = newHcState()
  d[].hcLoadHistory(src, 0, dictLen, dictLevel, apart = true)
  var a = newSeq[byte](max(cap, 0))
  var b = newSeq[byte](max(cap, 0))
  let sa = newHcState()
  let sb = newHcState()
  sa[].hcStart(dictLen, level)
  sb[].hcStart(dictLen, level)
  let na = sa[].hcCompressCtx(src, dictLen, src.len, a, d[], fast = false)
  let nb = sb[].hcCompressCtx(src, dictLen, src.len, b, d[], fast = true)
  doAssert na == nb and a[0 ..< na] == b[0 ..< nb],
    "safe and fast HC compressors disagree (dictCtx)"
  if na > 0:
    doAssert decompressBlock(
      a.toOpenArray(0, na - 1), src.toOpenArray(0, dictLen - 1), src.len - dictLen
    ) == src[dictLen ..< src.len], "round trip failed (dictCtx)"

proc sameState(a, b: HcState): bool =
  ## Whether the tables and positions of `a` and `b` are the same.
  privateAccess(HcState)
  a.hashTable == b.hashTable and
    (not usesChains(a.level) or a.chainTable == b.chainTable) and a.level == b.level and
    a.base == b.base and a.lowLimit == b.lowLimit and a.dictLimit == b.dictLimit and
    a.nextToUpdate == b.nextToUpdate and a.endIdx == b.endIdx and a.dictId == b.dictId

proc checkHcRestore*(src: openArray[byte], h, cap, level: int, fast: static bool) =
  ## A block compressed after the history `src[0 ..< h]` (as a dictionary
  ## of BlockDict) from a copy of its state must leave the history's state
  ## once hcRestore has put it back, also when the output is too small.
  let d = newHcState()
  d[].hcLoadHistory(src, 0, h, level, apart = true)
  d[].setDictId(7)
  let s = newHcState()
  hcCopyState(s[], d[])
  var dst = newSeq[byte](max(cap, 0))
  discard s[].hcCompress(src, h, src.len, dst, fast)
  s[].hcRestore(d[], src, h, src.len, fast)
  doAssert sameState(s[], d[]), "hcRestore left another state"

proc checkSafeFastHC*(data: openArray[byte], cap, level: int, historyLen = 0) =
  ## hcCompress, safe and fast, must produce the same bytes, also
  ## after `historyLen` bytes of `data` loaded as a dictionary (the paths
  ## that reach back into a history), searched as an external one for some
  ## inputs.
  let src = exactCopy(data)
  let apart = data.len mod 3 != 0
  var a = newSeq[byte](max(cap, 0))
  var b = newSeq[byte](max(cap, 0))
  let sa = newHcState()
  let sb = newHcState()
  let h = min(historyLen, src.len)
  if h > 0:
    sa[].hcLoadHistory(src, 0, h, level, apart)
    sb[].hcLoadHistory(src, 0, h, level, apart)
  else:
    sa[].hcStart(0, level)
    sb[].hcStart(0, level)
  let na = sa[].hcCompress(src, h, src.len, a, fast = false)
  let nb = sb[].hcCompress(src, h, src.len, b, fast = true)
  doAssert na == nb and a[0 ..< na] == b[0 ..< nb],
    "safe and fast HC compressors disagree"
  if h > 0 and apart and src.len - h >= MinLength:
    checkHcRestore(src, h, cap, level, fast = false)
    checkHcRestore(src, h, cap, level, fast = true)
