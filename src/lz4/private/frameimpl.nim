## Internal module, not part of the API: frame headers, block compression
## and decoding for the frame encoder and decoder of `lz4/streaming`.

import common, blockimpl, hc, xxhash32

const
  LegacyMaxStored* = LegacyBlockSize + LegacyBlockSize div 255 + 16
    ## Largest stored block of a legacy frame; a larger value is the magic
    ## number of the next frame.
  RebaseLimit = 1 shl 30 ## See prepareLinked.
  LegacyFrameInfo* = FrameInfo(kind: fkLegacy, blockIndependent: true)

func blockSizeBytes*(id: BlockSizeId): int =
  1 shl (16 + 2 * ord(id))

# Header

func headerLength*(flg: byte): int =
  ## The length of a frame header, magic number and header checksum
  ## included, for this FLG byte.
  7 + (if (flg and 0x08) != 0: 8 else: 0) + (if (flg and 0x01) != 0: 4 else: 0)

proc checkFlg*(flg: byte) {.raises: [Lz4Error].} =
  ## Validates the version and the reserved bit of an FLG byte.
  if (flg shr 6) != 1:
    raiseLz4(ekMalformed, "unsupported frame version")
  if (flg and 0x02) != 0:
    raiseLz4(ekMalformed, "reserved bit set in the frame descriptor (FLG)")

proc parseHeader*(
    src: openArray[byte], pos: int, info: var FrameInfo
): int {.raises: [Lz4Error].} =
  ## Reads the normal frame header at `pos` (the magic is already known).
  ## Returns its length, or 0 when the input ends first. Present fields are
  ## validated even then, so a bad FLG or BD fails as early as possible.
  let avail = src.len - pos
  if avail < 5:
    return 0
  let flg = src[pos + 4]
  checkFlg(flg)
  if avail < 6:
    return 0
  let bd = src[pos + 5]
  if (bd and 0x8F) != 0:
    raiseLz4(ekMalformed, "reserved bit set in the frame descriptor (BD)")
  let bsid = int(bd shr 4) - 4
  if bsid < 0:
    raiseLz4(ekMalformed, "invalid block maximum size")
  let hasCs = (flg and 0x08) != 0
  let hasDict = (flg and 0x01) != 0
  let length = headerLength(flg)
  if avail < length:
    return 0
  let hc = src[pos + length - 1]
  let expected =
    byte((xxh32(src.toOpenArray(pos + 4, pos + length - 2)) shr 8) and 0xFF)
  if hc != expected:
    raiseLz4(ekChecksum, "frame header checksum mismatch")
  info = FrameInfo(
    kind: fkNormal,
    blockSize: BlockSizeId(bsid),
    blockIndependent: (flg and 0x20) != 0,
    blockChecksum: (flg and 0x10) != 0,
    contentChecksum: (flg and 0x04) != 0,
    hasContentSize: hasCs,
    hasDictId: hasDict,
  )
  var p = pos + 6
  if hasCs:
    info.contentSize = readLE64(src, p)
    p += 8
  if hasDict:
    info.dictId = readLE32(src, p)
  length

proc writeHeader*(
    dst: var openArray[byte], opts: FrameOptions, contentSize: uint64
): int =
  ## Writes a frame header at the start of `dst`, which must have room for
  ## MaxHeaderSize bytes. A zero `contentSize` or `dictId` is not written.
  ## Returns the header length.
  writeLE32(dst, 0, FrameMagic)
  var flg = 0x40'u8
  if opts.blockIndependent:
    flg = flg or 0x20
  if opts.blockChecksum:
    flg = flg or 0x10
  if contentSize != 0:
    flg = flg or 0x08
  if opts.contentChecksum:
    flg = flg or 0x04
  if opts.dictId != 0:
    flg = flg or 0x01
  dst[4] = flg
  dst[5] = byte((ord(opts.blockSize) + 4) shl 4)
  var p = 6
  if contentSize != 0:
    writeLE64(dst, p, contentSize)
    p += 8
  if opts.dictId != 0:
    writeLE32(dst, p, opts.dictId)
    p += 4
  dst[p] = byte((xxh32(dst.toOpenArray(4, p - 1)) shr 8) and 0xFF)
  p + 1

# Block compression

proc rebase*(table: var HashTable, base: var int, newBase: int) =
  ## Moves the base of `table` forward to `newBase`; older entries become
  ## 0, which points at `newBase`. Callers rebase only 64 KiB before the
  ## next block, so those entries stay out of reach as before.
  let shift = newBase - base
  for e in table.mitems:
    e =
      if int(e) < shift:
        0'u32
      else:
        e - uint32(shift)
  base = newBase

type PreparedDict* = object
  ## A frame dictionary indexed once for frames at every level (see
  ## FrameDict); compressors only read it.
  data*: seq[byte] # the last 64 KiB of the dictionary
  fast*: DictState # the fast levels: every position
  hc*: DictState
    ## the HC levels: loaded with hash chains, which the chain levels copy
    ## and lz4mid searches

type FrameCompressor* = object
  ## Compresses a frame's blocks. With a dictionary, independent blocks
  ## start from it and linked blocks have it as their first history. Its
  ## tables serve one frame after another (see init). A copy continues on
  ## its own in the same thread, sharing prepared dictionary states.
  linked: bool
  level: int
  accel: int
  table: HashTable
  next16: int ## see compressIndependent: 0 only while the table is clear
  nextCtx: int ## fast, independent with a dictionary: see compressDictCtx
  base: int # fast, linked: table positions are from here
  afterDict: int # linked: the dictionary's length, until the first block
  hc: HcBox
  dict: DictState # independent blocks: the dictionary in front of them
  dictCtx: DictState # HC, linked: the dictionary's state, which blocks search
  ctxLeft: int # while this is above 0 (see startAfterDict)
  prepared: ptr PreparedDict
    ## the dictionary, when it is prepared (see usePrepared): instead of
    ## `dict` and `dictCtx`

func usesHc(c: FrameCompressor): bool {.inline.} =
  isHcLevel(c.level)

proc linkedHc(c: var FrameCompressor): var HcState {.inline.} =
  ## The history of linked HC blocks, which init makes.
  doAssert not c.hc.isEmpty, "linked HC blocks without a history"
  c.hc[]

proc init*(c: var FrameCompressor, level: int, linked: bool) =
  ## Makes `c` a compressor for a new frame whose data starts at position 0
  ## of the buffers it is given. `c` is new (zeroed), or keeps its table
  ## and HC state from frames before, which give the blocks of new ones.
  ## The fields are set one by one: constructing the object would clear its
  ## hash table once more.
  c.linked = linked
  c.level = level
  c.accel = accelerationOf(level)
  c.base = 0
  c.afterDict = 0
  c.dict = DictState()
  c.dictCtx = DictState()
  c.ctxLeft = 0
  c.prepared = nil
  if isHcLevel(level):
    # Linked blocks carry their history; independent ones start it again.
    c.hc.setCarried(linked)
    if linked:
      c.hc[].hcStart(0, level)
  elif linked:
    # Positions start at 0: those of earlier frames would be out of reach.
    if c.next16 != 0:
      zeroMem(c.table.addr, sizeof(c.table))
    c.next16 = -1
    c.nextCtx = 0

proc setDictionary*(c: var FrameCompressor, buf: openArray[byte], dictLen: int) =
  ## Uses `buf[0 ..< dictLen]` (at most 64 KiB) as the dictionary of a new
  ## compressor. Linked blocks follow it in the same buffer; independent
  ## blocks follow a copy.
  if c.linked:
    # LZ4F compresses the first block after it in its own way (see
    # compressData).
    c.afterDict = dictLen
    if not c.usesHc:
      # Every position, as LZ4F indexes its dictionaries.
      loadDictTable(c.table, buf, dictLen, every = true)
      c.base = dictBase(dictLen)
  elif dictLen > 0:
    # Independent blocks start each from the dictionary's state.
    c.dict = initDictState(buf.toOpenArray(0, dictLen - 1), c.level, dkFrame)
    if not c.usesHc and c.nextCtx == 0 and c.next16 == 0:
      # A clear table: every entry (0) is below 1, so short blocks start
      # there without clearing it again.
      c.nextCtx = 1

proc initPreparedDict*(dict: openArray[byte]): PreparedDict =
  ## Indexes the last 64 KiB of `dict` for both compressors (no table when
  ## it is empty).
  result.data = @(dict.toOpenArray(dictTail(dict.len), dict.high))
  result.fast = initDictState(result.data, 0, dkFrame)
  result.hc = initDictState(result.data, Lz4fDictLevel, dkFrame)

func readsPrepared*(level: int, linked: bool): bool =
  ## Whether blocks with a prepared dictionary read it where it is (see
  ## usePrepared) rather than after a copy of it in their buffer.
  not linked and not isHcLevel(level)

proc usePrepared*(c: var FrameCompressor, p: ptr PreparedDict) =
  ## Uses the prepared dictionary `p[]` (not empty) for a new compressor,
  ## giving the blocks of setDictionary without indexing it again. `p[]`
  ## must outlive the frame's blocks. The blocks follow a copy of its data
  ## in their buffer, except those of readsPrepared.
  c.prepared = p
  if c.linked:
    c.afterDict = p.data.len
    if not c.usesHc:
      copyDictTable(c.table, p.fast)
      c.base = dictBase(p.data.len)
  elif not c.usesHc and c.nextCtx == 0 and c.next16 == 0:
    # See setDictionary.
    c.nextCtx = 1

proc prepareLinked*(c: var FrameCompressor, start, iend: int) =
  ## Keeps the fast table's positions in 32 bits on very large one-shot
  ## linked frames by moving its base forward.
  if not c.usesHc and iend - c.base > RebaseLimit:
    rebase(c.table, c.base, start - WindowSize)

proc release*(c: var FrameCompressor) =
  ## Frees the dictionary states (and forgets a prepared one) once no block
  ## of the frame is left to compress. The table and the HC state stay for
  ## the next frame (see init).
  c.dict = DictState()
  c.dictCtx = DictState()
  c.prepared = nil

proc moveHistory*(c: var FrameCompressor, n: int) =
  ## Moves the history's positions by -`n`: the buffer moved `n` bytes
  ## towards its start, or with `n < 0` the history goes on in the caller's
  ## data. Entries that would fall below 0 become 0, out of reach as before.
  # The encoder moves the history only after 64 KiB of blocks.
  doAssert c.ctxLeft <= 0, "a history moved away from its dictionary"
  if c.usesHc:
    c.linkedHc.hcMoveHistory(n)
  elif c.base >= n:
    c.base -= n
  else:
    rebase(c.table, c.base, n)
    c.base = 0

proc startAfterDict(c: var FrameCompressor, src: openArray[byte], start, iend: int) =
  ## Starts the history of the first linked HC block after the dictionary
  ## `src[0 ..< start]`. Long blocks copy the dictionary's state; short ones
  ## (and lz4mid) keep their own and search the dictionary's state, as do
  ## the blocks that start within 64 KiB of it. A prepared dictionary gives
  ## both states already made.
  if dictMode(c.level, iend - start, dkFrame) == dmCopy:
    if c.prepared != nil:
      copyDictHc(c.linkedHc, c.prepared.hc, c.level)
    else:
      c.linkedHc.hcLoadHistory(src, 0, start, c.level, apart = true)
  else:
    if c.prepared == nil:
      c.dictCtx = initDictState(src.toOpenArray(0, start - 1), c.level, dkFrame)
    c.ctxLeft = WindowSize
    c.linkedHc.hcStart(start, c.level)

proc compressData*(
    c: var FrameCompressor,
    src: openArray[byte],
    start, iend: int,
    dst: var openArray[byte],
): int =
  ## Compresses `src[start ..< iend]` into `dst`, or returns 0 if it does
  ## not fit. Linked blocks must follow the previous ones (or the dictionary)
  ## in `src`; independent blocks with a dictionary must follow a copy of it
  ## at the start of `src`, except those of readsPrepared.
  let firstAfterDict = c.afterDict > 0 # linked blocks only
  if firstAfterDict:
    doAssert start == c.afterDict, "a block not right after its dictionary"
    c.afterDict = 0
  if not c.linked and c.prepared != nil:
    let p = c.prepared
    if c.usesHc:
      doAssert start == p.data.len, "a block not right after its dictionary"
      compressAfterDict(
        c.table,
        c.nextCtx,
        c.hc,
        p.hc,
        c.level,
        src.toOpenArray(0, iend - 1),
        [],
        dst,
        inPlace = true,
      )
    else:
      # The dictionary where it is: the block need not follow a copy.
      if iend - start >= MinLength:
        c.next16 = -1 # compressAfterDict writes the table
      compressAfterDict(
        c.table,
        c.nextCtx,
        c.hc,
        p.fast,
        c.level,
        src.toOpenArray(start, iend - 1),
        p.data,
        dst,
        inPlace = false,
      )
  elif not c.linked and c.dict.len > 0:
    # Like compressBlock with a BlockDict: the dictionary precedes the block
    # in the same buffer.
    doAssert start == c.dict.len, "a block not right after its dictionary"
    if not c.usesHc and iend - start >= MinLength:
      c.next16 = -1 # compressAfterDict writes the table
    compressAfterDict(
      c.table,
      c.nextCtx,
      c.hc,
      c.dict,
      c.level,
      src.toOpenArray(0, iend - 1),
      [],
      dst,
      inPlace = true,
    )
  elif c.usesHc:
    if c.linked:
      if firstAfterDict:
        c.startAfterDict(src, start, iend)
      c.linkedHc.hcLinked(src, start)
      if c.ctxLeft > 0:
        c.ctxLeft -= iend - start
        result =
          if c.prepared != nil:
            compressLinkedCtx(c.linkedHc, c.prepared.hc, src, start, iend, dst)
          else:
            compressLinkedCtx(c.linkedHc, c.dictCtx, src, start, iend, dst)
        if c.ctxLeft <= 0:
          c.dictCtx = DictState()
        return
    else:
      c.hc[].hcStart(start, c.level)
    c.hc[].hcCompress(src, start, iend, dst)
  elif c.linked:
    if firstAfterDict:
      # LZ4F compresses it as after an external dictionary.
      compressGeneric(c.table, src, start, iend, 0, c.base, dst, c.accel, split = true)
    else:
      compressGeneric(c.table, src, start, iend, 0, c.base, dst, c.accel)
  else:
    if iend - start >= MinLength:
      c.nextCtx = 0 # compressIndependent writes the table
    compressIndependent(c.table, c.next16, src, start, iend, dst, c.accel)

proc writeBlock*(
    dst: var openArray[byte],
    at: int,
    src: openArray[byte],
    start, iend: int,
    c: var FrameCompressor,
    blockChecksum: bool,
): int =
  ## Writes the block for `src[start ..< iend]` at `dst[at ..]`, which needs
  ## `iend - start + 8` bytes: header, data and checksum. Returns the
  ## position after it. Data that does not shrink is stored uncompressed.
  let len = iend - start
  let data = at + 4
  var n = c.compressData(src, start, iend, dst.toOpenArray(data, data + len - 2))
  if n == 0:
    writeLE32(dst, at, uint32(len) or 0x8000_0000'u32)
    copyMem(dst[data].addr, src[start].addr, len)
    n = len
  else:
    writeLE32(dst, at, uint32(n))
  var p = data + n
  if blockChecksum:
    writeLE32(dst, p, xxh32(dst.toOpenArray(data, p - 1)))
    p += 4
  p

# Block decoding (for FrameDecoder)

func storedCapacity*(stored, blockMax: int): int =
  ## min(blockMax, stored * 255): the most a compressed block of `stored`
  ## bytes can decode to, computed without overflowing.
  if stored > blockMax div 255:
    blockMax
  else:
    stored * 255

proc decodeChecked*(
    blk: openArray[byte],
    dst: var openArray[byte],
    dict: openArray[byte],
    dstStart, lowLimit, structural, limitLeft: int,
    outOfRange: Lz4ErrorKind,
): int {.raises: [Lz4Error].} =
  ## Decodes a compressed block at `dstStart` and returns the end of the
  ## data, or -1 when the block needs more room than `dst` holds, which is
  ## less than min(structural, limitLeft): the caller then decodes it again
  ## with more room. Matches may refer back to `lowLimit`, then into `dict`.
  ## Exceeding `structural` is ekMalformed, exceeding `limitLeft` is
  ## ekLimitExceeded. An invalid block gives the same error whatever
  ## `limitLeft` is.
  let most = min(structural, limitLeft)
  let cap = min(most, dst.len - dstStart)
  var e = 0
  let s = decodeBlock(
    blk, dst.toOpenArray(0, dstStart + cap - 1), dict, dstStart, lowLimit, e
  )
  if s == dsOutputTooSmall:
    if cap < most:
      return -1
    if limitLeft < structural:
      # The limit stopped the block: only a valid one exceeds it.
      raiseDoesNotFit(
        blk,
        dstStart - lowLimit + dict.len,
        structural,
        ekLimitExceeded,
        ekMalformed,
        outOfRange,
      )
  if s != dsOk:
    raiseDecodeError(s, ekMalformed, outOfRange)
  e
