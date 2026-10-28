## Raw LZ4 blocks: compression and decompression, with or without a
## dictionary. A block has no header, checksum or decompressed length; the
## caller keeps the length. `lz4` exports this module.

import private/[common, hc, blockimpl]

type
  BlockCompressor* = object
    ## Keeps the hash table, the HC state and, with a dictionary at HC
    ## levels, the joined dictionary and block between `compressBlockInto`
    ## calls. No data is carried over: every call gives the block that new
    ## tables would. Copies have tables of their own and can run in
    ## different threads.
    table: HashTable
    next16: int # see compressIndependent
    nextCtx: int # see compressDictCtx
    hc: HcBox # started again on every call, or holds a copy of a BlockDict's state
    joined: seq[byte] # HC levels: a dictionary, then the block (see join)
    joinedDict: int # the BlockDict `joined` starts with (its id), or 0

  BlockDict* = object
    ## A dictionary prepared once for compressing many blocks at one level
    ## (see `initBlockDict`). `compressBlockInto` only reads it, so one
    ## BlockDict can serve several compressors in several threads. Share it
    ## rather than copies: copies share tables through non-atomic refs.
    data: seq[byte] # the last 64 KiB of the dictionary
    state: DictState

# Decompression

proc raiseBlockError(
    src: openArray[byte], prefixLen: int, s: DecodeStatus, tooSmall: Lz4ErrorKind
) {.noreturn, raises: [Lz4Error].} =
  ## The error of the public block procs, for a decode of `src` that
  ## stopped with `s`: `tooSmall` for a valid block that does not fit.
  if s == dsOutputTooSmall:
    raiseDoesNotFit(src, prefixLen, high(int), tooSmall, tooSmall)
  raiseDecodeError(s, tooSmall)

proc decodeNew(
    src, dict: openArray[byte], maxOutputSize: int, dst: var OutputBuffer
) {.raises: [Lz4Error].} =
  ## Writes `src` decoded after the usable part of `dict` (none when empty)
  ## to the empty `dst`, in a buffer whose size a first scan gives.
  if maxOutputSize < 0:
    raiseLz4(ekInvalidArgument, "maxOutputSize must not be negative")
  let tail = dictTail(dict.len)
  var total = 0
  let scan = decodedLength(src, dict.len - tail, maxOutputSize, total)
  if scan != dsOk:
    raiseBlockError(src, dict.len - tail, scan, ekLimitExceeded)
  var output: typeof(dst)
  output.setLenNoInit(total)
  var dstEnd = 0
  let s = decodeBlock(
    src, output.asBytes(0, output.high), dict.toOpenArray(tail, dict.high), 0, 0, dstEnd
  )
  if s != dsOk:
    raiseDecodeError(s, ekMalformed)
  dst = move output

proc decodeInto(
    src, dict: openArray[byte], dst: var openArray[byte]
): int {.raises: [Lz4Error].} =
  ## `src` decoded after the usable part of `dict` (none when empty) into
  ## `dst` in one pass; the block is scanned again only when it fails.
  let tail = dictTail(dict.len)
  var dstEnd = 0
  let s = decodeBlock(src, dst, dict.toOpenArray(tail, dict.high), 0, 0, dstEnd)
  if s != dsOk:
    raiseBlockError(src, dict.len - tail, s, ekOutputTooSmall)
  dstEnd

proc decompressBlock*(
    src: openArray[byte], maxOutputSize: int
): seq[byte] {.raises: [Lz4Error].} =
  ## Decompresses one LZ4 block. The format does not record the decompressed
  ## length: the sequences are scanned first, then the result is allocated
  ## once.
  ##
  ## Raises `Lz4Error` with `ekLimitExceeded` when the result would be
  ## longer than `maxOutputSize`, `ekMalformed` when `src` is not a valid
  ## block (whatever `maxOutputSize` is).
  decodeNew(src, [], maxOutputSize, result)

proc decompressBlock*(s: string, maxOutputSize: int): string {.raises: [Lz4Error].} =
  ## Decompresses the LZ4 block `s` (see `decompressBlock(src,
  ## maxOutputSize)`).
  decodeNew(s.toOpenArrayByte(0, s.high), [], maxOutputSize, result)

proc decompressBlockInto*(
    src: openArray[byte], dst: var openArray[byte]
): int {.raises: [Lz4Error].} =
  ## Decompresses one LZ4 block into `dst` and returns the number of bytes
  ## written. Raises `ekOutputTooSmall` when the result does not fit; `dst`
  ## may then have been partly written. Bytes after the result may be
  ## overwritten as well (the fast code paths copy whole chunks where there
  ## is room, as liblz4 does). An invalid block is `ekMalformed` whatever
  ## the size of `dst`.
  decodeInto(src, [], dst)

proc decompressBlock*(
    src: openArray[byte], dict: openArray[byte], maxOutputSize: int
): seq[byte] {.raises: [Lz4Error].} =
  ## Same as `decompressBlock(src, maxOutputSize)` for a block compressed
  ## with the dictionary `dict` (only its last 64 KiB can be referred to).
  decodeNew(src, dict, maxOutputSize, result)

proc decompressBlock*(
    s: string, dict: string, maxOutputSize: int
): string {.raises: [Lz4Error].} =
  ## Same as `decompressBlock(s, maxOutputSize)` for a block compressed with
  ## the dictionary `dict` (see `decompressBlock(src, dict, maxOutputSize)`).
  decodeNew(
    s.toOpenArrayByte(0, s.high),
    dict.toOpenArrayByte(0, dict.high),
    maxOutputSize,
    result,
  )

proc decompressBlockInto*(
    src: openArray[byte], dict: openArray[byte], dst: var openArray[byte]
): int {.raises: [Lz4Error].} =
  ## Same as `decompressBlockInto(src, dst)` for a block compressed with the
  ## dictionary `dict` (only its last 64 KiB can be referred to).
  decodeInto(src, dict, dst)

# Compression

func compressBound*(srcLen: int): int =
  ## The largest size a compressed block of `srcLen` input bytes can have.
  ## Returns 0 for a negative length or one above LZ4_MAX_INPUT_SIZE.
  if srcLen < 0 or srcLen > MaxInputSize:
    0
  else:
    srcLen + srcLen div 255 + 16

proc checkInputSize(n: int) {.raises: [Lz4Error].} =
  if n > MaxInputSize:
    raiseLz4(ekLimitExceeded, "the input is larger than LZ4_MAX_INPUT_SIZE")

proc compressFresh(src: openArray[byte], dst: var openArray[byte], level: int): int =
  ## One independent block with new (empty) tables.
  if isHcLevel(level) and src.len >= MinLength:
    # Shorter inputs are stored as literals.
    let s = newHcState()
    s[].hcStart(0, level)
    return s[].hcCompress(src, 0, src.len, dst)
  if src.len < Limit64K:
    var t: HashTable16
    compressGeneric(t, src, 0, src.len, 0, 0, dst, accelerationOf(level))
  else:
    var t: HashTable
    compressGeneric(t, src, 0, src.len, 0, 0, dst, accelerationOf(level))

proc compressBlockInto*(
    c: var BlockCompressor, src: openArray[byte], dst: var openArray[byte], level = 0
): int {.raises: [Lz4Error].} =
  ## Same as `compressBlockInto(src, dst, level)`, reusing the tables of `c`.
  checkInputSize(src.len)
  if isHcLevel(level):
    c.hc[].hcStart(0, level)
    return c.hc[].hcCompress(src, 0, src.len, dst)
  if src.len >= MinLength:
    c.nextCtx = 0 # compressIndependent writes the table
  compressIndependent(c.table, c.next16, src, 0, src.len, dst, accelerationOf(level))

proc compressBlockInto*(
    src: openArray[byte], dst: var openArray[byte], level = 0
): int {.raises: [Lz4Error].} =
  ## Compresses `src` as one LZ4 block into `dst` and returns the number of
  ## bytes written, or 0 when the result does not fit (an empty input still
  ## produces 1 byte). `compressBound` is always enough. Bytes of `dst`
  ## after the result, and all of them on failure, may be overwritten.
  ##
  ## `level`: negative values trade ratio for speed, 0 and 1 use the fast
  ## compressor, 2 to 12 the high compression one (higher is smaller and
  ## slower; 13 and more are 12). Raises `ekLimitExceeded` when `src` is
  ## longer than LZ4_MAX_INPUT_SIZE.
  ##
  ## Every call makes new tables; to compress many blocks, reuse a
  ## `BlockCompressor`.
  checkInputSize(src.len)
  compressFresh(src, dst, level)

const JoinedKeepMax = 1 shl 20
  ## The longest block whose copy a BlockCompressor keeps (see join).

proc join(c: var BlockCompressor, dict, src: openArray[byte], id: int) =
  ## Puts `dict`, then `src` (at least MinLength bytes) in c.joined: the HC
  ## compressor reads a dictionary in the same buffer as the block, faster
  ## than apart. `dict` is not copied again when it is the BlockDict `id`
  ## already there (0: none).
  c.joined.setLenNoInit(dict.len + src.len)
  if id == 0 or c.joinedDict != id:
    copyMem(c.joined[0].addr, dict[0].unsafeAddr, dict.len)
    c.joinedDict = id
  copyMem(c.joined[dict.len].addr, src[0].unsafeAddr, src.len)

proc dropJoined(c: var BlockCompressor, n: int) =
  ## Frees c.joined after a block of `n` bytes too long to keep a copy of.
  if n > JoinedKeepMax:
    c.joined = @[]
    c.joinedDict = 0

proc compressBlockInto*(
    c: var BlockCompressor,
    src: openArray[byte],
    dict: openArray[byte],
    dst: var openArray[byte],
    level = 0,
): int {.raises: [Lz4Error].} =
  ## Same as `compressBlockInto(src, dict, dst, level)`, reusing the tables
  ## of `c`. The dictionary is read and indexed on every call: to compress
  ## many blocks with one dictionary, prepare it once (`initBlockDict`).
  checkInputSize(src.len)
  let tail = dictTail(dict.len)
  let dictLen = dict.len - tail
  if dictLen == 0:
    # No dictionary: the usual tables.
    return c.compressBlockInto(src, dst, level)
  # Build the dictionary's state here as `initBlockDict` does, so that the
  # result is the same.
  template d(): untyped =
    dict.toOpenArray(tail, dict.high)

  case dictMode(level, src.len, dkBlock)
  of dmLiterals:
    compressGeneric(c.table.as16, src, 0, src.len, 0, 0, dst, accelerationOf(level))
  of dmCtx, dmCopy:
    if not isHcLevel(level):
      # Search the dictionary's table instead of copying it.
      loadDictTable(c.table, d, dictLen)
      c.next16 = -1
      c.nextCtx = 0
      compressWithDict(c.table, src, d, dst, accelerationOf(level))
    else:
      c.join(d, src, 0)
      c.hc[].hcLoadHistory(c.joined, 0, dictLen, level, apart = true)
      let size = c.hc[].hcCompress(c.joined, dictLen, c.joined.len, dst)
      c.dropJoined(src.len)
      size

proc initBlockDict*(dict: openArray[byte], level = 0): BlockDict =
  ## Prepares the dictionary `dict` (only its last 64 KiB can be referred
  ## to) for compressing blocks at `level` with `compressBlockInto(c, src, d,
  ## dst)`: it is copied and indexed once here rather than on every call.
  ## Decompress the blocks with `decompressBlock(blk, dict, ...)`.
  result.data = @(dict.toOpenArray(dictTail(dict.len), dict.high))
  result.state = initDictState(result.data, level, dkBlock)

proc compressBlockInto*(
    c: var BlockCompressor,
    src: openArray[byte],
    dict: BlockDict,
    dst: var openArray[byte],
): int {.raises: [Lz4Error].} =
  ## Compresses `src` as one LZ4 block that may refer to the prepared
  ## dictionary `dict`, at its level, into `dst`. The result equals
  ## `compressBlockInto(src, dict, dst, level)` without reading the
  ## dictionary again: a short input costs little more than without one.
  checkInputSize(src.len)
  if dict.data.len == 0:
    return c.compressBlockInto(src, dst, dict.state.level)
  let hc = isHcLevel(dict.state.level)
  if hc and src.len >= MinLength:
    c.join(dict.data, src, dict.state.id)
    result = compressAfterDict(
      c.table,
      c.nextCtx,
      c.hc,
      dict.state,
      dict.state.level,
      c.joined,
      [],
      dst,
      inPlace = true,
    )
    c.dropJoined(src.len)
    return
  if not hc and src.len >= MinLength:
    c.next16 = -1 # compressAfterDict writes the table
  compressAfterDict(
    c.table,
    c.nextCtx,
    c.hc,
    dict.state,
    dict.state.level,
    src,
    dict.data,
    dst,
    inPlace = false,
  )

proc compressBlockInto*(
    src: openArray[byte], dict: openArray[byte], dst: var openArray[byte], level = 0
): int {.raises: [Lz4Error].} =
  ## Same as `compressBlockInto(src, dst, level)` for a block that may refer
  ## to the last 64 KiB of `dict`; decompress it with
  ## `decompressBlock(blk, dict, ...)`.
  ##
  ## The block is liblz4's from LZ4_loadDict and LZ4_compress_fast_continue
  ## (HC from level 2); frames prepare dictionaries differently, so their
  ## blocks may differ.
  if dict.len == 0:
    compressBlockInto(src, dst, level)
  else:
    # Declared here so that the table is only zeroed when it is needed.
    var c: BlockCompressor
    c.compressBlockInto(src, dict, dst, level)

proc compressNew(
    src, dict: openArray[byte], level: int, dst: var OutputBuffer
) {.raises: [Lz4Error].} =
  ## Writes the block of `src` after `dict` (none when empty) to the empty
  ## `dst`, made in a buffer of `compressBound`.
  checkInputSize(src.len)
  var output: typeof(dst)
  output.setLenNoInit(compressBound(src.len))
  output.setLenNoInit(
    compressBlockInto(src, dict, output.asBytes(0, output.high), level)
  )
  output.trimCapacity()
  dst = move output

proc compressBlock*(src: openArray[byte], level = 0): seq[byte] {.raises: [Lz4Error].} =
  ## Compresses `src` as one LZ4 block, with new tables as
  ## `compressBlockInto(src, dst, level)` does.
  compressNew(src, [], level, result)

proc compressBlock*(s: string, level = 0): string {.raises: [Lz4Error].} =
  ## Compresses `s` as one LZ4 block (see `compressBlock(src, level)`).
  compressNew(s.toOpenArrayByte(0, s.high), [], level, result)

proc compressBlock*(
    src: openArray[byte], dict: openArray[byte], level = 0
): seq[byte] {.raises: [Lz4Error].} =
  ## Compresses `src` as one LZ4 block that may refer to the last 64 KiB of
  ## the dictionary `dict` (see `compressBlockInto(src, dict, dst, level)`).
  compressNew(src, dict, level, result)

proc compressBlock*(s: string, dict: string, level = 0): string {.raises: [Lz4Error].} =
  ## Same as `compressBlock(s, level)` for a block that may refer to the
  ## last 64 KiB of the dictionary `dict` (see `compressBlock(src, dict,
  ## level)`).
  compressNew(
    s.toOpenArrayByte(0, s.high), dict.toOpenArrayByte(0, dict.high), level, result
  )
