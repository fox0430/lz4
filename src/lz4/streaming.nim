## Streaming frame compression and decompression, and the one-shot functions
## built on them. `lz4` exports this module.
##
## `FrameEncoder` produces the same bytes as `compressFrame` when `flush` is
## not called, except that `compressFrame` picks a smaller block size and
## independent blocks for an input that fits in one block. `FrameDecoder`
## accepts its input cut anywhere and keeps the last 64 KiB of a linked
## frame, so the caller may empty `output` between calls.

import private/[common, frameimpl, xxhash32]

type
  ErrorState = object
    failed: bool
    kind: Lz4ErrorKind
    msg: string

  FrameDict* = object
    ## A dictionary prepared once for compressing many frames at any level
    ## (see `initFrameDict`). The one-shot procs only read it, so one
    ## FrameDict can serve encoders in several threads. Share it rather than
    ## copies: copies share its tables through non-atomic refs. An encoder
    ## started with it must also stay in its thread until `finish`.
    p: ref PreparedDict # nil: no dictionary

  FrameEncoder* = object
    ## Streaming frame compressor (see `initFrameEncoder`). It can go on to
    ## more frames, keeping its tables (see `reset` and
    ## `compressFrame(e, src, opts)`). A copy continues the frame in the
    ## same thread, sharing dictionary state through non-atomic refs.
    ready: bool # set by initFrameEncoder
    opts: FrameOptions
    contentSize: int64 # -1: not written
    written: int64 # input received so far
    started: bool # header written
    finished: bool
    bsize: int
    comp: FrameCompressor
    dictLen: int # the dictionary in front of `buf`, until its state is made
    pdict: ptr PreparedDict # that dictionary when prepared, until then
    keep: ref PreparedDict # a FrameDict of initFrameEncoder or reset, until finish
    buf: seq[byte] # [history or dictionary | pending block]
    bufDict: int ## the prepared dictionary (its id) that `buf` starts with, or 0
    winLen: int # bytes in front of the pending block
    fill: int # pending input after them
    digest: Xxh32State

  DecoderState = enum
    stMagic
    stHeader
    stBlockHeader
    stBlockData
    stContentChecksum
    stSkipSize
    stSkipData
    stLegacySize
    stLegacyData

  FrameDecoder* = object ## Streaming frame decompressor (see `initFrameDecoder`).
    ready: bool # set by initFrameDecoder
    maxOutput: int64
    total: int64 # output produced so far, all frames
    err: ErrorState
    state: DecoderState
    atEnd: bool # the last feed stopped at the end of a frame
    hdr: array[MaxHeaderSize, byte] # magic, frame header, sizes, checksums
    hdrLen: int
    hdrNeed: int
    info: FrameInfo # the last frame header read
    hasInfo: bool
    bmax: int
    outOfRange: Lz4ErrorKind
    blockLen: int # stored size of the current block
    blockRaw: bool
    need: int # bytes the current block needs (+ checksum)
    blk: seq[byte] # the current block when it arrives in pieces (grows with it)
    blkLen: int
    skipLeft: int64
    frameOut: int64 # content produced by the current frame
    frameIn: int64 # stored bytes of the current frame's blocks decoded so far
    oneShot: bool # decodeAll: own output, each feed has the rest of the input
    digest: Xxh32State
    dict: seq[byte] # the last 64 KiB of the dictionary (empty: none)
    work: seq[byte] # linked frames: the history before this feed
    winLen: int
    dictFirst: bool # linked frames: that history is `dict`, not yet in `work`
    histStart: int # linked frames: where this feed's history starts in `output`

const KeptBlockBuffer = blockSizeBytes(bs64KiB) + 4
  ## The largest block buffer kept from one frame to the next: a 64 KiB
  ## block and its checksum. Larger ones (up to 8 MiB in a legacy frame) are
  ## freed at the end of the frame.

proc check(e: ErrorState) {.raises: [Lz4Error].} =
  ## Raises the first error again; once failed, every call fails the same
  ## way.
  if e.failed:
    raiseLz4(e.kind, e.msg)

template sticky(e: var ErrorState, body: untyped) =
  ## Runs `body`, remembering the first Lz4Error it raises.
  try:
    body
  except Lz4Error as ex:
    if not e.failed:
      e = ErrorState(failed: true, kind: ex.kind, msg: ex.msg)
    # Re-raise by name: a bare raise breaks the raises annotation on Nim
    # 2.2.0.
    raise ex

# Encoder

proc checkBlockSize(opts: FrameOptions) {.raises: [Lz4Error].} =
  if opts.blockSize notin BlockSizeId.low .. BlockSizeId.high:
    raiseLz4(ekInvalidArgument, "invalid blockSize")

func bufferLen(e: FrameEncoder): int =
  ## Linked blocks keep up to 2 * WindowSize of history before the pending
  ## block; independent blocks keep the dictionary (`winLen` bytes).
  (if e.opts.blockIndependent: e.winLen else: 2 * WindowSize) + e.bsize

const KeptEncoderBuffer = 2 * WindowSize + blockSizeBytes(bs64KiB)
  ## The largest buffer an encoder keeps for its next frame (see finish):
  ## that of linked 64 KiB blocks.

proc makeBuffer(e: var FrameEncoder, n: int) {.raises: [].} =
  ## Gives the empty buffer the length `n`, in the buffer kept from the
  ## frames before when its capacity holds bufferLen, else in a new one.
  if e.buf.capacity < e.bufferLen:
    e.buf = newSeqUninit[byte](e.bufferLen)
  e.buf.setLenNoInit(n)

proc initFrame(
    e: var FrameEncoder, opts: FrameOptions, contentSize: int64
) {.raises: [Lz4Error].} =
  ## Starts the frame of initFrameEncoder in `e`, without a dictionary yet
  ## (see init). `e` is new (zeroed) or keeps its tables and buffer from
  ## earlier frames (see reset). The fields are set one by one to avoid
  ## clearing the compressor's 16 KiB hash table. Nothing changes when it
  ## raises.
  if opts.writeContentSize and contentSize < 0:
    raiseLz4(ekInvalidArgument, "writeContentSize needs the content size")
  if not opts.writeContentSize and contentSize >= 0:
    raiseLz4(
      ekInvalidArgument, "a content size was given but writeContentSize is false"
    )
  checkBlockSize(opts)
  e.ready = true
  e.opts = opts
  e.contentSize = contentSize
  e.written = 0
  e.started = false
  e.finished = false
  e.bsize = blockSizeBytes(opts.blockSize)
  e.comp.init(opts.level, not opts.blockIndependent)
  e.fill = 0
  e.digest = initXxh32()
  e.dictLen = 0
  e.pdict = nil
  e.keep = nil
  e.winLen = 0
  if e.buf.len > 0:
    e.buf.setLenNoInit(0)

proc init(
    e: var FrameEncoder, dict: openArray[byte], opts: FrameOptions, contentSize: int64
) {.raises: [Lz4Error].} =
  ## initFrame with the last 64 KiB of `dict` as the dictionary.
  e.initFrame(opts, contentSize)
  e.bufDict = 0
  let tail = dictTail(dict.len)
  e.dictLen = dict.len - tail
  e.winLen = e.dictLen
  if e.dictLen > 0:
    # Copy it now, since `dict` is not kept: a copy of the encoder then
    # copies only the dictionary.
    e.makeBuffer(e.dictLen)
    copyMem(e.buf[0].addr, dict[tail].unsafeAddr, e.dictLen)

proc init(
    e: var FrameEncoder, p: ptr PreparedDict, opts: FrameOptions, contentSize: int64
) {.raises: [Lz4Error].} =
  ## initFrame with the prepared dictionary `p[]` (none when nil or empty),
  ## which must outlive the frame (see `keep`).
  e.initFrame(opts, contentSize)
  if p == nil or p.data.len == 0:
    e.bufDict = 0
    return
  if readsPrepared(opts.level, not opts.blockIndependent):
    # The blocks need no copy of it: the buffer holds pending input only.
    e.bufDict = 0
    e.comp.usePrepared(p)
    return
  # As with a dictionary as it is, but independent blocks leave the copy
  # for the next frame.
  e.pdict = p
  e.dictLen = p.data.len
  e.winLen = e.dictLen
  let id = p.hc.id
  let there = e.bufDict == id and e.buf.capacity >= e.bufferLen
  e.makeBuffer(e.dictLen)
  if not there:
    copyMem(e.buf[0].addr, p.data[0].unsafeAddr, e.dictLen)
  e.bufDict = if opts.blockIndependent: id else: 0

func prepared(d: FrameDict): ptr PreparedDict =
  if d.p == nil: nil else: d.p[].addr

proc initFrameDict*(dict: openArray[byte]): FrameDict =
  ## Prepares the dictionary `dict` (only its last 64 KiB can be referred
  ## to) for compressing many frames at any level: copied and indexed once,
  ## for both compressors. It takes about 270 KiB. An empty `dict` is the
  ## same as none.
  new(result.p)
  result.p[] = initPreparedDict(dict)

proc initFrameEncoder*(
    opts = FrameOptions(), contentSize = -1'i64
): FrameEncoder {.raises: [Lz4Error].} =
  ## A streaming encoder writing one frame. With `opts.writeContentSize`,
  ## `contentSize` must be the total length that will be written: `write`
  ## raises ekInvalidArgument as soon as more bytes arrive, `finish` when
  ## fewer did. Without it, `contentSize` must be negative. A content size
  ## of 0 is not written.
  result.init([], opts, contentSize)

proc initFrameEncoder*(
    dict: openArray[byte], opts = FrameOptions(), contentSize = -1'i64
): FrameEncoder {.raises: [Lz4Error].} =
  ## Same as `initFrameEncoder(opts, contentSize)`, compressing with the
  ## last 64 KiB of `dict`: independent blocks may refer to it, linked
  ## blocks have it as their first history. Set `opts.dictId` to record the
  ## dictionary in the header.
  result.init(dict, opts, contentSize)

proc initFrameEncoder*(
    dict: FrameDict, opts = FrameOptions(), contentSize = -1'i64
): FrameEncoder {.raises: [Lz4Error].} =
  ## Same as `initFrameEncoder(dict, opts, contentSize)` with the
  ## dictionary that `dict` prepared, which costs less than indexing it
  ## again (see `initFrameDict`). The encoder refers to `dict` until
  ## `finish`.
  result.init(dict.prepared, opts, contentSize)
  result.keep = dict.p

proc reset*(
    e: var FrameEncoder, opts = FrameOptions(), contentSize = -1'i64
) {.raises: [Lz4Error].} =
  ## Starts a new frame in `e`, as `e = initFrameEncoder(opts,
  ## contentSize)` does, but with the tables and buffer that `e` made for
  ## the frames before, which makes a short frame much cheaper. The frame in
  ## progress, if any, is dropped. `e` may be a zeroed `FrameEncoder`.
  ## Raises as initFrameEncoder does; `e` is unchanged then.
  e.init([], opts, contentSize)

proc reset*(
    e: var FrameEncoder,
    dict: openArray[byte],
    opts = FrameOptions(),
    contentSize = -1'i64,
) {.raises: [Lz4Error].} =
  ## Same as `reset(e, opts, contentSize)` for a frame compressed with the
  ## last 64 KiB of `dict` (see `initFrameEncoder(dict, opts,
  ## contentSize)`).
  e.init(dict, opts, contentSize)

proc reset*(
    e: var FrameEncoder, dict: FrameDict, opts = FrameOptions(), contentSize = -1'i64
) {.raises: [Lz4Error].} =
  ## Same as `reset(e, opts, contentSize)` for a frame compressed with the
  ## dictionary that `dict` prepared (see `initFrameEncoder(dict: FrameDict,
  ## opts, contentSize)`).
  e.init(dict.prepared, opts, contentSize)
  e.keep = dict.p

proc checkOpen(e: FrameEncoder, call: string) {.raises: [Lz4Error].} =
  ## The checks every call starts with. The encoder's errors are all found
  ## before anything changes (compressing cannot fail), so after one the
  ## encoder can go on.
  if not e.ready:
    raiseLz4(ekInvalidArgument, "the FrameEncoder was not made by initFrameEncoder")
  if e.finished:
    raiseLz4(ekInvalidArgument, call & ": the frame is already finished")

proc reserveBuffer(e: var FrameEncoder) {.raises: [].} =
  ## Makes the buffer when it is first needed (initFrameEncoder makes the
  ## one of a dictionary) and the dictionary's state in front of it.
  if e.buf.len == 0:
    e.makeBuffer(e.bufferLen)
  if e.dictLen > 0:
    # Its full length (in a copy of the encoder, a new buffer).
    e.buf.setLenNoInit(e.bufferLen)
    if e.pdict != nil:
      e.comp.usePrepared(e.pdict)
      e.pdict = nil
    else:
      e.comp.setDictionary(e.buf, e.dictLen)
    e.dictLen = 0

proc startFrame(e: var FrameEncoder, output: var OutputBuffer) {.raises: [].} =
  if e.started:
    return
  e.started = true
  var hdr: array[MaxHeaderSize, byte]
  let cs =
    if e.contentSize > 0:
      uint64(e.contentSize)
    else:
      0'u64
  let n = writeHeader(hdr, e.opts, cs)
  output.addBytes(hdr.toOpenArray(0, n - 1))

proc emitFrom(
    e: var FrameEncoder, data: openArray[byte], p, iend: int, output: var OutputBuffer
) {.raises: [].} =
  ## Compresses the block `data[p ..< iend]` where it is and appends it to
  ## `output`.
  let at = output.len
  output.setLenNoInit(at + iend - p + 8)
  output.setLenNoInit(
    writeBlock(
      output.asBytes(0, output.high), at, data, p, iend, e.comp, e.opts.blockChecksum
    )
  )

proc emitBlock(e: var FrameEncoder, output: var OutputBuffer) {.raises: [].} =
  ## Compresses the pending input as one block and appends it to `output`.
  if e.fill == 0:
    return
  let iend = e.winLen + e.fill
  e.emitFrom(e.buf, e.winLen, iend, output)
  e.fill = 0
  if not e.opts.blockIndependent:
    # Move the last 64 KiB to the front once the next full block would not
    # fit. Moving only every 64 KiB or more keeps frequent flushes cheap.
    if iend + e.bsize > e.buf.len:
      let shift = iend - WindowSize
      moveMem(e.buf[0].addr, e.buf[shift].addr, WindowSize)
      e.comp.moveHistory(shift)
      e.winLen = WindowSize
    else:
      e.winLen = iend

proc bufferFrom(
    e: var FrameEncoder, data: openArray[byte], p: int, output: var OutputBuffer
): int {.inline, raises: [].} =
  ## Adds `data[p ..]` to the pending input in the buffer, as much as the
  ## block holds, compresses the block once it is full, and returns the
  ## position after what it took.
  if e.fill == 0:
    e.reserveBuffer()
  let take = min(e.bsize - e.fill, data.len - p)
  copyMem(e.buf[e.winLen + e.fill].addr, data[p].unsafeAddr, take)
  e.fill += take
  if e.fill == e.bsize:
    e.emitBlock(output)
  p + take

func directBlock(e: FrameEncoder, data: openArray[byte], p: int, last: bool): bool =
  ## Whether `data[p ..]` holds a block to compress where it is: a whole
  ## one, or with `last` the short one at the end.
  data.len - p >= e.bsize or last and p < data.len

proc emitDirect(
    e: var FrameEncoder,
    data: openArray[byte],
    p0: int,
    last: bool,
    output: var OutputBuffer,
): int {.raises: [].} =
  ## Compresses the whole blocks in `data` from `p0` on, and with `last`
  ## the short one at the end too, without copying them to the buffer, and
  ## returns the position after them. Linked blocks need their history in
  ## `data`; the first block goes through the buffer unless the pending
  ## block took 64 KiB of `data` before `p0`.
  var p = p0
  if e.opts.blockIndependent:
    while e.directBlock(data, p, last):
      let iend = min(p + e.bsize, data.len)
      e.emitFrom(data, p, iend, output)
      p = iend
    return p
  if e.winLen > 0:
    if p < WindowSize:
      p = e.bufferFrom(data, p, output)
      e.emitBlock(output)
      if not e.directBlock(data, p, last):
        return p
    # data[p] takes the place of the buffer's next block, after the last
    # 64 KiB of history, which are in `data` too.
    e.comp.moveHistory(e.winLen - p)
  else:
    # The frame starts with `data`: its positions are the compressor's.
    doAssert p == 0, "a linked frame starting part way into its data"
  while e.directBlock(data, p, last):
    let iend = min(p + e.bsize, data.len)
    e.comp.prepareLinked(p, iend)
    e.emitFrom(data, p, iend, output)
    p = iend
  if not last:
    e.reserveBuffer()
    copyMem(e.buf[0].addr, data[p - WindowSize].unsafeAddr, WindowSize)
    e.comp.moveHistory(p - WindowSize)
    e.winLen = WindowSize
  p

proc writeData(
    e: var FrameEncoder, data: openArray[byte], last: bool, output: var OutputBuffer
) {.raises: [].} =
  ## `write` after its checks. With `last`, `data` is the rest of the input
  ## and `finish` follows: its short last block is compressed where it is as
  ## well rather than copied to the buffer.
  e.startFrame(output)
  var p = 0
  if e.fill > 0 and data.len > 0:
    p = e.bufferFrom(data, 0, output)
  if e.fill == 0 and e.directBlock(data, p, last) and
      not (e.opts.blockIndependent and e.winLen > 0):
    p = e.emitDirect(data, p, last, output)
  while p < data.len:
    p = e.bufferFrom(data, p, output)
  e.written += data.len
  if e.opts.contentChecksum:
    e.digest.update(data)

proc write*(
    e: var FrameEncoder, data: openArray[byte], output: var (seq[byte] | string)
) {.raises: [Lz4Error].} =
  ## Adds `data` to the frame. Complete blocks are appended to `output` (the
  ## header comes with the first call), a seq of bytes or a string; the rest
  ## waits for more data, `flush` or `finish`. Whole blocks are compressed
  ## where they are, except those that go through the encoder's buffer.
  ##
  ## Raises ekInvalidArgument when `data` goes past the announced content
  ## size, after `finish`, and for an encoder that `initFrameEncoder` did
  ## not make. Nothing changes then: the encoder can go on.
  e.checkOpen("write")
  if e.contentSize >= 0 and data.len > e.contentSize - e.written:
    raiseLz4(ekInvalidArgument, "more data than the announced content size")
  e.writeData(data, last = false, output)

proc write*(
    e: var FrameEncoder, data: openArray[char], output: var (seq[byte] | string)
) {.raises: [Lz4Error].} =
  ## The same for `data` in a string or a slice of one
  ## (`s.toOpenArray(first, last)`).
  e.write(data.toOpenArrayByte(0, data.high), output)

proc flush*(
    e: var FrameEncoder, output: var (seq[byte] | string)
) {.raises: [Lz4Error].} =
  ## Compresses the pending input as a block now, even if it is shorter than
  ## the block size. Writes nothing when no input is pending, not even the
  ## header. Raises as `write` does.
  ##
  ## In a linked frame with a dictionary at the fast levels, the blocks
  ## after a flush may differ from liblz4's.
  e.checkOpen("flush")
  e.emitBlock(output)

proc finish*(
    e: var FrameEncoder, output: var (seq[byte] | string)
) {.raises: [Lz4Error].} =
  ## Writes the pending input, the end mark and the content checksum. Raises
  ## ekInvalidArgument when less data than the announced content size was
  ## written, and as `write` does; nothing changes then.
  ##
  ## The encoder keeps its tables and a buffer of up to 192 KiB for `reset`,
  ## and no longer refers to a FrameDict.
  e.checkOpen("finish")
  if e.contentSize >= 0 and e.written != e.contentSize:
    raiseLz4(ekInvalidArgument, "less data than the announced content size")
  e.startFrame(output)
  e.emitBlock(output)
  output.addLE32(0)
  if e.opts.contentChecksum:
    output.addLE32(e.digest.digest())
  e.finished = true
  # Nothing is compressed until a reset: release the dictionary states and
  # a large buffer.
  if e.buf.capacity > KeptEncoderBuffer:
    e.buf = @[]
    e.bufDict = 0
  elif e.buf.len > 0:
    e.buf.setLenNoInit(0)
  e.dictLen = 0
  e.pdict = nil
  e.keep = nil
  e.comp.release()

# Decoder

proc initFrameDecoder*(maxOutputSize: int64): FrameDecoder {.raises: [Lz4Error].} =
  ## A streaming decoder for a sequence of frames (normal, skippable and
  ## legacy). `maxOutputSize` limits the total output of all `feed` calls
  ## (ekLimitExceeded) and bounds memory use on untrusted input; pass
  ## high(int64) for no limit.
  ##
  ## Besides `output`, the decoder keeps 128 KiB of history for linked
  ## blocks and a buffer for a block that arrives in pieces.
  if maxOutputSize < 0:
    raiseLz4(ekInvalidArgument, "maxOutputSize must not be negative")
  FrameDecoder(ready: true, maxOutput: maxOutputSize, outOfRange: ekMalformed)

proc initFrameDecoder*(
    dict: openArray[byte], maxOutputSize: int64
): FrameDecoder {.raises: [Lz4Error].} =
  ## Same as `initFrameDecoder(maxOutputSize)` for frames compressed with
  ## the dictionary `dict` (used by every frame except legacy ones). The
  ## dictionary id of a frame is not checked, as with `lz4 -D`; `frameInfo`
  ## gives it. An empty `dict` is the same as none.
  result = initFrameDecoder(maxOutputSize)
  let tail = dictTail(dict.len)
  result.dict = @(dict.toOpenArray(tail, dict.len - 1))

proc atFrameEnd*(d: FrameDecoder): bool =
  ## True when the last `feed` stopped at the end of a frame (normal or
  ## skippable) and no new frame has been started. False right after
  ## `initFrameDecoder`, and after a legacy frame (which has no end mark: it
  ## ends when `feed` reads the magic number of the next frame).
  d.atEnd

proc frameInfo*(d: FrameDecoder, info: var FrameInfo): bool =
  ## Sets `info` to the header of the current frame and returns true: the
  ## frame whose header the last `feed` read, whose content it appended, or
  ## whose end it reached. Returns false and sets `info` to `FrameInfo()`
  ## while no whole header is known. The fields are those of
  ## `readFrameInfo`.
  ##
  ## The decoder does not check the dictionary id: compare `info.dictId`
  ## with the dictionary's. For this, `feed` stops after a frame header.
  if not d.hasInfo:
    info = FrameInfo()
    return false
  info = d.info
  true

proc checkReady(d: FrameDecoder) {.raises: [Lz4Error].} =
  ## The checks every call starts with: the first error again, if any.
  d.err.check()
  if not d.ready:
    raiseLz4(ekInvalidArgument, "the FrameDecoder was not made by initFrameDecoder")

proc limitLeft(d: FrameDecoder): int64 =
  d.maxOutput - d.total

func sizeKnown(d: FrameDecoder): bool =
  ## Whether the frame header gives the content size (0 means unknown).
  d.info.hasContentSize and d.info.contentSize != 0

proc startNormalFrame(d: var FrameDecoder) =
  ## The header in `hdr` has been validated into `info`.
  d.bmax = blockSizeBytes(d.info.blockSize)
  d.frameOut = 0
  d.frameIn = 0
  d.digest = initXxh32()
  if d.sizeKnown and d.info.contentSize > uint64(d.limitLeft):
    raiseLz4(ekLimitExceeded, "the frame content size exceeds maxOutputSize")
  d.outOfRange =
    if d.info.hasDictId and d.dict.len == 0: ekUnsupported else: ekMalformed
  # The history of linked blocks starts with the dictionary, copied to
  # `work` only when a feed stops inside the frame (see keepHistory).
  d.winLen = 0
  d.dictFirst = not d.info.blockIndependent and d.dict.len > 0

proc growOutput(output: var OutputBuffer, n: int) =
  if n > high(int) - output.len:
    raiseLz4(ekLimitExceeded, "the output does not fit in one buffer")
  output.setLenNoInit(output.len + n)

proc reserve(s: var OutputBuffer, extra: int, exact = false) =
  ## Grows the capacity of `s` to hold `extra` more bytes: as Nim grows it
  ## (by half at least), or with `exact` to just that.
  let n = s.len
  if not exact:
    s.setLenNoInit(n + extra)
    s.setLenNoInit(n)
  elif extra > s.capacity - n:
    var t =
      when s is string:
        newStringUninit(n + extra)
      else:
        newSeqUninit[byte](n + extra)
    if n > 0:
      copyMem(t[0].addr, s[0].addr, n)
    t.setLenNoInit(n)
    s = move t

proc estimateLeft(d: FrameDecoder, inputLeft: int): int =
  ## For a frame without a content size: what `inputLeft` bytes of input
  ## should decode to, at the ratio of the frame's blocks so far, plus an
  ## eighth; -1 before the first block.
  if d.frameIn == 0:
    return -1
  let e = float(d.frameOut) / float(d.frameIn) * float(inputLeft) * 1.125
  if e >= float(high(int)):
    high(int)
  else:
    int(e)

const InputGrowth = 4
  ## growFor may make room for this many times the input not yet decoded.

proc growFor(d: FrameDecoder, output: var OutputBuffer, room, inputLeft: int): int =
  ## Grows `output` for a block of a normal frame that may add up to `room`
  ## bytes, and returns how much of it to decode in first (see
  ## decodeBlockData). `inputLeft` is the input from the block on.
  ##
  ## It grows towards the end of the frame, by at most the larger of
  ## InputGrowth times `inputLeft` and what the frame decoded, so a false
  ## content size cannot cost much more than the input. In decodeAll's own
  ## output (`oneShot`) it grows to just the end.
  let len = output.len
  let most = high(int) - len
  let free = output.capacity - len
  if room <= free or room > most:
    # It fits, or cannot (growOutput reports that).
    return room
  let left =
    if d.sizeKnown:
      # (frameOut <= contentSize: checked after every block.)
      int(min(d.info.contentSize - uint64(d.frameOut), uint64(high(int))))
    else:
      d.estimateLeft(inputLeft)
  if left < 0:
    return room
  let allowed = max(
    min(len, int(min(d.frameOut, int64(high(int))))),
    if inputLeft > high(int) div InputGrowth:
      high(int)
    else:
      inputLeft * InputGrowth,
  )
  if d.oneShot:
    let want = min(left, allowed)
    if want > free:
      output.reserve(min(max(want, len div 3), most), exact = true)
    min(room, output.capacity - len)
  else:
    let towardsEnd =
      if left > allowed:
        allowed
      elif left > most - d.bmax:
        most
      else:
        left + d.bmax
    output.reserve(min(max(room, towardsEnd), most))
    room

proc keepHistory(d: var FrameDecoder, output: openArray[byte]) =
  ## Keeps the last 64 KiB of linked-block output as history for the next
  ## feed, with older history in `work` (or the dictionary) as an external
  ## dictionary.
  let n = output.len - d.histStart
  if n > 0:
    if d.work.len < 2 * WindowSize:
      d.work.setLenNoInit(2 * WindowSize)
    if d.dictFirst:
      # The end of the dictionary that the next blocks can still reach.
      d.dictFirst = false
      d.winLen = min(d.dict.len, WindowSize - min(n, WindowSize))
      if d.winLen > 0:
        copyMem(d.work[0].addr, d.dict[d.dict.len - d.winLen].addr, d.winLen)
  if n >= WindowSize:
    copyMem(d.work[0].addr, output[output.len - WindowSize].unsafeAddr, WindowSize)
    d.winLen = WindowSize
  elif n > 0:
    if d.winLen + n > d.work.len:
      let keep = min(d.winLen, WindowSize - n)
      moveMem(d.work[0].addr, d.work[d.winLen - keep].addr, keep)
      d.winLen = keep
    copyMem(d.work[d.winLen].addr, output[d.histStart].unsafeAddr, n)
    d.winLen += n
  d.histStart = output.len

proc decodeBlockData(
    d: var FrameDecoder, data: openArray[byte], inputLeft: int, output: var OutputBuffer
) =
  ## Handles one complete block (`data` includes its checksum, if any).
  ## `inputLeft` is the input of this feed still to decode: `data` and what
  ## follows it (only what follows for a block gathered in `blk`).
  let size = d.blockLen
  let legacy = d.state == stLegacyData
  if not legacy and d.info.blockChecksum and
      xxh32(data.toOpenArray(0, size - 1)) != readLE32(data, size):
    raiseLz4(ekChecksum, "block checksum mismatch")
  if d.blockRaw and int64(size) > d.limitLeft:
    # Checked after the checksum, as for a compressed block.
    raiseLz4(ekLimitExceeded, "the decompressed data exceeds maxOutputSize")
  let before = output.len
  try:
    let left = d.limitLeft
    let blockMax = if legacy: LegacyBlockSize else: d.bmax
    let structural = storedCapacity(size, blockMax)
    # decodeChecked works with an int limit; no block is larger.
    let limit = int(min(left, int64(high(int))))
    # What the block may add to `output`; on error, `output` is cut back.
    let room =
      if d.blockRaw:
        size
      else:
        min(structural, limit)
    let space =
      if legacy:
        room
      else:
        d.growFor(output, room, inputLeft)
    if d.blockRaw:
      growOutput(output, room)
      if size > 0:
        copyMem(output[before].addr, data[0].addr, size)
    else:
      template decodeAfter(dict: openArray[byte], lowLimit: int): int =
        decodeChecked(
          data.toOpenArray(0, size - 1),
          output.asBytes(0, output.high),
          dict,
          before,
          lowLimit,
          structural,
          limit,
          if legacy: ekMalformed else: d.outOfRange,
        )

      template decode(): int =
        if legacy:
          # Legacy frames never use the dictionary.
          decodeAfter(d.dict.toOpenArray(0, -1), before)
        elif d.info.blockIndependent:
          decodeAfter(d.dict, before)
        elif d.dictFirst:
          decodeAfter(d.dict, d.histStart)
        else:
          decodeAfter(d.work.toOpenArray(0, d.winLen - 1), d.histStart)

      # First in `space`, which growFor may make smaller than `room`; in
      # `room` again if the block does not fit.
      growOutput(output, space)
      var e = decode()
      if e < 0:
        output.setLenNoInit(before)
        growOutput(output, room)
        e = decode()
      output.setLenNoInit(e)
    let n = output.len - before
    d.total += n
    if not legacy:
      d.frameOut += n
      d.frameIn += size
      if d.sizeKnown and uint64(d.frameOut) > d.info.contentSize:
        raiseLz4(ekMalformed, "the frame holds more data than its content size")
      if d.info.contentChecksum:
        d.digest.update(output.asBytes(before, output.high))
  except Lz4Error as e:
    output.setLenNoInit(before)
    # See `sticky`.
    raise e

proc dropLargeBuffer(d: var FrameDecoder) =
  ## At the end of a frame: see KeptBlockBuffer.
  if d.blk.len > KeptBlockBuffer:
    d.blk = @[]

proc endFrame(d: var FrameDecoder) =
  if d.sizeKnown and uint64(d.frameOut) != d.info.contentSize:
    raiseLz4(ekMalformed, "the frame content size does not match its data")
  d.state = stMagic
  d.hdrLen = 0
  d.atEnd = true
  d.dropLargeBuffer()

proc gather(d: var FrameDecoder, input: openArray[byte], pos: var int, n: int): bool =
  ## Collects bytes into `hdr` until it holds `n`; true when it does.
  let take = min(n - d.hdrLen, input.len - pos)
  for k in 0 ..< take:
    d.hdr[d.hdrLen + k] = input[pos + k]
  d.hdrLen += take
  pos += take
  d.hdrLen == n

proc startMagic(d: var FrameDecoder) =
  ## Dispatches on the magic number in `hdr[0 ..< 4]`.
  let magic = readLE32(d.hdr, 0)
  if magic == FrameMagic:
    d.state = stHeader
    d.hdrNeed = 5
  elif (magic and SkippableMagicMask) == SkippableMagicBase:
    d.frameOut = 0
    d.state = stSkipSize
  elif magic == LegacyMagic:
    d.info = LegacyFrameInfo
    d.hasInfo = true
    d.state = stLegacySize
    d.hdrLen = 0
  else:
    raiseLz4(ekMalformed, "unknown frame magic number")

proc feedBlock(
    d: var FrameDecoder, input: openArray[byte], pos: var int, output: var OutputBuffer
): bool =
  ## Feeds the current block; true once it has been decoded.
  if d.blkLen == 0 and input.len - pos >= d.need:
    d.decodeBlockData(input.toOpenArray(pos, pos + d.need - 1), input.len - pos, output)
    pos += d.need
    return true
  let take = min(d.need - d.blkLen, input.len - pos)
  if d.blk.len < d.blkLen + take:
    # Grown with the data, not to the announced size.
    d.blk.setLenNoInit(min(d.need, max(d.blkLen + take, 2 * d.blk.len)))
  if take > 0:
    copyMem(d.blk[d.blkLen].addr, input[pos].addr, take)
  d.blkLen += take
  pos += take
  if d.blkLen < d.need:
    return false
  d.decodeBlockData(d.blk.toOpenArray(0, d.need - 1), input.len - pos, output)
  d.blkLen = 0
  true

proc feedInput(
    d: var FrameDecoder, input: openArray[byte], pos: var int, output: var OutputBuffer
) =
  ## `feed` after its checks: decodes `input` from `pos` on, until the
  ## input ends or `feed` stops, and moves `pos` past what it consumed.
  while pos < input.len:
    case d.state
    of stMagic:
      if not d.gather(input, pos, 4):
        break
      d.startMagic()
      if d.state == stLegacySize:
        # The magic number is the whole header of a legacy frame.
        return
    of stHeader:
      if not d.gather(input, pos, d.hdrNeed):
        break
      if d.hdrNeed == 5:
        checkFlg(d.hdr[4])
        d.hdrNeed = headerLength(d.hdr[4])
        continue
      if parseHeader(d.hdr.toOpenArray(0, d.hdrNeed - 1), 0, d.info) == 0:
        raiseLz4(ekMalformed, "truncated frame header")
      d.hasInfo = true
      d.startNormalFrame()
      d.state = stBlockHeader
      d.hdrLen = 0
      return
    of stBlockHeader:
      if not d.gather(input, pos, 4):
        break
      let h = readLE32(d.hdr, 0)
      d.hdrLen = 0
      if h == 0:
        if d.info.contentChecksum:
          d.state = stContentChecksum
        else:
          d.endFrame()
          return
      else:
        let size = int(h and 0x7FFF_FFFF'u32)
        if size > d.bmax:
          raiseLz4(ekMalformed, "block larger than the block maximum size")
        d.blockLen = size
        d.blockRaw = (h and 0x8000_0000'u32) != 0
        if d.blockRaw and not d.info.blockChecksum and int64(size) > d.limitLeft:
          # Known from the header: no need to wait for the data.
          raiseLz4(ekLimitExceeded, "the decompressed data exceeds maxOutputSize")
        d.need = size + (if d.info.blockChecksum: 4 else: 0)
        d.blkLen = 0
        d.state = stBlockData
        if d.need == 0:
          # An empty uncompressed block: decode it now.
          d.decodeBlockData(d.hdr.toOpenArray(0, -1), input.len - pos, output)
          d.state = stBlockHeader
    of stBlockData:
      if d.feedBlock(input, pos, output):
        d.state = stBlockHeader
    of stContentChecksum:
      if not d.gather(input, pos, 4):
        break
      if d.digest.digest() != readLE32(d.hdr, 0):
        raiseLz4(ekChecksum, "content checksum mismatch")
      d.endFrame()
      return
    of stSkipSize:
      if not d.gather(input, pos, 8):
        break
      d.info = FrameInfo(kind: fkSkippable, skippableSize: readLE32(d.hdr, 4))
      d.hasInfo = true
      d.skipLeft = int64(d.info.skippableSize)
      d.state = stSkipData
      if d.skipLeft == 0:
        d.endFrame()
      return
    of stSkipData:
      let take = int(min(d.skipLeft, int64(input.len - pos)))
      pos += take
      d.skipLeft -= take
      if d.skipLeft == 0:
        d.endFrame()
        return
    of stLegacySize:
      if not d.gather(input, pos, 4):
        break
      let size = readLE32(d.hdr, 0)
      if size > uint32(LegacyMaxStored):
        # The next frame's magic number: the legacy frame ends here.
        d.dropLargeBuffer()
        d.startMagic()
        return
      d.hdrLen = 0
      d.blockLen = int(size)
      d.blockRaw = false
      d.need = int(size)
      d.blkLen = 0
      d.state = stLegacyData
      if d.need == 0:
        # Decode the invalid empty block now.
        d.decodeBlockData(d.hdr.toOpenArray(0, -1), input.len - pos, output)
        d.state = stLegacySize
    of stLegacyData:
      if d.feedBlock(input, pos, output):
        d.state = stLegacySize

proc feed*(
    d: var FrameDecoder, input: openArray[byte], output: var (seq[byte] | string)
): int {.raises: [Lz4Error].} =
  ## Decodes as much of `input` as possible, appends the content to
  ## `output` and returns the number of bytes consumed. It stops after each
  ## frame header, before any of the frame's content (so that `frameInfo`
  ## can be checked first), and at the end of a frame. The result may be
  ## less than `input.len`: feed the rest again to go on. A non-empty
  ## `input` always consumes at least one byte.
  ##
  ## The caller may empty `output` between calls: the decoder keeps the
  ## history that linked blocks need.
  ##
  ## On an error, `output` keeps the blocks completed before it, and later
  ## calls raise the same error. Raises ekInvalidArgument for a decoder
  ## that `initFrameDecoder` did not make.
  d.checkReady()
  if input.len == 0:
    return 0
  var pos = 0
  d.histStart = output.len
  if d.state in {stMagic, stHeader, stSkipSize}:
    # A frame starts only here, as feed returns at the end of the previous
    # one: none is known until then.
    d.hasInfo = false
  sticky d.err:
    d.atEnd = false
    d.feedInput(input, pos, output)
    # Keep the new history in `work`: the caller may empty `output` before
    # the next call.
    if d.state in {stBlockHeader, stBlockData} and not d.info.blockIndependent:
      d.keepHistory(output.asBytes(0, output.high))
  pos

proc feed*(
    d: var FrameDecoder, input: openArray[char], output: var (seq[byte] | string)
): int {.raises: [Lz4Error].} =
  ## The same for `input` in a string or a slice of one
  ## (`s.toOpenArray(pos, s.high)`).
  d.feed(input.toOpenArrayByte(0, input.high), output)

proc finish*(d: var FrameDecoder) {.raises: [Lz4Error].} =
  ## Call at the end of the input. Raises ekMalformed when it ends inside a
  ## frame (which changes nothing: more input can still complete it).
  ## Ending right after a frame, between two blocks of a legacy frame, or
  ## before any input is fine; the decoder can then go on with more input.
  d.checkReady()
  if d.hdrLen != 0 or d.state notin {stMagic, stLegacySize}:
    raiseLz4(ekMalformed, "the input ends inside a frame")
  d.dropLargeBuffer()

# One-shot decompression

proc decodeAll(
    d: var FrameDecoder, src: openArray[byte], output: var OutputBuffer
) {.raises: [Lz4Error].} =
  ## Decodes `src` into the empty `output`, which an exception leaves
  ## empty.
  var o: typeof(output)
  d.oneShot = true
  var pos = 0
  while pos < src.len:
    pos += d.feed(src.toOpenArray(pos, src.high), o)
  d.finish()
  o.trimCapacity()
  output = move o

proc decompressFrame*(
    src: openArray[byte], maxOutputSize: int
): seq[byte] {.raises: [Lz4Error].} =
  ## Decompresses all the frames in `src` (normal, skippable and legacy,
  ## one after the other, as the lz4 CLI does) and returns their
  ## concatenated content. An empty `src` gives an empty result.
  ##
  ## `maxOutputSize` limits the total output (ekLimitExceeded): pass what
  ## the caller expects, or high(int) for no limit. Raises ekMalformed for
  ## invalid data, ekChecksum for a checksum mismatch, and ekUnsupported
  ## when a frame with a dictionary id needs a dictionary that was not
  ## given.
  var d = initFrameDecoder(maxOutputSize)
  d.decodeAll(src, result)

proc decompressFrame*(
    src: openArray[byte], dict: openArray[byte], maxOutputSize: int
): seq[byte] {.raises: [Lz4Error].} =
  ## Same as `decompressFrame(src, maxOutputSize)` for frames compressed
  ## with the dictionary `dict` (`lz4 -D`). The dictionary is used whether
  ## or not a frame has a dictionary id, and the id is not checked; every
  ## frame starts from the dictionary again. Legacy frames never use it.
  var d = initFrameDecoder(dict, maxOutputSize)
  d.decodeAll(src, result)

proc decompress*(s: string, maxOutputSize: int): string {.raises: [Lz4Error].} =
  ## Decompresses the LZ4 frames in `s` (see `decompressFrame`).
  var d = initFrameDecoder(maxOutputSize)
  d.decodeAll(s.toOpenArrayByte(0, s.high), result)

proc decompress*(
    s: string, dict: string, maxOutputSize: int
): string {.raises: [Lz4Error].} =
  ## Same as `decompress(s, maxOutputSize)` for frames compressed with the
  ## dictionary `dict` (see `decompressFrame(src, dict, maxOutputSize)`).
  var d = initFrameDecoder(dict.toOpenArrayByte(0, dict.high), maxOutputSize)
  d.decodeAll(s.toOpenArrayByte(0, s.high), result)

# One-shot compression

func oneShotOptions(opts: FrameOptions, srcLen: int): FrameOptions =
  ## The options of the frame of `srcLen` bytes, as `compressFrame` chooses
  ## them: the smallest block size up to `opts.blockSize` that holds the
  ## whole input, and then independent blocks.
  result = opts
  while result.blockSize > bs64KiB and srcLen <= blockSizeBytes(pred(result.blockSize)):
    result.blockSize = pred(result.blockSize)
  if srcLen <= blockSizeBytes(result.blockSize):
    result.blockIndependent = true

proc frameBound(src: openArray[byte], opts: FrameOptions): int {.raises: [Lz4Error].} =
  ## Room for the frame of `src`: a block is stored in at most its input
  ## length (otherwise it is kept uncompressed).
  checkOneBuffer(src.len)
  let bsize = blockSizeBytes(opts.blockSize)
  MaxHeaderSize + (src.len + bsize - 1) div bsize * 8 + src.len + 8

proc encodeAll(
    e: var FrameEncoder,
    src, dict: openArray[byte],
    prepared: ptr PreparedDict,
    opts: FrameOptions,
    output: var OutputBuffer,
) {.raises: [Lz4Error].} =
  ## Writes the frame of `src` to the empty `output`, with the options of
  ## oneShotOptions, in `e` (see reset). The dictionary is `prepared[]`,
  ## or when nil, `dict` (none when empty).
  checkBlockSize(opts)
  let o = oneShotOptions(opts, src.len)
  # Check the size before the encoder copies the dictionary and makes its
  # states.
  let bound = frameBound(src, o)
  let size = if o.writeContentSize: src.len.int64 else: -1
  if prepared != nil:
    # Only read: `keep` stays nil.
    e.init(prepared, o, size)
  else:
    e.init(dict, o, size)
  var frame: typeof(output)
  frame.reserve(bound)
  # Blocks are compressed where they are in `src`, except independent blocks
  # that need a copy of the dictionary in front of them, and the first linked
  # block after it.
  e.writeData(src, last = true, frame)
  e.finish(frame)
  frame.trimCapacity()
  output = move frame

proc encodeAll(
    src, dict: openArray[byte],
    prepared: ptr PreparedDict,
    opts: FrameOptions,
    output: var OutputBuffer,
) {.raises: [Lz4Error].} =
  ## The same with a new encoder.
  var e: FrameEncoder
  e.encodeAll(src, dict, prepared, opts, output)

proc compressFrame*(
    src: openArray[byte], opts = FrameOptions()
): seq[byte] {.raises: [Lz4Error].} =
  ## Compresses `src` into one LZ4 frame.
  ##
  ## An input that fits in one block gets the smallest block size that holds
  ## it (up to `opts.blockSize`) and independent blocks; otherwise the
  ## header gets `opts.blockSize` and `opts.blockIndependent` as given. The
  ## content size is written when `opts.writeContentSize` is set and the
  ## input is not empty.
  ##
  ## The frame is that of the `lz4` tool with the same options for an input
  ## below 4 MiB; larger inputs may differ, as the tool compresses them in
  ## 4 MiB pieces.
  ##
  ## Every call makes new tables. To compress many short inputs, reuse a
  ## FrameEncoder (`compressFrame(e, src, opts)`).
  encodeAll(src, [], nil, opts, result)

proc compressFrame*(
    src: openArray[byte], dict: openArray[byte], opts = FrameOptions()
): seq[byte] {.raises: [Lz4Error].} =
  ## Compresses `src` into one LZ4 frame with the dictionary `dict` (see
  ## `initFrameEncoder(dict, ...)`), as `lz4 -D` does: the frame is that of
  ## LZ4F_compressFrame_usingCDict. To compress many frames with one
  ## dictionary, prepare it once (`initFrameDict`).
  encodeAll(src, dict, nil, opts, result)

proc compressFrame*(
    src: openArray[byte], dict: FrameDict, opts = FrameOptions()
): seq[byte] {.raises: [Lz4Error].} =
  ## Same as `compressFrame(src, dict, opts)` with the dictionary that
  ## `dict` prepared, which costs less than indexing it again: a short
  ## frame costs little more than without a dictionary. `dict` is only
  ## read (see `FrameDict`).
  encodeAll(src, [], dict.prepared, opts, result)

proc compress*(s: string, opts = FrameOptions()): string {.raises: [Lz4Error].} =
  ## Compresses `s` into one LZ4 frame (see `compressFrame`).
  encodeAll(s.toOpenArrayByte(0, s.high), [], nil, opts, result)

proc compress*(
    s: string, dict: string, opts = FrameOptions()
): string {.raises: [Lz4Error].} =
  ## Compresses `s` into one LZ4 frame with the dictionary `dict` (see
  ## `compressFrame(src, dict, opts)`).
  encodeAll(
    s.toOpenArrayByte(0, s.high), dict.toOpenArrayByte(0, dict.high), nil, opts, result
  )

proc compress*(
    s: string, dict: FrameDict, opts = FrameOptions()
): string {.raises: [Lz4Error].} =
  ## Compresses `s` into one LZ4 frame with the dictionary that `dict`
  ## prepared (see `compressFrame(src, dict: FrameDict, opts)`).
  encodeAll(s.toOpenArrayByte(0, s.high), [], dict.prepared, opts, result)

proc compressFrame*(
    e: var FrameEncoder, src: openArray[byte], opts = FrameOptions()
): seq[byte] {.raises: [Lz4Error].} =
  ## Same as `compressFrame(src, opts)`, with the tables of `e` (see
  ## `reset`): to compress many short inputs, reuse one encoder. The frame
  ## in progress in `e`, if any, is dropped, and `e` is left finished.
  ## Raises as `compressFrame(src, opts)` does; `e` is unchanged then.
  e.encodeAll(src, [], nil, opts, result)

proc compressFrame*(
    e: var FrameEncoder,
    src: openArray[byte],
    dict: openArray[byte],
    opts = FrameOptions(),
): seq[byte] {.raises: [Lz4Error].} =
  ## Same as `compressFrame(src, dict, opts)`, with the tables of `e` (see
  ## `compressFrame(e, src, opts)`).
  e.encodeAll(src, dict, nil, opts, result)

proc compressFrame*(
    e: var FrameEncoder, src: openArray[byte], dict: FrameDict, opts = FrameOptions()
): seq[byte] {.raises: [Lz4Error].} =
  ## Same as `compressFrame(src, dict: FrameDict, opts)`, with the tables of
  ## `e` (see `compressFrame(e, src, opts)`): to compress many short inputs
  ## with one dictionary, the fastest way. `e` does not refer to `dict`
  ## afterwards.
  e.encodeAll(src, [], dict.prepared, opts, result)

proc compress*(
    e: var FrameEncoder, s: string, opts = FrameOptions()
): string {.raises: [Lz4Error].} =
  ## Same as `compress(s, opts)`, with the tables of `e` (see
  ## `compressFrame(e, src, opts)`).
  e.encodeAll(s.toOpenArrayByte(0, s.high), [], nil, opts, result)

proc compress*(
    e: var FrameEncoder, s: string, dict: string, opts = FrameOptions()
): string {.raises: [Lz4Error].} =
  ## Same as `compress(s, dict, opts)`, with the tables of `e` (see
  ## `compressFrame(e, src, opts)`).
  e.encodeAll(
    s.toOpenArrayByte(0, s.high), dict.toOpenArrayByte(0, dict.high), nil, opts, result
  )

proc compress*(
    e: var FrameEncoder, s: string, dict: FrameDict, opts = FrameOptions()
): string {.raises: [Lz4Error].} =
  ## Same as `compress(s, dict: FrameDict, opts)`, with the tables of `e`
  ## (see `compressFrame(e, src, dict: FrameDict, opts)`).
  e.encodeAll(s.toOpenArrayByte(0, s.high), [], dict.prepared, opts, result)
