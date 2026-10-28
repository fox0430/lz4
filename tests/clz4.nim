## Test-only liblz4 bindings, used to cross-check this implementation.
##
## The library never imports this module. Among the tests only
## tinterop_lib.nim imports it, so the other tests do not link against
## liblz4 and can run where it is not installed. The link flags come from
## `-d:clz4Link=...` (default `-llz4`); CI passes the path of a static
## liblz4.a built from lz4 1.10.0.

const clz4Link* {.strdefine.} = "-llz4"
{.passL: clz4Link.}

type
  LZ4FDctx* = distinct pointer
  LZ4FDecompressOptions* = object
    stableDst*: cuint
    skipChecksums*: cuint
    reserved1*: cuint
    reserved0*: cuint

  LZ4FCctx* = distinct pointer
  LZ4FCDict* = distinct pointer
  LZ4FFrameInfo* = object
    blockSizeID*: cint
    blockMode*: cint ## 0: linked, 1: independent
    contentChecksumFlag*: cint
    frameType*: cint
    contentSize*: culonglong
    dictID*: cuint
    blockChecksumFlag*: cint

  LZ4FPreferences* = object
    frameInfo*: LZ4FFrameInfo
    compressionLevel*: cint
    autoFlush*: cuint
    favorDecSpeed*: cuint
    reserved*: array[3, cuint]

const LZ4F_VERSION* = 100

{.push importc, cdecl.}
proc LZ4_versionNumber*(): cint
proc LZ4_compressBound*(inputSize: cint): cint
proc LZ4_compress_default*(src, dst: pointer, srcSize, dstCapacity: cint): cint
proc LZ4_compress_fast*(
  src, dst: pointer, srcSize, dstCapacity, acceleration: cint
): cint

proc LZ4_compress_HC*(
  src, dst: pointer, srcSize, dstCapacity, compressionLevel: cint
): cint

proc LZ4_decompress_safe*(src, dst: pointer, compressedSize, dstCapacity: cint): cint
proc LZ4_decompress_safe_usingDict*(
  src, dst: pointer, srcSize, dstCapacity: cint, dictStart: pointer, dictSize: cint
): cint

proc LZ4_createStream*(): pointer
proc LZ4_freeStream*(stream: pointer): cint
proc LZ4_loadDict*(stream: pointer, dict: pointer, dictSize: cint): cint
proc LZ4_compress_fast_continue*(
  stream: pointer, src, dst: pointer, srcSize, dstCapacity, acceleration: cint
): cint

proc LZ4_createStreamHC*(): pointer
proc LZ4_freeStreamHC*(stream: pointer): cint
proc LZ4_resetStreamHC_fast*(stream: pointer, level: cint)
proc LZ4_loadDictHC*(stream: pointer, dict: pointer, dictSize: cint): cint
proc LZ4_compress_HC_continue*(
  stream: pointer, src, dst: pointer, srcSize, dstCapacity: cint
): cint

proc LZ4F_isError*(code: csize_t): cuint
proc LZ4F_getErrorName*(code: csize_t): cstring
proc LZ4F_createDecompressionContext*(dctx: var LZ4FDctx, version: cuint): csize_t
proc LZ4F_freeDecompressionContext*(dctx: LZ4FDctx): csize_t
proc LZ4F_decompress*(
  dctx: LZ4FDctx,
  dst: pointer,
  dstSize: var csize_t,
  src: pointer,
  srcSize: var csize_t,
  opts: ptr LZ4FDecompressOptions,
): csize_t

proc LZ4F_decompress_usingDict*(
  dctx: LZ4FDctx,
  dst: pointer,
  dstSize: var csize_t,
  src: pointer,
  srcSize: var csize_t,
  dict: pointer,
  dictSize: csize_t,
  opts: ptr LZ4FDecompressOptions,
): csize_t

proc LZ4F_createCompressionContext*(cctx: var LZ4FCctx, version: cuint): csize_t
proc LZ4F_freeCompressionContext*(cctx: LZ4FCctx): csize_t
proc LZ4F_createCDict*(dict: pointer, dictSize: csize_t): LZ4FCDict
proc LZ4F_freeCDict*(cdict: LZ4FCDict)
proc LZ4F_compressBound*(srcSize: csize_t, prefs: ptr LZ4FPreferences): csize_t
proc LZ4F_compressFrameBound*(srcSize: csize_t, prefs: ptr LZ4FPreferences): csize_t
proc LZ4F_compressFrame*(
  dst: pointer,
  dstCapacity: csize_t,
  src: pointer,
  srcSize: csize_t,
  prefs: ptr LZ4FPreferences,
): csize_t

proc LZ4F_compressBegin_usingCDict*(
  cctx: LZ4FCctx,
  dst: pointer,
  dstCapacity: csize_t,
  cdict: LZ4FCDict,
  prefs: ptr LZ4FPreferences,
): csize_t

proc LZ4F_compressUpdate*(
  cctx: LZ4FCctx,
  dst: pointer,
  dstCapacity: csize_t,
  src: pointer,
  srcSize: csize_t,
  opts: pointer,
): csize_t

proc LZ4F_flush*(
  cctx: LZ4FCctx, dst: pointer, dstCapacity: csize_t, opts: pointer
): csize_t

proc LZ4F_compressEnd*(
  cctx: LZ4FCctx, dst: pointer, dstCapacity: csize_t, opts: pointer
): csize_t

{.pop.}

var emptyBuf: array[1, byte]

proc dataPtr(a: openArray[byte]): pointer {.inline.} =
  # LZ4_compress_HC crashes on a NULL source even when its size is 0, so an
  # empty buffer gets a valid (unused) address instead.
  if a.len == 0:
    emptyBuf[0].addr
  else:
    a[0].addr

proc libCompress*(src: openArray[byte], acceleration = 1): seq[byte] =
  ## LZ4_compress_fast into a buffer of LZ4_compressBound bytes.
  result = newSeq[byte](LZ4_compressBound(src.len.cint))
  let n = LZ4_compress_fast(
    dataPtr(src), dataPtr(result), src.len.cint, result.len.cint, acceleration.cint
  )
  doAssert n > 0, "LZ4_compress_fast failed"
  result.setLen(n)

proc libCompressHC*(src: openArray[byte], level: int): seq[byte] =
  result = newSeq[byte](LZ4_compressBound(src.len.cint))
  let n = LZ4_compress_HC(
    dataPtr(src), dataPtr(result), src.len.cint, result.len.cint, level.cint
  )
  doAssert n > 0, "LZ4_compress_HC failed"
  result.setLen(n)

proc libCompressDict*(src, dict: openArray[byte], acceleration = 1): seq[byte] =
  ## LZ4_loadDict + LZ4_compress_fast_continue: one block that may refer to
  ## the dictionary.
  let stream = LZ4_createStream()
  defer:
    discard LZ4_freeStream(stream)
  discard LZ4_loadDict(stream, dataPtr(dict), dict.len.cint)
  result = newSeq[byte](LZ4_compressBound(src.len.cint))
  let n = LZ4_compress_fast_continue(
    stream,
    dataPtr(src),
    dataPtr(result),
    src.len.cint,
    result.len.cint,
    acceleration.cint,
  )
  doAssert n > 0, "LZ4_compress_fast_continue failed"
  result.setLen(n)

proc libCompressHCDict*(src, dict: openArray[byte], level: int): seq[byte] =
  ## LZ4_loadDictHC + LZ4_compress_HC_continue.
  let stream = LZ4_createStreamHC()
  defer:
    discard LZ4_freeStreamHC(stream)
  LZ4_resetStreamHC_fast(stream, level.cint)
  discard LZ4_loadDictHC(stream, dataPtr(dict), dict.len.cint)
  result = newSeq[byte](LZ4_compressBound(src.len.cint))
  let n = LZ4_compress_HC_continue(
    stream, dataPtr(src), dataPtr(result), src.len.cint, result.len.cint
  )
  doAssert n > 0, "LZ4_compress_HC_continue failed"
  result.setLen(n)

proc libDecompress*(
    src: openArray[byte], capacity: int
): tuple[ok: bool, data: seq[byte]] =
  ## LZ4_decompress_safe with an output buffer of `capacity` bytes.
  var dst = newSeq[byte](capacity)
  let n = LZ4_decompress_safe(dataPtr(src), dataPtr(dst), src.len.cint, capacity.cint)
  if n < 0:
    return (false, @[])
  dst.setLen(n)
  (true, dst)

proc libDecompressDict*(
    src, dict: openArray[byte], capacity: int
): tuple[ok: bool, data: seq[byte]] =
  var dst = newSeq[byte](capacity)
  let n = LZ4_decompress_safe_usingDict(
    dataPtr(src),
    dataPtr(dst),
    src.len.cint,
    capacity.cint,
    dataPtr(dict),
    dict.len.cint,
  )
  if n < 0:
    return (false, @[])
  dst.setLen(n)
  (true, dst)

proc libDecompressFrame*(
    src: openArray[byte], dict: openArray[byte] = [], maxOutput = 1 shl 30
): tuple[ok: bool, consumed: int, data: seq[byte]] =
  ## Decodes the first frame of `src` with LZ4F_decompress(_usingDict).
  ## `ok` is true only when the frame was complete (LZ4F_decompress returned
  ## 0) within `maxOutput` bytes of output; `consumed` is the number of input
  ## bytes LZ4F used. The output buffer grows on demand.
  var dctx: LZ4FDctx
  doAssert LZ4F_isError(LZ4F_createDecompressionContext(dctx, LZ4F_VERSION)) == 0
  defer:
    discard LZ4F_freeDecompressionContext(dctx)
  var dst = newSeqUninit[byte](min(maxOutput, max(1 shl 16, src.len * 4)))
  var inPos = 0
  var outPos = 0
  while true:
    if outPos == dst.len:
      if dst.len >= maxOutput:
        return (false, inPos, @[])
      dst.setLen(min(maxOutput, dst.len * 2))
    var dstSize = csize_t(dst.len - outPos)
    var srcSize = csize_t(src.len - inPos)
    let srcP =
      if inPos < src.len:
        src[inPos].addr
      else:
        nil
    let r =
      if dict.len > 0:
        LZ4F_decompress_usingDict(
          dctx,
          dst[outPos].addr,
          dstSize,
          srcP,
          srcSize,
          dataPtr(dict),
          csize_t(dict.len),
          nil,
        )
      else:
        LZ4F_decompress(dctx, dst[outPos].addr, dstSize, srcP, srcSize, nil)
    inPos += int(srcSize)
    outPos += int(dstSize)
    if LZ4F_isError(r) != 0:
      return (false, inPos, @[])
    if r == 0:
      dst.setLen(outPos)
      return (true, inPos, dst)
    if srcSize == 0 and dstSize == 0 and outPos < dst.len:
      # No progress although there is room for output: the input ended
      # inside the frame.
      return (false, inPos, @[])

proc libDecompressFrameInto*(src: openArray[byte], dst: var openArray[byte]): int =
  ## Decodes the first frame of `src` with LZ4F_decompress into `dst`, a
  ## buffer made beforehand. Returns the content length, or -1 when the
  ## frame is invalid, does not end within `src` or does not fit in `dst`.
  var dctx: LZ4FDctx
  doAssert LZ4F_isError(LZ4F_createDecompressionContext(dctx, LZ4F_VERSION)) == 0
  defer:
    discard LZ4F_freeDecompressionContext(dctx)
  var inPos = 0
  var outPos = 0
  while true:
    var dstSize = csize_t(dst.len - outPos)
    var srcSize = csize_t(src.len - inPos)
    let r = LZ4F_decompress(
      dctx,
      dataPtr(dst.toOpenArray(outPos, dst.high)),
      dstSize,
      dataPtr(src.toOpenArray(inPos, src.high)),
      srcSize,
      nil,
    )
    inPos += int(srcSize)
    outPos += int(dstSize)
    if LZ4F_isError(r) != 0:
      return -1
    if r == 0:
      return outPos
    if srcSize == 0 and dstSize == 0:
      # No progress: the input ended inside the frame, or `dst` is full.
      return -1

proc libCompressFrame*(data: openArray[byte], level: int, linked: bool): seq[byte] =
  ## The frame of LZ4F_compressFrame with 64 KiB blocks and a content
  ## checksum, as `compressFrame(data, FrameOptions(...))` makes it.
  var prefs = LZ4FPreferences(
    frameInfo: LZ4FFrameInfo(
      blockSizeID: 4, blockMode: (if linked: 0 else: 1), contentChecksumFlag: 1
    ),
    compressionLevel: cint(level),
  )
  result = newSeqUninit[byte](LZ4F_compressFrameBound(csize_t(data.len), prefs.addr))
  let r = LZ4F_compressFrame(
    dataPtr(result), csize_t(result.len), dataPtr(data), csize_t(data.len), prefs.addr
  )
  doAssert LZ4F_isError(r) == 0, $LZ4F_getErrorName(r)
  result.setLen(int(r))

proc libCompressFrameStream*(
    data, dict: openArray[byte],
    writes: openArray[tuple[len: int, flush: bool]],
    level: int,
    linked: bool,
): seq[byte] =
  ## The frame of LZ4F_compressBegin_usingCDict (no dictionary when `dict` is
  ## empty), one LZ4F_compressUpdate per write, each followed by LZ4F_flush
  ## when asked, then LZ4F_compressEnd: 64 KiB blocks and a content
  ## checksum, as `FrameOptions()`. The writes must add up to `data.len`.
  var cctx: LZ4FCctx
  doAssert LZ4F_isError(LZ4F_createCompressionContext(cctx, LZ4F_VERSION)) == 0
  let cdict =
    if dict.len > 0:
      LZ4F_createCDict(dict[0].unsafeAddr, csize_t(dict.len))
    else:
      LZ4FCDict(nil)
  defer:
    discard LZ4F_freeCompressionContext(cctx)
    if dict.len > 0:
      LZ4F_freeCDict(cdict)
  var prefs = LZ4FPreferences(
    frameInfo: LZ4FFrameInfo(
      blockSizeID: 4, blockMode: (if linked: 0 else: 1), contentChecksumFlag: 1
    ),
    compressionLevel: cint(level),
  )
  var pos = 0
  template call(srcSize: int, body: untyped) =
    # With room for the worst case of the call at `dstP`.
    block:
      result.setLen(pos + int(LZ4F_compressBound(csize_t(srcSize), prefs.addr)) + 32)
      let dstP {.inject.} = result[pos].addr
      let dstCap {.inject.} = csize_t(result.len - pos)
      let r = body
      doAssert LZ4F_isError(r) == 0, $LZ4F_getErrorName(r)
      pos += int(r)

  call(0, LZ4F_compressBegin_usingCDict(cctx, dstP, dstCap, cdict, prefs.addr))
  var p = 0
  for w in writes:
    let src = dataPtr(data.toOpenArray(p, p + w.len - 1))
    call(w.len, LZ4F_compressUpdate(cctx, dstP, dstCap, src, csize_t(w.len), nil))
    p += w.len
    if w.flush:
      call(0, LZ4F_flush(cctx, dstP, dstCap, nil))
  doAssert p == data.len
  call(0, LZ4F_compressEnd(cctx, dstP, dstCap, nil))
  result.setLen(pos)
