## Frame headers (`readFrameInfo`) and legacy frames. The frame encoder and
## decoder and the one-shot frame procs are in `lz4/streaming`; `lz4` exports
## this module.

import private/[common, frameimpl]
import blocks

func blockMaxSize*(info: FrameInfo): int =
  ## The size of the largest block of the frame in bytes: that of
  ## `info.blockSize` for a normal frame, 8 MiB for a legacy frame, 0 for a
  ## skippable frame (which has no blocks).
  case info.kind
  of fkNormal:
    blockSizeBytes(info.blockSize)
  of fkSkippable:
    0
  of fkLegacy:
    LegacyBlockSize

# Header

proc readFrameInfo*(
    src: openArray[byte], info: var FrameInfo
): int {.raises: [Lz4Error].} =
  ## Reads the frame header at the start of `src` into `info` and returns
  ## its length, or returns 0 when `src` ends first; `MaxHeaderSize` bytes
  ## are always enough. `info` is `FrameInfo()` when no header is read (on
  ## a 0 result or an error).
  ##
  ## A skippable frame gives kind fkSkippable and its `skippableSize`
  ## (return value 8); its content is not skipped. A legacy frame gives kind
  ## fkLegacy and independent blocks (return value 4). Raises ekChecksum
  ## for a header checksum mismatch and ekMalformed otherwise.
  info = FrameInfo()
  if src.len < 4:
    return 0
  let magic = readLE32(src, 0)
  if magic == FrameMagic:
    # (parseHeader sets `info` only for a valid header.)
    result = parseHeader(src, 0, info)
  elif (magic and SkippableMagicMask) == SkippableMagicBase:
    if src.len < 8:
      return 0
    info = FrameInfo(kind: fkSkippable, skippableSize: readLE32(src, 4))
    result = 8
  elif magic == LegacyMagic:
    info = LegacyFrameInfo
    result = 4
  else:
    raiseLz4(ekMalformed, "unknown frame magic number")

# Legacy frame compression

func legacyBlockLevel(level: int): int =
  ## The block level of `compressBlock` for a legacy frame level: the fast
  ## compressor below 3 with acceleration `-level` (not LZ4F's `-level + 1`),
  ## and HC from 3 on.
  if level < 0:
    level + 1
  elif level < 3:
    0
  else:
    level

proc legacyFrame(
    src: openArray[byte], level: int, dst: var OutputBuffer
) {.raises: [Lz4Error].} =
  ## Writes the legacy frame of `src` to the empty `dst`.
  var output: typeof(dst)
  # Room for each block's size and compressBound.
  checkOneBuffer(src.len)
  let nblocks = (src.len + LegacyBlockSize - 1) div LegacyBlockSize
  output.setLenNoInit(4 + nblocks * (4 + 16) + src.len + src.len div 255)
  writeLE32(output.asBytes(0, output.high), 0, LegacyMagic)
  var op = 4
  var c: BlockCompressor
  let blockLevel = legacyBlockLevel(level)
  var pos = 0
  while pos < src.len:
    let blockLen = min(LegacyBlockSize, src.len - pos)
    let n = c.compressBlockInto(
      src.toOpenArray(pos, pos + blockLen - 1),
      output.asBytes(op + 4, output.high),
      blockLevel,
    )
    # compressBound is always enough: legacy blocks are never stored.
    writeLE32(output.asBytes(0, output.high), op, uint32(n))
    op += 4 + n
    pos += blockLen
  output.setLenNoInit(op)
  output.trimCapacity()
  dst = move output

proc compressLegacyFrame*(
    src: openArray[byte], level = 0
): seq[byte] {.raises: [Lz4Error].} =
  ## Compresses `src` into one legacy frame (the format of `lz4 -l`): the
  ## legacy magic, then independent blocks of 8 MiB (the last one shorter),
  ## each preceded by its compressed size. There are no checksums, content
  ## size or end mark, and blocks are never stored uncompressed.
  ##
  ## `level` is read as `lz4 -l` reads it: negative levels use acceleration
  ## `-level`, 0 to 2 the default fast compressor, 3 to 12 HC.
  legacyFrame(src, level, result)

proc compressLegacy*(s: string, level = 0): string {.raises: [Lz4Error].} =
  ## Compresses `s` into one legacy frame (see `compressLegacyFrame`).
  legacyFrame(s.toOpenArrayByte(0, s.high), level, result)
