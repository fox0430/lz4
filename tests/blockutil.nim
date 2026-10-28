## Helpers that build LZ4 blocks and frames by hand for the tests.

import lz4, lz4/private/xxhash32

proc seqBytes*(lits: openArray[byte], offset, matchLen: int, last = false): seq[byte] =
  ## One sequence: literals, then (unless `last`) a match.
  let litLen = lits.len
  var token = (if litLen >= 15: 15 else: litLen) shl 4
  var ext: seq[byte]
  if litLen >= 15:
    var r = litLen - 15
    while r >= 255:
      ext.add 255
      r -= 255
    ext.add byte(r)
  var mext: seq[byte]
  if not last:
    let m = matchLen - 4
    token = token or (if m >= 15: 15 else: m)
    if m >= 15:
      var r = m - 15
      while r >= 255:
        mext.add 255
        r -= 255
      mext.add byte(r)
  result.add byte(token)
  result.add ext
  result.add lits
  if not last:
    result.add byte(offset and 0xFF)
    result.add byte(offset shr 8)
    result.add mext

proc expand*(
    lits: openArray[byte], offset, matchLen: int, prefix: seq[byte]
): seq[byte] =
  ## Reference decoding of one sequence appended to `prefix`.
  result = prefix
  result.add lits
  let start = result.len - offset
  for i in 0 ..< matchLen:
    result.add result[start + i]

proc appendSequence*(
    data: var seq[byte], lits: openArray[byte], offset, matchLen: int
) =
  ## In-place variant of `expand`.
  data.add lits
  let start = data.len - offset
  for i in 0 ..< matchLen:
    data.add data[start + i]

proc le32*(v: uint32): seq[byte] =
  @[
    byte(v and 0xFF),
    byte((v shr 8) and 0xFF),
    byte((v shr 16) and 0xFF),
    byte(v shr 24),
  ]

proc frameHeader*(flg, bd: byte, contentSize = -1'i64, dictId = -1'i64): seq[byte] =
  ## A frame header with the given FLG and BD bytes, an optional content
  ## size and dictionary id, and a correct header checksum.
  result = @[0x04'u8, 0x22, 0x4D, 0x18, flg, bd]
  if contentSize >= 0:
    for i in 0 ..< 8:
      result.add byte((contentSize shr (8 * i)) and 0xFF)
  if dictId >= 0:
    for i in 0 ..< 4:
      result.add byte((dictId shr (8 * i)) and 0xFF)
  result.add byte((xxh32(result.toOpenArray(4, result.high)) shr 8) and 0xFF)

proc encodeFrame*(data, dict: openArray[byte], opts: FrameOptions): seq[byte] =
  ## The frame of `data` with the options as given, made by FrameEncoder
  ## (compressFrame changes the block size and mode of an input that fits
  ## in one block), with the dictionary `dict`.
  var e = initFrameEncoder(dict, opts, if opts.writeContentSize: data.len else: -1)
  e.write(data, result)
  e.finish(result)

proc encodeFrame*(data: openArray[byte], opts: FrameOptions): seq[byte] =
  ## Same without a dictionary.
  encodeFrame(data, [], opts)

proc allFrameOptions*(): seq[FrameOptions] =
  ## Every combination of the boolean frame options and block sizes.
  for bs in BlockSizeId:
    for indep in [true, false]:
      for bc in [false, true]:
        for cc in [false, true]:
          for ws in [false, true]:
            result.add FrameOptions(
              blockSize: bs,
              blockIndependent: indep,
              blockChecksum: bc,
              contentChecksum: cc,
              writeContentSize: ws,
            )
