## libFuzzer target for the block compressor.
##
## The first 12 bytes hold three bytes per piece, for four pieces: where the
## piece ends (as a fraction of what is left), the capacity of its
## destination (as a fraction of compressBound; 255 means compressBound
## itself) and its level (fast and HC levels). One BlockCompressor compresses the pieces in turn,
## each into an exact-size destination, and every result must be 0 or decode
## back. Long pieces followed by short ones catch a hash table that keeps
## old positions.

import lz4
import fuzzutil

proc NimMain() {.importc.}

proc LLVMFuzzerInitialize(
    argc: ptr cint, argv: ptr ptr cstring
): cint {.exportc, cdecl.} =
  NimMain()

proc LLVMFuzzerTestOneInput(
    data: ptr UncheckedArray[byte], len: csize_t
): cint {.exportc, cdecl.} =
  const headerLen = 12
  let n = int(len)
  if n < headerLen:
    return 0
  var c: BlockCompressor
  var pos = headerLen
  for k in 0 ..< 4:
    let sizeByte = int(data[3 * k])
    let capByte = int(data[3 * k + 1])
    let levelByte = int(data[3 * k + 2])
    let pieceEnd =
      if k == 3:
        n
      else:
        pos + (n - pos) * sizeByte div 255
    let bound = compressBound(pieceEnd - pos)
    let level =
      case levelByte and 15
      of 0, 1, 2:
        0
      of 3:
        1
      of 4:
        -1
      of 5:
        -2
      of 6:
        -50
      of 7:
        low(int)
      of 8, 9:
        2
      of 10, 11:
        3
      of 12, 13:
        9
      of 14:
        10
      else:
        12
    checkCompress(
      c, data.toOpenArray(pos, pieceEnd - 1), bound * capByte div 255, level
    )
    pos = pieceEnd
