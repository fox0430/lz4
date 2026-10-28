## libFuzzer target: the safe and the fast versions against each other.
## Bytes 0-1 give the output capacity, byte 2 the length of a prefix
## (dictionary) taken from the start of the rest, and
## the high bits of byte 0 how much of it is given as an external
## dictionary; the rest is decoded as a block by both decoders (which must
## agree on the status and the output), and compressed by both compressors
## (which must produce the same bytes).

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
  let n = int(len)
  if n < 3:
    return 0
  let cap = int(data[0]) or (int(data[1]) shl 8)
  let prefixLen = min(int(data[2]) * 16, n - 3)
  checkSafeFastDecode(
    data.toOpenArray(3 + prefixLen, n - 1),
    data.toOpenArray(3, 3 + prefixLen - 1),
    cap,
    uint64(n),
    prefixLen * int(data[0] shr 4) div 15,
  )
  let bound = compressBound(n - 3)
  checkSafeFastCompress(
    data.toOpenArray(3, n - 1),
    if (data[0] and 1) == 0:
      bound
    else:
      bound * int(data[1]) div 255,
    1 + int(data[2] and 3),
    prefixLen,
  )
