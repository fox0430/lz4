## libFuzzer target for the frame decoder. The whole input is a stream of
## frames; it is decoded with a limit, and again with a dictionary.

import lz4
import fuzzutil

proc NimMain() {.importc.}

proc LLVMFuzzerInitialize(
    argc: ptr cint, argv: ptr ptr cstring
): cint {.exportc, cdecl.} =
  NimMain()

let dict = block:
  var d = newSeq[byte](1000)
  for i in 0 ..< d.len:
    d[i] = byte((i * 7) and 0xFF)
  d

proc LLVMFuzzerTestOneInput(
    data: ptr UncheckedArray[byte], len: csize_t
): cint {.exportc, cdecl.} =
  let src = exactCopy(data.toOpenArray(0, int(len) - 1))
  checkFrameDecode(src, 1 shl 22)
  try:
    discard decompressFrame(src, dict, 1 shl 22)
  except Lz4Error:
    discard
