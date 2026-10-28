## libFuzzer target: differential test of the frame decoder against
## LZ4F_decompress. One direction only: when liblz4 decodes a whole frame,
## decompressFrame must decode the bytes liblz4 consumed to
## the same content. Offset 0 (accepted by liblz4) is the only exception.
## Legacy frames, which LZ4F does not handle, never get that far.

import std/strutils
import lz4
import clz4, fuzzutil

proc NimMain() {.importc.}

proc LLVMFuzzerInitialize(
    argc: ptr cint, argv: ptr ptr cstring
): cint {.exportc, cdecl.} =
  NimMain()

proc LLVMFuzzerTestOneInput(
    data: ptr UncheckedArray[byte], len: csize_t
): cint {.exportc, cdecl.} =
  let src = exactCopy(data.toOpenArray(0, int(len) - 1))
  let (ok, consumed, expected) = libDecompressFrame(src, maxOutput = 1 shl 24)
  if not ok:
    return 0
  try:
    let d = decompressFrame(src.toOpenArray(0, consumed - 1), high(int))
    doAssert d == expected, "output differs from LZ4F_decompress"
  except Lz4Error as e:
    doAssert "offset 0" in e.msg,
      "LZ4F_decompress accepted a frame we rejected: " & e.msg
