## libFuzzer target: differential test of the block decoder against
## liblz4's LZ4_decompress_safe. Only one direction is checked: when
## liblz4 succeeds, we must succeed with the same output, except for
## offset 0, which liblz4 accepts and we reject.
##
## The first two input bytes choose the output capacity; the rest is the
## block. The output buffer is pre-filled with input-derived bytes so that
## a read of unwritten output cannot match by luck.

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
  if len < 2:
    return 0
  let cap = int(data[0]) or (int(data[1]) shl 8)
  let src = exactCopy(data.toOpenArray(2, int(len) - 1))
  let (ok, expected) = libDecompress(src, cap)
  var dst = newSeq[byte](cap)
  for i in 0 ..< cap:
    dst[i] = byte((i * 131 + int(len)) and 0xFF)
  try:
    let n = decompressBlockInto(src, dst)
    if ok:
      doAssert n == expected.len and dst[0 ..< n] == expected,
        "output differs from liblz4"
  except Lz4Error as e:
    doAssert not ok or "offset 0" in e.msg,
      "liblz4 accepted a block we rejected: " & e.msg
