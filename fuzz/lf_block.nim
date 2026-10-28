## libFuzzer target for the block decoder. Build with the `fuzzLibFuzzer`
## nimble task, then run fuzz/lf_block.
##
## The first two input bytes choose the capacity of the output buffer; the
## rest is the block.

import fuzzutil

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
  checkBlockDecoders(data.toOpenArray(2, int(len) - 1), cap)
