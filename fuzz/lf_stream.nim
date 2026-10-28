## libFuzzer target: the streaming decoder against decompressFrame.
## Byte 0 picks the size of the pieces the input is fed in (1 to 256
## bytes); the rest is a stream of frames. Both decoders must give the
## same verdict, output and error kind.

import fuzzutil

proc NimMain() {.importc.}

proc LLVMFuzzerInitialize(
    argc: ptr cint, argv: ptr ptr cstring
): cint {.exportc, cdecl.} =
  NimMain()

proc LLVMFuzzerTestOneInput(
    data: ptr UncheckedArray[byte], len: csize_t
): cint {.exportc, cdecl.} =
  if len < 1:
    return 0
  let chunk = 1 + int(data[0])
  checkStreamMatchesOneShot(
    data.toOpenArray(1, int(len) - 1), [chunk, 1, chunk * 3], 1 shl 22
  )
