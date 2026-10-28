## Adapters between `std/streams` and the streaming frame API:
## `compressStream(input, output, opts)` and
## `decompressStream(input, output, maxOutputSize)`, with overloads that
## take a dictionary. Import `lz4/streamio` explicitly; `lz4` does not
## import std/streams.
##
## Besides `Lz4Error`, the procs pass on the `IOError` and `OSError` of the
## streams.

import std/streams
import private/common
import streaming

proc readBuffer(bufferSize: int): seq[byte] {.raises: [Lz4Error].} =
  ## The buffer `input` is read into (every read overwrites it).
  if bufferSize <= 0:
    raiseLz4(ekInvalidArgument, "bufferSize must be positive")
  newSeqUninit[byte](bufferSize)

proc pump(
    e: var FrameEncoder, input, output: Stream, bufferSize: int
) {.raises: [Lz4Error, IOError, OSError].} =
  var buf = readBuffer(bufferSize)
  var compressed: seq[byte]
  while true:
    let n = input.readData(buf[0].addr, buf.len)
    if n <= 0:
      break
    e.write(buf.toOpenArray(0, n - 1), compressed)
    if compressed.len > 0:
      output.writeData(compressed[0].addr, compressed.len)
      compressed.setLenNoInit(0)
  e.finish(compressed)
  output.writeData(compressed[0].addr, compressed.len)
  output.flush()

proc compressStream*(
    input, output: Stream,
    opts = FrameOptions(),
    contentSize = -1'i64,
    bufferSize = 1 shl 16,
) {.raises: [Lz4Error, IOError, OSError].} =
  ## Reads `input` to its end and writes it to `output` as one LZ4 frame,
  ## then flushes `output`. With `opts.writeContentSize`, `contentSize` must
  ## be the length of what `input` holds (see `initFrameEncoder`).
  ##
  ## On an error, `output` keeps what was written before it (it is not
  ## flushed): the start of a frame without its end. With ekInvalidArgument,
  ## that is a content size mismatch found while reading.
  var e = initFrameEncoder(opts, contentSize)
  pump(e, input, output, bufferSize)

proc compressStream*(
    input, output: Stream,
    dict: openArray[byte],
    opts = FrameOptions(),
    contentSize = -1'i64,
    bufferSize = 1 shl 16,
) {.raises: [Lz4Error, IOError, OSError].} =
  ## Same as `compressStream(input, output, opts)`, with the dictionary
  ## `dict` (like `lz4 -D`).
  var e = initFrameEncoder(dict, opts, contentSize)
  pump(e, input, output, bufferSize)

proc drain(
    d: var FrameDecoder, input, output: Stream, bufferSize: int
) {.raises: [Lz4Error, IOError, OSError].} =
  var buf = readBuffer(bufferSize)
  var decoded: seq[byte]
  while true:
    let n = input.readData(buf[0].addr, buf.len)
    if n <= 0:
      break
    var pos = 0
    while pos < n:
      try:
        pos += d.feed(buf.toOpenArray(pos, n - 1), decoded)
      except Lz4Error as e:
        # Write what was decoded before the error.
        if decoded.len > 0:
          try:
            output.writeData(decoded[0].addr, decoded.len)
          except IOError, OSError:
            discard
        # Re-raise by name: a bare raise breaks the raises annotation.
        raise e
      if decoded.len > 0:
        output.writeData(decoded[0].addr, decoded.len)
        decoded.setLenNoInit(0)
  d.finish()
  output.flush()

proc decompressStream*(
    input, output: Stream, maxOutputSize: int64, bufferSize = 1 shl 16
) {.raises: [Lz4Error, IOError, OSError].} =
  ## Reads the LZ4 frames in `input` to its end and writes their content to
  ## `output`, then flushes it. `maxOutputSize` limits the total written
  ## (see `initFrameDecoder`; high(int64) for no limit). On an Lz4Error,
  ## `output` has received the content of the blocks decoded before it,
  ## whatever `bufferSize` is (it is not flushed). If writing that content
  ## fails, the Lz4Error is still what is raised.
  var d = initFrameDecoder(maxOutputSize)
  drain(d, input, output, bufferSize)

proc decompressStream*(
    input, output: Stream,
    dict: openArray[byte],
    maxOutputSize: int64,
    bufferSize = 1 shl 16,
) {.raises: [Lz4Error, IOError, OSError].} =
  ## Same as `decompressStream(input, output, maxOutputSize)` for frames
  ## compressed with the dictionary `dict`.
  var d = initFrameDecoder(dict, maxOutputSize)
  drain(d, input, output, bufferSize)
