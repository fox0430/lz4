## Pure Nim implementation of the LZ4 block and frame formats.
##
## This module exports the public API: `lz4/types`, `lz4/blocks`,
## `lz4/frames` and `lz4/streaming`. `lz4/streamio` is imported on its own;
## the modules under `lz4/private/` are internal.
##
## Frames (`compressFrame`, `decompress`) are the format of the `lz4` tool.
## Blocks (`compressBlock`, ...) are the raw format, without length or
## checksum. Streaming (`FrameEncoder`, `FrameDecoder`) handles frames piece
## by piece, and an encoder can reuse its tables for later frames.
## Dictionaries (`lz4 -D`) can be passed as they are or prepared once.
##
## Compression levels are LZ4F's: negative values are faster, 0 and 1 use
## the fast compressor, 2 to 12 the high compression (HC) one.
##
## Every error is an `Lz4Error`. `maxOutputSize` bounds the output of the
## decompression procs, which is what makes them safe on untrusted input.
## The library is memory safe on any input, also with `-d:danger`;
## `-d:lz4Safe` selects the safe code paths.

runnableExamples:
  # Frames, with the string API.
  let text = "hello hello hello hello hello, LZ4!"
  let packed = compress(text)
  assert decompress(packed, maxOutputSize = 1 shl 20) == text

runnableExamples:
  # Frames of bytes, with options.
  var data = newSeq[byte](10_000)
  for i in 0 ..< data.len:
    data[i] = byte(i mod 7)
  let opts = FrameOptions(blockChecksum: true, writeContentSize: true, level: 9)
  let frame = compressFrame(data, opts)
  assert frame.len < data.len
  assert decompressFrame(frame, maxOutputSize = 1 shl 20) == data

runnableExamples:
  # Raw blocks: keep the decompressed length yourself.
  let data = @[1'u8, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 5]
  let blk = compressBlock(data)
  assert decompressBlock(blk, maxOutputSize = data.len) == data
  # Into a buffer of your own; compressBlockInto returns 0 when it is too
  # small.
  var buf = newSeq[byte](compressBound(data.len))
  let n = compressBlockInto(data, buf)
  var back = newSeq[byte](data.len)
  assert decompressBlockInto(buf.toOpenArray(0, n - 1), back) == data.len

runnableExamples:
  # Streaming: feed returns what it consumed; it stops after each frame
  # header and at each frame end.
  var enc = initFrameEncoder(FrameOptions(blockIndependent: false))
  var compressed: seq[byte]
  for piece in ["first piece, ", "second piece, ", "third piece"]:
    enc.write(piece, compressed)
  enc.finish(compressed)

  var dec = initFrameDecoder(maxOutputSize = 1 shl 20)
  var output: seq[byte]
  var pos = 0
  while pos < compressed.len:
    pos += dec.feed(compressed.toOpenArray(pos, compressed.high), output)
  dec.finish()
  assert output.len == "first piece, second piece, third piece".len

runnableExamples:
  # Dictionaries (like lz4 -D): the same dictionary on both sides.
  var dict = newSeq[byte](1000)
  for i in 0 ..< dict.len:
    dict[i] = byte(i * 7 mod 251)
  let msg = dict[100 ..< 600]
  let frame = compressFrame(msg, dict)
  assert decompressFrame(frame, dict, maxOutputSize = msg.len) == msg
  # Many blocks with one dictionary: prepare it once (initBlockDict), then
  # each block costs little more than without a dictionary.
  let prepared = initBlockDict(dict, level = 0)
  var c: BlockCompressor
  var buf = newSeq[byte](compressBound(msg.len))
  let n = c.compressBlockInto(msg, prepared, buf)
  assert decompressBlock(buf.toOpenArray(0, n - 1), dict, msg.len) == msg
  # Many frames: the same with initFrameDict, for frames at any level.
  let framesDict = initFrameDict(dict)
  var e: FrameEncoder
  for level in [0, 9]:
    let f = e.compressFrame(msg, framesDict, FrameOptions(level: level))
    assert f == compressFrame(msg, dict, FrameOptions(level: level))

runnableExamples:
  # Many frames: one encoder, which keeps its tables from frame to frame
  # (reset for streaming, or the one-shot procs that take it).
  var e: FrameEncoder
  for msg in ["one message", "another message"]:
    let f = e.compress(msg, FrameOptions(level: 9))
    assert decompress(f, maxOutputSize = 100) == msg
  var frame: string
  e.reset(FrameOptions(blockIndependent: false))
  e.write("a third message", frame)
  e.finish(frame)
  assert decompress(frame, maxOutputSize = 100) == "a third message"

import lz4/[types, blocks, frames, streaming]

export types, blocks, frames, streaming
