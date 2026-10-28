## Inputs above 1 GiB (`nimble testHuge`, not part of `nimble test`: about
## 4 GiB of memory and a few minutes). Linked frames that long take paths
## the other tests cannot reach in reasonable time: the fast compressor
## moves the base of its table (RebaseLimit, 1 GiB), the HC compressors
## reload their history (LinkedLimit, 1 GiB), and the encoder compresses
## whole blocks where they are in its input, its positions moved there and
## back (FrameEncoder.write). Moving the positions must not change the
## output, so one write of the whole input must give the bytes of many
## small writes, whose positions stay small.

import std/unittest
import lz4
import datagen

const
  Size = (1 shl 30) + (96 shl 20) # 1.1 GiB
  Piece = 1 shl 20

proc hugeInput(): seq[byte] =
  ## Mixed content, built from a few pieces with a different patch in each
  ## copy (generating 1.1 GiB byte by byte would take long).
  var pieces: seq[seq[byte]]
  for i in 0 ..< 8:
    pieces.add mixed(Piece, uint64(100 + i))
  var r = initRng(7)
  result = newSeqUninit[byte](Size)
  var p = 0
  while p < Size:
    let n = min(Piece, Size - p)
    copyMem(result[p].addr, pieces[r.below(pieces.len)][0].addr, n)
    for k in 0 ..< 16:
      result[p + r.below(n)] = byte(r.next() and 0xFF)
    p += n

proc encodeInWrites(
    data: openArray[byte], opts: FrameOptions, writeLen: int
): seq[byte] =
  var e = initFrameEncoder(opts)
  var p = 0
  while p < data.len:
    let k = min(writeLen, data.len - p)
    e.write(data.toOpenArray(p, p + k - 1), result)
    p += k
  e.finish(result)

proc decodesTo(frame, data: openArray[byte]): bool =
  ## Streaming decoding, compared piece by piece (no second copy of 1.1 GiB).
  var d = initFrameDecoder(high(int64))
  var output: seq[byte]
  var pos = 0
  var at = 0
  while pos < frame.len:
    let k = min(16 shl 20, frame.len - pos)
    var used = 0
    while used < k:
      used += d.feed(frame.toOpenArray(pos + used, pos + k - 1), output)
    pos += k
    if output.len > data.len - at or output != data.toOpenArray(at, at + output.len - 1):
      return false
    at += output.len
    output.setLen(0)
  d.finish()
  at == data.len

let input = hugeInput()

suite "linked frames above 1 GiB":
  for level in [0, 2, 3]:
    test "level " & $level & ": one write gives the bytes of small writes":
      let opts = FrameOptions(level: level, blockIndependent: false)
      let whole = compressFrame(input, opts)
      # Writes of an odd size: blocks go through the buffer, and through
      # the input with the positions moved, in every arrangement.
      check whole == encodeInWrites(input, opts, 3 * Piece + 1)
      check decodesTo(whole, input)

  test "one-shot decompression of 1.1 GiB with a content size":
    let frame = compressFrame(
      input, FrameOptions(blockIndependent: false, writeContentSize: true)
    )
    check decompressFrame(frame, high(int)) == input
