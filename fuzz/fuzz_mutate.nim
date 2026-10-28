## Mutation fuzzer without external dependencies.
##
##   nim c -r fuzz/fuzz_mutate.nim [iterations] [seed]
##
## Valid inputs are generated, mutated (bit flips, truncation, insertion...)
## and decoded, and generated data is compressed into destinations of
## various sizes and decoded back. Anything other than success or an
## Lz4Error fails: with
## runtime checks a Defect aborts the run, and the `fuzzAsan` nimble task
## builds this file with -d:danger, ASan and UBSan to catch what the
## explicit checks miss. Inputs and output buffers are allocated with their
## exact sizes so that ASan sees any access past their ends.

import std/[os, strutils]
import lz4
import datagen, fuzzutil

proc decodeBlock(input: openArray[byte], r: var Rng) =
  checkBlockDecoders(input, r.below(10_000))
  if r.below(4) == 0:
    let dict = randomBytes(r.below(70_000), r.next())
    checkBlockDecoders(input, r.below(10_000), dict)

proc compressSome(c: var BlockCompressor, r: var Rng) =
  ## Compression with small and exact destinations, through one compressor
  ## so that long inputs are followed by short ones, at fast and HC levels,
  ## with and without a dictionary.
  let level = [0, 0, 1, -1, -7, low(int), 2, 3, 9, 10, 12][r.below(11)]
  # HC is slow: smaller inputs for it.
  let maxLen =
    if level >= 2:
      20_000
    elif r.below(10) == 0:
      70_000
    else:
      3000
  let n = r.below(maxLen)
  let data =
    case r.below(4)
    of 0:
      randomBytes(n, r.next())
    of 1:
      textLike(n, r.next())
    of 2:
      repeating(n, 1 + r.below(20), r.next())
    else:
      mixed(n, r.next())
  let bound = compressBound(data.len)
  let cap =
    case r.below(3)
    of 0:
      bound
    of 1:
      r.below(bound + 1)
    else:
      max(0, data.len - 1)
  checkCompress(c, data, cap, level)
  if r.below(4) == 0:
    let dict = textLike(r.below(80_000), r.next())
    checkCompressDict(c, data, dict, cap, level)

proc frameSome(r: var Rng) =
  ## A random stream of frames: decoded as is (must round trip), then
  ## mutated, truncated and decoded with a random limit.
  let (stream, content) = randomStream(r, 150_000)
  doAssert decompressFrame(exactCopy(stream), high(int)) == content
  for _ in 0 ..< 4:
    checkFrameDecode(mutate(r, stream), r.below(content.len + 100))

proc streamSome(r: var Rng, e: var FrameEncoder) =
  ## Streaming against one-shot: the same verdict, output and error kind for
  ## random (and mutated) streams fed in random pieces, and an encoder fed
  ## in random pieces that matches compressFrame. `e` goes from one call to
  ## the next (reset), with the tables of the frames before.
  let (stream, content) = randomStream(r, 100_000)
  let m =
    if r.below(4) == 0:
      stream
    else:
      mutate(r, stream)
  var chunks: seq[int]
  for _ in 0 .. r.below(4):
    chunks.add 1 + r.below([3, 50, 5000, 100_000][r.below(4)])
  checkStreamMatchesOneShot(
    m,
    chunks,
    if r.below(2) == 0:
      high(int)
    else:
      r.below(content.len + 100),
  )
  var opts = randomFrameOptions(r)
  if r.below(4) == 0:
    opts.level = [2, 9, 12][r.below(3)]
  let data = randomContent(r, if opts.level >= 2: 60_000 else: 300_000)
  let flushes = r.below(3) == 0
  var expected: seq[byte]
  if not flushes:
    # compressFrame picks the block size and mode of an input that fits in
    # one block; the encoder gets the ones it picked. With flushes the
    # options stay as drawn, so that linked blocks (all of the HC inputs
    # fit in one block) are fuzzed too.
    expected = compressFrame(data, opts)
    doAssert e.compressFrame(data, opts) == expected, "reused encoder differs"
    opts = usedOptions(expected, opts)
  e.reset(opts, if opts.writeContentSize: data.len else: -1)
  var c: seq[byte]
  var p = 0
  while p < data.len:
    let k = min(data.len - p, 1 + r.below(100_000))
    e.write(data.toOpenArray(p, p + k - 1), c)
    if flushes and r.below(2) == 0:
      e.flush(c)
    p += k
  e.finish(c)
  if flushes:
    doAssert decompressFrame(c, high(int)) == data
  else:
    doAssert c == expected, "encoder differs from compressFrame"

type FuzzDict = tuple[bytes: seq[byte], prepared: FrameDict]

proc fuzzDicts(r: var Rng): seq[FuzzDict] =
  ## A few dictionaries of each kind of content, from a few bytes to more
  ## than 64 KiB, prepared once as callers do.
  for n in [5, 3000, 65536, 90_000]:
    let d = randomContent(r, n)
    result.add (d, initFrameDict(d))

proc dictFrameSome(r: var Rng, e: var FrameEncoder, dicts: seq[FuzzDict]) =
  ## Frames with a prepared dictionary, one-shot and streamed in random
  ## pieces (and flushes), through `e`, which goes on from the frames of
  ## streamSome: the bytes of the dictionary as it is.
  let d = dicts[r.below(dicts.len)]
  var opts = randomFrameOptions(r)
  if r.below(2) == 0:
    opts.level = [2, 3, 9, 10, 12][r.below(5)]
  var data = randomContent(r, if opts.level >= 2: 30_000 else: 200_000)
  if data.len > 100 and d.bytes.len > 0:
    # Pieces of the dictionary, which its state finds.
    for _ in 0 .. r.below(5):
      let at = r.below(data.len - 50)
      let start = r.below(d.bytes.len)
      let m = min(50, d.bytes.len - start)
      data[at ..< at + m] = d.bytes[start ..< start + m]
  let expected = compressFrame(data, d.bytes, opts)
  doAssert e.compressFrame(data, d.prepared, opts) == expected,
    "frame with a prepared dictionary differs"
  doAssert decompressFrame(expected, d.bytes, high(int)) == data
  let size = if opts.writeContentSize: data.len.int64 else: -1
  var f = initFrameEncoder(d.bytes, opts, size)
  e.reset(d.prepared, opts, size)
  var c, fc: seq[byte]
  var p = 0
  while p < data.len:
    let k = min(data.len - p, 1 + r.below([100, 5000, 100_000][r.below(3)]))
    e.write(data.toOpenArray(p, p + k - 1), c)
    f.write(data.toOpenArray(p, p + k - 1), fc)
    if r.below(4) == 0:
      e.flush(c)
      f.flush(fc)
    p += k
  e.finish(c)
  f.finish(fc)
  doAssert c == fc, "stream with a prepared dictionary differs"

proc safeFastSome(r: var Rng) =
  ## The safe and the fast versions must agree: the decoders on mutated
  ## blocks (with and without a prefix), the compressors byte for byte.
  let prefix =
    if r.below(3) == 0:
      randomBytes(r.below(70_000), r.next())
    else:
      newSeq[byte]()
  let (blk, data) = randomBlock(r, 3000, prefix)
  checkSafeFastDecode(
    mutate(r, blk), prefix, r.below(data.len + 64), r.next(), r.below(prefix.len + 1)
  )
  let src = randomContent(r, 100_000)
  let bound = compressBound(src.len)
  checkSafeFastCompress(
    src,
    if r.below(2) == 0:
      bound
    else:
      r.below(bound + 1),
    [1, 1, 3, 65537][r.below(4)],
    if src.len > 20 and r.below(2) == 0:
      r.below(src.len)
    else:
      0,
  )
  if r.below(4) == 0:
    let small = randomContent(r, 20_000)
    checkSafeFastHC(
      small,
      compressBound(small.len) - r.below(20),
      [2, 3, 9, 10, 12][r.below(5)],
      if r.below(2) == 0:
        r.below(small.len + 1)
      else:
        0,
    )
  if r.below(8) == 0:
    # A short block searching the dictionary's state, as in frames.
    let dictLen = 1 + r.below(70_000)
    var data = textLike(dictLen, r.next())
    data.add randomContent(r, 4096)
    checkSafeFastHCDictCtx(
      data,
      dictLen,
      compressBound(data.len - dictLen) - r.below(20),
      [2, 3, 9, 10, 12][r.below(5)],
    )

proc main() =
  let iterations =
    if paramCount() >= 1:
      parseInt(paramStr(1))
    else:
      200_000
  let seed =
    if paramCount() >= 2:
      uint64(parseBiggestUInt(paramStr(2)))
    else:
      1'u64
  var r = initRng(seed)
  # Compression draws from its own generator, so that adding it did not
  # change the decoder inputs a given seed produces.
  var rc = initRng(seed xor 0x5DEECE66D'u64)
  var rf = initRng(seed xor 0xB5297A4D'u64)
  var rs = initRng(seed xor 0x68E31DA4'u64)
  var rd = initRng(seed xor 0x1B873593'u64)
  var rp = initRng(seed xor 0x27D4EB2F'u64)
  let dicts = fuzzDicts(rp)
  var c: BlockCompressor
  var e: FrameEncoder
  for i in 0 ..< iterations:
    if i mod 4 == 0:
      compressSome(c, rc)
    if i mod 64 == 0:
      frameSome(rf)
    if i mod 64 == 32:
      streamSome(rs, e)
    if i mod 64 == 48:
      dictFrameSome(rp, e, dicts)
    if i mod 16 == 8:
      safeFastSome(rd)
    let (blk, data) = randomBlock(r, 5000)
    if i mod 8 == 0:
      doAssert decompressBlock(exactCopy(blk), data.len) == data
    decodeBlock(mutate(r, blk), r)
    decodeBlock(randomBytes(r.below(64), r.next()), r)
  echo "fuzz_mutate: ", iterations, " iterations (seed ", seed, "): ok"

main()
