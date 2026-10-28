## Benchmarks against liblz4.
##
##   nim c -r -d:danger bench/bench.nim [files...]
##
## Without arguments, it measures three inputs one by one: the corpus
## files it finds (the Nim standard library sources), concatenated, and
## 8 MB each of the generated text and mixed data from
## tests/datagen.nim. Files given on the command line (for example the
## Silesia corpus in tests/data/) are measured instead, one by one.
## Speeds are MB/s of uncompressed data, best of several runs; the ratio
## is compressed / original. Frame decompression writes into a buffer
## made beforehand on both sides (FrameDecoder and LZ4F_decompress);
## decompressFrame, which grows its result, is compared with the same
## liblz4 speed. Level 12 is skipped for inputs above 16 MiB (it is
## slow), and linked frames for inputs of 64 KiB or less (compressFrame
## makes a frame of one block independent).
##
## benchy is not used, so that the benchmark needs nothing beyond the
## test dependencies.

import std/[monotimes, os, strformat, strutils, times]
import lz4, lz4/private/xxhash32
from lz4/private/common import MaxInputSize
import clz4, datagen

const
  minTime = initDuration(milliseconds = 300)
  minRun = initDuration(microseconds = 100)

proc measure(bytes: int, body: proc()): float =
  ## MB/s of the fastest run of `body`, repeated for at least `minTime`. A
  ## run calls `body` as many times as it takes to last `minRun`, so that
  ## a small input is not timed below the clock's resolution (as 0 s).
  var reps = 1
  while true:
    let t0 = getMonoTime()
    for _ in 1 .. reps:
      body()
    if getMonoTime() - t0 >= minRun:
      break
    reps *= 2
  var best = high(float)
  let start = getMonoTime()
  var runs = 0
  while runs < 3 or getMonoTime() - start < minTime:
    let t0 = getMonoTime()
    for _ in 1 .. reps:
      body()
    let dt = (getMonoTime() - t0).inNanoseconds.float / 1e9 / float(reps)
    best = min(best, dt)
    inc runs
  float(bytes) / best / 1e6

iterator parts(len, size: int): Slice[int] =
  ## The ranges of `len` bytes cut into parts of `size` (the last one may
  ## be shorter).
  var p = 0
  while p < len:
    yield p ..< min(len, p + size)
    p += size

proc row(what: string, ours, lib: float) =
  let pct =
    if lib > 0:
      &"{100.0 * ours / lib:6.1f} %"
    else:
      "    -   "
  echo &"  {what:<34} {ours:9.1f} {lib:9.1f}   {pct}"

proc frameRows(data: seq[byte], label: string, opts: FrameOptions) =
  ## Frame compression and decompression of `data` with `opts`.
  var f, lf: seq[byte]
  let cs = measure(
    data.len,
    proc() =
      f = compressFrame(data, opts),
  )
  let lcs = measure(
    data.len,
    proc() =
      lf = libCompressFrame(data, opts.level, not opts.blockIndependent),
  )
  row(&"frame compress ({label})", cs, lcs)
  # Room for the content and one block: FrameDecoder makes room for a whole
  # block (64 KiB) before it decodes one.
  var o = newSeqOfCap[byte](data.len + 65536)
  let ds = measure(
    data.len,
    proc() =
      o.setLen(0)
      var d = initFrameDecoder(high(int64))
      var pos = 0
      while pos < f.len:
        pos += d.feed(f.toOpenArray(pos, f.high), o)
      d.finish()
      doAssert o.len == data.len
    ,
  )
  var lo = newSeqUninit[byte](data.len)
  let lds = measure(
    data.len,
    proc() =
      doAssert libDecompressFrameInto(f, lo) == data.len
    ,
  )
  row(&"frame decompress ({label})", ds, lds)
  let gs = measure(
    data.len,
    proc() =
      doAssert decompressFrame(f, high(int)).len == data.len
    ,
  )
  row(&"decompressFrame ({label})", gs, lds)

proc benchData(name: string, data: seq[byte]) =
  echo &"{name}: {data.len} bytes"
  if data.len == 0:
    echo "  (empty, skipped)"
    return
  echo &"  {\"\":<34} {\"ours\":>9} {\"liblz4\":>9}   ours/liblz4"
  # Whole input as one block (the 32-bit table, 5-byte hash).
  var c: seq[byte]
  var lc: seq[byte]
  let cs = measure(
    data.len,
    proc() =
      c = compressBlock(data),
  )
  let lcs = measure(
    data.len,
    proc() =
      lc = libCompress(data),
  )
  row("block compress (one block)", cs, lcs)
  var out1 = newSeq[byte](data.len)
  let ds = measure(
    data.len,
    proc() =
      doAssert decompressBlockInto(c, out1) == data.len
    ,
  )
  let lds = measure(
    data.len,
    proc() =
      let n = LZ4_decompress_safe(lc[0].addr, out1[0].addr, lc.len.cint, out1.len.cint)
      doAssert n == data.len
    ,
  )
  row("block decompress (one block)", ds, lds)
  echo &"  {\"ratio (one block)\":<34} {c.len / data.len:9.4f} {lc.len / data.len:9.4f}"
  # 64 KiB blocks (the 16-bit table), as in the default frame.
  var cparts, lparts: seq[seq[byte]]
  let cs64 = measure(
    data.len,
    proc() =
      cparts.setLen(0)
      for s in parts(data.len, 65536):
        cparts.add compressBlock(data.toOpenArray(s.a, s.b))
    ,
  )
  let lcs64 = measure(
    data.len,
    proc() =
      lparts.setLen(0)
      for s in parts(data.len, 65536):
        lparts.add libCompress(data.toOpenArray(s.a, s.b))
    ,
  )
  row("block compress (64 KiB blocks)", cs64, lcs64)
  var buf = newSeq[byte](65536)
  let ds64 = measure(
    data.len,
    proc() =
      var n = 0
      for p in cparts:
        n += decompressBlockInto(p, buf)
      doAssert n == data.len
    ,
  )
  let lds64 = measure(
    data.len,
    proc() =
      var n = 0
      for p in lparts:
        n += LZ4_decompress_safe(p[0].unsafeAddr, buf[0].addr, p.len.cint, buf.len.cint)
      doAssert n == data.len
    ,
  )
  row("block decompress (64 KiB blocks)", ds64, lds64)
  var csum, lsum = 0
  for p in cparts:
    csum += p.len
  for p in lparts:
    lsum += p.len
  echo &"  {\"ratio (64 KiB blocks)\":<34} {csum / data.len:9.4f} {lsum / data.len:9.4f}"
  # Frames, with the default options (content checksum on) and with linked
  # blocks.
  frameRows(data, "defaults", FrameOptions())
  if data.len > 65536:
    frameRows(data, "linked", FrameOptions(blockIndependent: false))
  let xs = measure(
    data.len,
    proc() =
      discard xxh32(data),
  )
  row("XXH32", xs, 0)
  # High compression, one block (decompression is as fast as above).
  for lv in [9, 12]:
    let level = lv # a copy the closures below can capture
    if level == 12 and data.len > 16 shl 20:
      continue
    var hcOurs, hcLib: seq[byte]
    let hs = measure(
      data.len,
      proc() =
        hcOurs = compressBlock(data, level),
    )
    let lhs = measure(
      data.len,
      proc() =
        hcLib = libCompressHC(data, level),
    )
    row(&"HC level {level} compress (one block)", hs, lhs)
    let label = "ratio (HC level " & $level & ")"
    echo &"  {label:<34} {hcOurs.len / data.len:9.4f} {hcLib.len / data.len:9.4f}"
  echo ""

proc main() =
  if paramCount() > 0:
    for i in 1 .. paramCount():
      let path = paramStr(i)
      let size = getFileSize(path)
      if size > MaxInputSize:
        # The block procs, ours and liblz4's, take no more.
        echo &"{path.extractFilename}: {size} bytes"
        echo &"  (above {MaxInputSize} bytes, skipped)"
        continue
      benchData(path.extractFilename, readBytes(path))
  else:
    var corpus: seq[byte]
    for f in corpusFiles(1000):
      corpus.add readBytes(f)
    benchData("corpus (Nim stdlib sources)", corpus)
    benchData("textLike 8 MB", textLike(8 shl 20))
    benchData("mixed 8 MB", mixed(8 shl 20))

main()
