## Cross-checks against the lz4 command line tool.

import std/[os, osproc, strutils, tempfiles, unittest]
import lz4, lz4/private/xxhash32
import blockutil, datagen, fuzzutil

let lz4Exe = findExe("lz4")
if lz4Exe.len == 0:
  quit "lz4 CLI not found on PATH", 1
let versionLine = execProcess(lz4Exe & " --version")
let versionOk = "v1.10.0" in versionLine
if not versionOk:
  if existsEnv("CI"):
    quit "lz4 1.10.0 required, found: " & versionLine, 1
  echo "lz4 CLI is not 1.10.0: the tests that depend on its exact ",
    "behaviour will be skipped"

template withExactVersion(body: untyped) =
  ## Runs `body` only with lz4 1.10.0, and marks the test skipped otherwise.
  if versionOk:
    body
  else:
    skip()

let tmp = createTempDir("nim-lz4-cli-", "")

proc writeBytes(path: string, data: openArray[byte]) =
  var f = open(path, fmWrite)
  defer:
    f.close()
  if data.len > 0:
    doAssert f.writeBuffer(data[0].unsafeAddr, data.len) == data.len

proc runLz4(
    args: string, input: openArray[byte], pipe = true
): tuple[ok: bool, output: seq[byte]] =
  ## Runs `lz4 <args>` on `input` and returns its standard output. With
  ## `pipe`, the input is piped to standard input. That is what the error
  ## comparisons need: the CLI skips truncated skippable frames without
  ## noticing in seekable input, which includes a `< file` redirection.
  ## Without it, the input is a file argument, which the CLI needs to know
  ## the input size (--content-size).
  let inPath = tmp / "in.bin"
  let outPath = tmp / "out.bin"
  writeBytes(inPath, input)
  let source =
    if pipe:
      "cat " & quoteShell(inPath) & " | " & quoteShell(lz4Exe) & " " & args
    else:
      quoteShell(lz4Exe) & " " & args & " " & quoteShell(inPath)
  let code = execShellCmd(
    source & " > " & quoteShell(outPath) & " 2> " & quoteShell(tmp / "err.txt")
  )
  (code == 0, readBytes(outPath))

proc cliCompress(data: openArray[byte], args: string): seq[byte] =
  let (ok, c) = runLz4("-c -q " & args, data, pipe = false)
  doAssert ok, "lz4 " & args & " failed"
  c

proc cliDecompress(data: openArray[byte]): tuple[ok: bool, output: seq[byte]] =
  runLz4("-d -c -q", data)

# Larger than 4 MiB, so that every block size gives several blocks: the CLI
# shrinks the block size and ignores -BD for single-block inputs.
let big = mixed(4_500_000, 77)
let small = textLike(70_000, 78)

suite "lz4 CLI -> decompressFrame":
  test "every M3 option (level 1)":
    for bs in 4 .. 7:
      for linked in [false, true]:
        for bx in [false, true]:
          for noCrc in [false, true]:
            for cs in [false, true]:
              var args = "-1 -B" & $bs
              if linked:
                args.add " -BD"
              if bx:
                args.add " -BX"
              if noCrc:
                args.add " --no-frame-crc"
              if cs:
                args.add " --content-size"
              let c = cliCompress(big, args)
              check decompressFrame(c, high(int)) == big
              var info: FrameInfo
              check readFrameInfo(c, info) > 0
              check ord(info.blockSize) + 4 == bs
              check info.blockIndependent == not linked
              check info.blockChecksum == bx
              check info.contentChecksum == not noCrc
              check info.hasContentSize == cs

  test "high compression levels":
    for level in ["-9", "-12"]:
      for extra in ["", " -BD", " -B4 -BX"]:
        check decompressFrame(cliCompress(small, level & extra), high(int)) == small
    check decompressFrame(cliCompress(big, "-9 -BD -B4"), high(int)) == big

  test "the CLI shrinks a one-block input and ignores -BD (version-dependent)":
    withExactVersion:
      let c = cliCompress(textLike(50_000), "-BD -B4")
      check c[4] == 0x64
      let d = cliCompress(textLike(100_000), "-B7")
      check d[5] == 0x50

  test "a one-block input: compressFrame gives the CLI's frame":
    # The CLI compresses a file shorter than a block with
    # LZ4F_compressFrame, which compressFrame follows: the same block size
    # and mode, then the same bytes.
    withExactVersion:
      for len in [0, 100, 50_000, 65535, 70_000, 262143]:
        let data = textLike(len, 79)
        for bs in 4 .. 7:
          if len >= 1 shl (8 + 2 * bs):
            continue
          for linked in [false, true]:
            for level in [1, 9]:
              var args = "-" & $level & " -B" & $bs
              if linked:
                args.add " -BD"
              let opts = FrameOptions(
                blockSize: BlockSizeId(bs - 4),
                blockIndependent: not linked,
                level: level,
              )
              check compressFrame(data, opts) == cliCompress(data, args)

  test "corpus files at the default settings":
    for f in corpusFiles():
      let data = readBytes(f)
      check decompressFrame(cliCompress(data, ""), high(int)) == data

suite "compressFrame -> lz4 CLI":
  test "every option combination and some levels":
    for opts in allFrameOptions():
      let (ok, d) = cliDecompress(compressFrame(big, opts))
      check ok
      check d == big
    for level in [-100, -1, 1, 9]:
      let (ok, d) = cliDecompress(compressFrame(small, FrameOptions(level: level)))
      check ok
      check d == small

  test "frame sizes within 1 % of the CLI at level 1":
    # More than one block for every block size, so that the CLI keeps the
    # block size and -BD.
    for (args, opts) in [
      ("-1 -B4", FrameOptions()),
      ("-1 -B4 -BD", FrameOptions(blockIndependent: false)),
      ("-1 -B7", FrameOptions(blockSize: bs4MiB)),
      ("-1 -B7 -BD", FrameOptions(blockSize: bs4MiB, blockIndependent: false)),
    ]:
      let theirs = cliCompress(big, args).len
      let ours = compressFrame(big, opts).len
      echo "    ", args, ": ours ", ours, " bytes, lz4 CLI ", theirs, " bytes"
      check float(ours) <= float(theirs) * 1.01

  test "empty input and the standard inputs":
    for (name, data) in standardInputs():
      let (ok, d) = cliDecompress(compressFrame(data))
      check ok
      check d == data

proc decodeStreaming(
    stream: openArray[byte], dict: seq[byte] = @[], useDict = false, chunk = 9999
): seq[byte] =
  let res = decodeStream(stream, [chunk], dict = dict, useDict = useDict)
  if not res.ok:
    checkpoint "decoding failed: " & $res.kind & ": " & res.msg
  check res.ok
  res.data

suite "lz4 CLI, M4 options":
  let dictData = textLike(80_000, 101)
  let dictPath = tmp / "dict.bin"
  writeBytes(dictPath, dictData)
  # Data that shares a lot with the dictionary.
  var related = dictData[30_000 ..< 70_000]
  related.add textLike(200_000, 102)

  test "legacy frames (-l)":
    for data in [small, big, newSeq[byte]()]:
      let c = cliCompress(data, "-l")
      check c[0 .. 3] == @[0x02'u8, 0x21, 0x4C, 0x18]
      check decompressFrame(c, high(int)) == data
      check decodeStreaming(c) == data
      check decodeStreaming(c, chunk = 777) == data

  test "dictionary (-D), independent and linked, every block size":
    for args in ["", "-BD", "-B4 -BD", "-B7", "-BX -BD -9"]:
      let c = cliCompress(related, "-D " & quoteShell(dictPath) & " " & args)
      check decompressFrame(c, dictData, high(int)) == related
      check decodeStreaming(c, dictData, useDict = true) == related
      check decodeStreaming(c, dictData, useDict = true, chunk = 1000) == related
      # lz4 -D writes no Dict-ID, so without the dictionary the frame is
      # simply malformed.
      try:
        discard decompressFrame(c, high(int))
        fail()
      except Lz4Error as e:
        check e.kind == ekMalformed

  test "a dictionary larger than 64 KiB uses its last 64 KiB":
    let c = cliCompress(related, "-D " & quoteShell(dictPath) & " -BD")
    check decompressFrame(c, dictData, high(int)) == related
    check decompressFrame(c, dictData[dictData.len - 65536 .. ^1], high(int)) == related

  test "concatenated frames with skippable frames in between":
    let skip = @[0x5F'u8, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]
    let legacy = cliCompress(small, "-l")
    let stream =
      legacy & cliCompress(small, "-BD") & skip &
      cliCompress(big, "-B5 -BX --content-size") & cliCompress(small, "")
    let expected = small & small & big & small
    check decompressFrame(stream, high(int)) == expected
    check decodeStreaming(stream) == expected
    check decodeStreaming(stream, chunk = 3) == expected
    # The CLI agrees.
    let (ok, d) = cliDecompress(stream)
    check ok
    check d == expected

  test "a legacy frame after a normal frame":
    # lz4 1.10.0 fails here (ERROR_frameType_unknown: it hands the bytes
    # after a normal frame to LZ4F, which does not know legacy frames). The
    # data is valid, so this implementation accepts it.
    let stream = cliCompress(small, "") & cliCompress(small, "-l")
    check decompressFrame(stream, high(int)) == small & small
    check decodeStreaming(stream) == small & small

  test "concatenated -D -BD frames: every frame starts from the dictionary":
    let one = cliCompress(related, "-D " & quoteShell(dictPath) & " -BD")
    let two = one & one
    check decompressFrame(two, dictData, high(int)) == related & related
    check decodeStreaming(two, dictData, useDict = true) == related & related

  test "Dict-ID inserted into an lz4 -D frame":
    # Set FLG bit 0, insert a Dict-ID and recompute the header checksum.
    let c = cliCompress(related, "-D " & quoteShell(dictPath))
    var f = c[0 .. 5]
    f[4] = f[4] or 1
    f.add [0x78'u8, 0x56, 0x34, 0x12]
    f.add byte((xxh32(f.toOpenArray(4, f.high)) shr 8) and 0xFF)
    f.add c[7 .. ^1]
    var info: FrameInfo
    check readFrameInfo(f, info) == 11
    check info.hasDictId and info.dictId == 0x12345678'u32
    check decompressFrame(f, dictData, high(int)) == related
    try:
      discard decompressFrame(f, high(int))
      fail()
    except Lz4Error as e:
      check e.kind == ekUnsupported
    # The CLI ignores the Dict-ID and needs -D as well.
    let (ok, d) = runLz4("-d -c -q -D " & quoteShell(dictPath), f)
    check ok
    check d == related

  test "error behaviour matches the CLI on standard input":
    withExactVersion:
      var truncatedSkip = @[0x50'u8, 0x2A, 0x4D, 0x18, 100, 0, 0, 0, 1, 2]
      let frame = cliCompress(small, "")
      for bad in [
        truncatedSkip,
        frame & truncatedSkip,
        frame & @[1'u8, 2],
        frame[0 ..< frame.len - 1],
      ]:
        let (ok, _) = cliDecompress(bad)
        check not ok
        try:
          discard decompressFrame(bad, high(int))
          fail()
        except Lz4Error as e:
          check e.kind == ekMalformed

  test "FrameEncoder output decodes with the CLI":
    var r = initRng(103)
    for opts in [
      FrameOptions(),
      FrameOptions(blockIndependent: false),
      FrameOptions(blockSize: bs4MiB, blockChecksum: true),
    ]:
      var e = initFrameEncoder(opts)
      var c: seq[byte]
      var p = 0
      while p < big.len:
        let k = min(big.len - p, 1 + r.below(300_000))
        e.write(big.toOpenArray(p, p + k - 1), c)
        if r.below(4) == 0:
          e.flush(c)
        p += k
      e.finish(c)
      let (ok, d) = cliDecompress(c)
      check ok
      check d == big

suite "lz4 CLI, high compression and dictionaries":
  let dictData = textLike(80_000, 191)
  let dictPath = tmp / "dict-hc.bin"
  writeBytes(dictPath, dictData)
  var related = dictData[10_000 ..< 75_000]
  related.add textLike(300_000, 192)

  test "our HC frames decode with the CLI; sizes within 1 % of lz4 -N":
    for (level, args) in [(2, "-2"), (3, "-3"), (9, "-9"), (12, "-12")]:
      for (opts, extra) in [
        (FrameOptions(), " -B4"), (FrameOptions(blockIndependent: false), " -B4 -BD")
      ]:
        var o = opts
        o.level = level
        let ours = compressFrame(big, o)
        let (ok, d) = cliDecompress(ours)
        check ok
        check d == big
        let theirs = cliCompress(big, args & extra).len
        echo "    ",
          args, extra, ": ours ", ours.len, " bytes, lz4 CLI ", theirs, " bytes"
        check float(ours.len) <= float(theirs) * 1.01

  test "our dictionary frames decode with lz4 -d -D":
    for level in [0, 2, 9]:
      for indep in [true, false]:
        let ours = compressFrame(
          related, dictData, FrameOptions(level: level, blockIndependent: indep)
        )
        let (ok, d) = runLz4("-d -c -q -D " & quoteShell(dictPath), ours)
        check ok
        check d == related

  test "dictionary frames equal lz4 -D at every level":
    # lz4 -D compresses an input under 4 MiB with
    # LZ4F_compressFrame_usingCDict, which compressFrame follows. Inputs of
    # one short block as well (LZ4F searches the dictionary's state for
    # those rather than copy it), and a dictionary shorter than 64 KiB.
    withExactVersion:
      let shortDict = dictData[^3000 .. ^1]
      let shortPath = tmp / "dict-short.bin"
      writeBytes(shortPath, shortDict)
      for (dict, path) in [(dictData, dictPath), (shortDict, shortPath)]:
        for data in [related, related[0 ..< 3000]]:
          for (level, args) in [
            (-3, "--fast=3"),
            (1, "-1"),
            (2, "-2"),
            (3, "-3"),
            (9, "-9"),
            (10, "-10"),
            (12, "-12"),
          ]:
            for (bs, indep, extra) in [
              (bs64KiB, true, " -B4"),
              (bs64KiB, false, " -B4 -BD"),
              (bs256KiB, false, " -B5 -BD"),
            ]:
              let opts =
                FrameOptions(level: level, blockSize: bs, blockIndependent: indep)
              let ours = compressFrame(data, dict, opts)
              let theirs = cliCompress(data, args & extra & " -D " & quoteShell(path))
              if ours != theirs:
                checkpoint args & extra & ", dictionary of " & $dict.len & " bytes, " &
                  $data.len & " bytes: ours " & $ours.len & ", lz4 CLI " & $theirs.len
              check ours == theirs

suite "lz4 CLI, legacy frame compression":
  test "our legacy frames decode with the CLI and equal lz4 -l":
    # Up to three 8 MiB blocks, fast and HC levels, read as lz4 -l reads
    # them (level 2 is the fast compressor, --fast=N acceleration N).
    let huge = mixed(17_000_000, 221)
    for (data, level, args) in [
      (small, 0, "-l"),
      (big, 0, "-l"),
      (huge, 0, "-l"),
      (big, -5, "-l --fast=5"),
      (big, 2, "-l -2"),
      (big, 3, "-l -3"),
      (huge, 9, "-l -9"),
      (small, 12, "-l -12"),
    ]:
      let ours = compressLegacyFrame(data, level)
      let (ok, d) = cliDecompress(ours)
      check ok
      check d == data
      let theirs = cliCompress(data, args)
      if ours != theirs:
        checkpoint args & ": ours " & $ours.len & " bytes, lz4 CLI " & $theirs.len
      check ours == theirs

removeDir(tmp)
