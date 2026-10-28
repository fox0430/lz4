## The std/streams adapters.

import std/[streams, unittest]
import lz4, lz4/streamio
from lz4/private/common import readLE32
import datagen, errorcheck

suite "std/streams adapters":
  test "round trip through string streams":
    for data in [newSeq[byte](), textLike(100), mixed(1_000_000, 211)]:
      for opts in [FrameOptions(), FrameOptions(blockIndependent: false, level: 9)]:
        let input = newStringStream(toString(data))
        let packed = newStringStream()
        compressStream(input, packed, opts, bufferSize = 7777)
        check decompress(packed.data, high(int)) == toString(data)
        packed.setPosition(0)
        let output = newStringStream()
        decompressStream(packed, output, high(int64), bufferSize = 1000)
        check output.data == toString(data)

  test "content size and dictionaries":
    let data = textLike(50_000, 212)
    let packed = newStringStream()
    compressStream(
      newStringStream(toString(data)),
      packed,
      FrameOptions(writeContentSize: true),
      data.len,
    )
    check decompress(packed.data, high(int)) == toString(data)
    let dict = textLike(30_000, 213)
    let withDict = newStringStream()
    compressStream(
      newStringStream(toString(data)),
      withDict,
      dict,
      FrameOptions(blockIndependent: false),
    )
    check decompressFrame(toBytes(withDict.data), dict, high(int)) == data
    withDict.setPosition(0)
    let output = newStringStream()
    decompressStream(withDict, output, dict, high(int64))
    check output.data == toString(data)

  test "an error keeps the blocks decoded before it, whatever the buffer size":
    # 64 KiB blocks with checksums; the 40th is corrupted.
    let data = mixed(3_000_000, 214)
    var f = compressFrame(data, FrameOptions(blockChecksum: true))
    var info: FrameInfo
    var p = readFrameInfo(f, info)
    for _ in 0 ..< 39:
      p += 4 + int(readLE32(f, p) and 0x7FFF_FFFF'u32) + 4
    f[p + 4] = f[p + 4] xor 1
    let good = toString(data[0 ..< 39 * 65536])
    for bufferSize in [1000, 65536, 1 shl 20, f.len]:
      let output = newStringStream()
      expectKind ekChecksum:
        decompressStream(
          newStringStream(toString(f)), output, high(int64), bufferSize = bufferSize
        )
      let same = output.data == good
      if not same:
        checkpoint "bufferSize " & $bufferSize & ": " & $output.data.len & " bytes"
      check same

  test "an output stream that fails does not hide a decoding error":
    proc failWrite(
        s: Stream, buffer: pointer, bufLen: int
    ) {.nimcall, raises: [IOError, OSError], tags: [WriteIOEffect], gcsafe.} =
      raise newException(IOError, "the output is full")

    # The second block is corrupted. The first one is written when the
    # error is raised, and that write fails.
    let data = mixed(300_000, 215)
    var f = compressFrame(data, FrameOptions(blockChecksum: true))
    var info: FrameInfo
    var p = readFrameInfo(f, info)
    p += 4 + int(readLE32(f, p) and 0x7FFF_FFFF'u32) + 4
    f[p + 4] = f[p + 4] xor 1
    expectKind ekChecksum:
      decompressStream(
        newStringStream(toString(f)),
        Stream(writeDataImpl: failWrite),
        high(int64),
        bufferSize = f.len,
      )

  test "a wrong content size leaves the start of the frame":
    # Found only as the input is read: the blocks before it are written.
    let data = mixed(300_000, 216)
    for size in [100_000, 400_000]:
      let output = newStringStream()
      expectKind ekInvalidArgument:
        compressStream(
          newStringStream(toString(data)),
          output,
          FrameOptions(writeContentSize: true),
          size,
        )
      check output.data.len > 0
      expectKind ekMalformed:
        discard decompress(output.data, high(int))

  test "errors":
    let bad = newStringStream("not lz4 data")
    expectKind ekMalformed:
      decompressStream(bad, newStringStream(), high(int64))
    let f = compress("hello hello hello hello")
    expectKind ekMalformed:
      decompressStream(
        newStringStream(f[0 ..< f.len - 2]), newStringStream(), high(int64)
      )
    expectKind ekLimitExceeded:
      decompressStream(newStringStream(f), newStringStream(), maxOutputSize = 3)
    expectKind ekInvalidArgument:
      compressStream(newStringStream("x"), newStringStream(), bufferSize = 0)
    expectKind ekInvalidArgument:
      compressStream(
        newStringStream("x"), newStringStream(), FrameOptions(writeContentSize: true)
      )
