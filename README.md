# lz4

A pure Nim implementation of LZ4: the block and frame formats, compression
and decompression, one-shot and streaming.

- No C library: no `importc` of liblz4, no `dynlib`.
- Compatible with the reference implementation: frames and blocks made by
  `lz4` / liblz4 decode here, and the other way round, as the tests check
  against liblz4 and the `lz4` tool (v1.10.0).
- Memory safe on untrusted input, even with `-d:danger`: the code checks
  every read and write itself instead of relying on Nim's runtime checks.
  The fuzzers (`nimble fuzzAsan`, libFuzzer targets in `fuzz/`) run with
  AddressSanitizer and the signed overflow and shift checks of
  UndefinedBehaviorSanitizer.
- Fast: on x86-64 (Silesia corpus, Ryzen 9 7950X, gcc 16, `-d:release`),
  as a share of the speed of liblz4 1.10.0 (the Arch Linux package):
  - block decompression: 80-88 %
  - frame decompression (default options, content checksum checked):
    113-144 % of `LZ4F_decompress` when both write into a buffer made
    beforehand, 109-144 % for `decompressFrame`, which grows its result
  - fast compression: 87-93 % as one block, 83-95 % in 64 KiB blocks
  - high compression (levels 9 and 12): 66-98 %
- Same output as liblz4, byte for byte in the tests on little-endian
  64-bit systems: the compressors are ports of lz4.c and lz4hc.c. With a
  dictionary, blocks match `LZ4_loadDict` (`LZ4_loadDictHC`) and the
  `_continue` functions, and frames match `lz4 -D` (LZ4F prepares the
  dictionary its own way, so a frame's blocks may differ from
  `compressBlock`'s). Some linked frames may differ, and decode the same:
  beyond 1 GiB at level 2, after `FrameEncoder.flush` with a dictionary at
  the fast levels, and against the `lz4` tool from 4 MiB on (see
  `FrameOptions.level`, `flush` and `compressFrame`).

Requires Nim 2.2.0 or later (C or C++ backend).

## Usage

```nim
import pkg/lz4

# Frames (the format of the `lz4` tool and of .lz4 files)
let compressed = compress("hello hello hello hello")
assert decompress(compressed, maxOutputSize = 1 shl 20) == "hello hello hello hello"

let data: seq[byte] = @[1'u8, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3]
let frame = compressFrame(data, FrameOptions(blockChecksum: true,
                                             writeContentSize: true))
assert decompressFrame(frame, maxOutputSize = 1 shl 20) == data

# Raw blocks (no header, no checksum; the caller keeps the length)
let blk = compressBlock(data)
assert decompressBlock(blk, maxOutputSize = data.len) == data

# High compression: levels 2 to 12 (like lz4 -2 ... -12)
let small = compressFrame(data, FrameOptions(level: 9))

# Dictionaries (like lz4 -D), for frames and for blocks
let dict = data
let withDict = compressFrame(data, dict)
assert decompressFrame(withDict, dict, maxOutputSize = data.len) == data
let blkWithDict = compressBlock(data, dict)
assert decompressBlock(blkWithDict, dict, maxOutputSize = data.len) == data
```

To compress many blocks or frames, reuse a `BlockCompressor`
(`compressBlockInto`) or a `FrameEncoder` (`compressFrame(e, src, opts)`,
`reset`), which keep their tables, and prepare a dictionary once with
`initBlockDict` or `initFrameDict`. The API documentation (`nimble docs`)
has examples.

Streaming, for data that does not fit in memory or arrives in pieces:

```nim
import pkg/lz4

var enc = initFrameEncoder(FrameOptions(blockIndependent: false))
var compressed: seq[byte]
for piece in ["first piece, ", "second piece, ", "third piece"]:
  enc.write(piece, compressed)
enc.finish(compressed)

var dec = initFrameDecoder(maxOutputSize = 1 shl 30)
var output = ""
var pos = 0
while pos < compressed.len:
  # feed returns how much it consumed; it stops after each frame header
  # and at the end of each frame.
  pos += dec.feed(compressed.toOpenArray(pos, compressed.high), output)
  # Write the output so far and empty it: the decoder keeps the history
  # that linked blocks need.
  stdout.write output
  output.setLen(0)
dec.finish()
```

With `std/streams`, `import lz4/streamio` gives `compressStream(input,
output, opts)` and `decompressStream(input, output, maxOutputSize)` (and
overloads that take a dictionary).

### Untrusted input

The decompression procs take a `maxOutputSize`, the most they may produce,
which bounds memory use: LZ4 data can expand about 255 times (1 GiB from
about 4 MiB). Pass the most you expect, or `high(int)` (`high(int64)`
where the limit is an int64) for no limit.

### Errors

The API raises `Lz4Error`, whose `kind` tells what went wrong (see
`Lz4ErrorKind`); the `lz4/streamio` adapters also pass on `IOError` and
`OSError`.

## What is supported

| | compression | decompression |
|---|---|---|
| block format | yes | yes |
| frame format, all flags (dictionary id included) | yes | yes |
| linked blocks | yes | yes |
| content size, block and content checksums | yes | yes (checked) |
| skippable frames, concatenated frames | - | yes |
| legacy frames (`lz4 -l`) | yes (`compressLegacyFrame`) | yes |
| dictionaries (`lz4 -D`) | yes | yes |
| fast levels (`lz4 -1`, `--fast=N`) | yes | - |
| high compression (`lz4 -2` to `-12`) | yes | - |

Compression levels follow LZ4F's `compressionLevel`: negative values trade
ratio for speed (acceleration `-level + 1`), 0 and 1 are the default
(fast) compressor, 2 to 12 the high compression (HC) one, slower and
smaller as the level grows (13 and more are 12).

## License

MIT (`LICENSE`). The compressors (`src/lz4/private/blockimpl.nim`,
`src/lz4/private/hc.nim`) are ports of lz4.c and lz4hc.c and keep their
BSD 2-Clause License (`LICENSE-lz4`): a program that ships them in binary
form must reproduce that notice in its documentation or other materials.
