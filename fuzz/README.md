# fuzz/

Fuzzing harnesses.

| File | What it does | How to run |
|---|---|---|
| `fuzz_mutate.nim` | Mutation fuzzer without dependencies: generates valid blocks and frame streams, mutates them and checks that decoding either succeeds or raises `Lz4Error`, that `decompressBlock` and `decompressBlockInto` agree, that `FrameDecoder` agrees with `decompressFrame`, and that the safe and fast versions agree; also checks compression round trips with destinations of various sizes, and that one `FrameEncoder`, reused from frame to frame, writes the frames of new ones | `nimble fuzz` (runtime checks on), `nimble fuzzAsan` (`-d:danger` + ASan + UBSan) |
| `lf_block.nim` | libFuzzer: block decoder (bytes 0-1: output capacity, rest: block) | `nimble fuzzLibFuzzer`, then `fuzz/lf_block -max_total_time=60 corpus/` |
| `lf_diff_block.nim` | libFuzzer: block decoder against liblz4 (same input layout as `lf_block`) | as above |
| `lf_compress.nim` | libFuzzer: block compressor (bytes 0-11: end, capacity and level of four pieces; rest: data) | as above |
| `lf_frame.nim` | libFuzzer: frame decoder (the input is a stream of frames; also decoded with a dictionary) | as above |
| `lf_diff_frame.nim` | libFuzzer: frame decoder against `LZ4F_decompress` (one direction: what liblz4 accepts, we accept with the same output) | as above |
| `lf_stream.nim` | libFuzzer: `FrameDecoder` fed in pieces against `decompressFrame` (byte 0: piece size) | as above |
| `lf_diff_safe_fast.nim` | libFuzzer: the safe and fast decoders and compressors against each other (bytes 0-1: capacity, byte 2: prefix length) | as above |

The ASan / UBSan builds use `-d:danger -d:useMalloc` with clang, so the
library runs without Nim's runtime checks and every seq is a separate
`malloc` block. The harnesses copy inputs into buffers of their exact size
so that an access one byte past the end is reported.

`lf_diff_*.nim` targets compare against liblz4 (through `tests/clz4.nim`) and
link with `-llz4` unless `CLZ4_LINK` / `-d:clz4Link=...` says otherwise.
