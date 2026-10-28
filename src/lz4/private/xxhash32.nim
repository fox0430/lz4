## Internal module, not part of the API.
##
## XXH32, written from the xxHash specification. Used for the frame header,
## block and content checksums.

import std/bitops
import common

const
  Prime1 = 2654435761'u32
  Prime2 = 2246822519'u32
  Prime3 = 3266489917'u32
  Prime4 = 668265263'u32
  Prime5 = 374761393'u32

type Xxh32State* = object
  ## Streaming state: four accumulators, the pending stripe and the total
  ## length.
  v1, v2, v3, v4: uint32
  seed: uint32
  buf: array[16, byte]
  bufLen: int
  total: uint64

func round(acc, input: uint32): uint32 {.inline.} =
  result = rotateLeftBits(acc + input * Prime2, 13) * Prime1
  # Keeps gcc from vectorizing the four lanes: the vector multiply is slow
  # on many CPUs, and without SSE4.1 gcc builds it from shifts and adds.
  compilerGuard(result)

func finalize(h: uint32, tail: openArray[byte]): uint32 =
  ## Mixes in the last 0..15 bytes and avalanches.
  var h = h
  var i = 0
  while i + 4 <= tail.len:
    h = rotateLeftBits(h + readLE32(tail, i) * Prime3, 17) * Prime4
    i += 4
  while i < tail.len:
    h = rotateLeftBits(h + uint32(tail[i]) * Prime5, 11) * Prime1
    inc i
  h = h xor (h shr 15)
  h = h * Prime2
  h = h xor (h shr 13)
  h = h * Prime3
  h xor (h shr 16)

func initXxh32*(seed = 0'u32): Xxh32State =
  Xxh32State(
    v1: seed + Prime1 + Prime2,
    v2: seed + Prime2,
    v3: seed,
    v4: seed - Prime1,
    seed: seed,
  )

proc stripesImpl(
    s: var Xxh32State, data: openArray[byte], first, last: int, fast: static bool
) =
  ## Consumes the 16-byte stripes in `data[first ..< last]`.
  var v1 = s.v1
  var v2 = s.v2
  var v3 = s.v3
  var v4 = s.v4
  var i = first
  when fast:
    let p = bytesOf(data)
    template lane(k: int): uint32 =
      loadLE32(p, k)

  else:
    template lane(k: int): uint32 =
      readLE32(data, k)

  while last - i >= 16:
    v1 = round(v1, lane(i))
    v2 = round(v2, lane(i + 4))
    v3 = round(v3, lane(i + 8))
    v4 = round(v4, lane(i + 12))
    i += 16
  s.v1 = v1
  s.v2 = v2
  s.v3 = v3
  s.v4 = v4

proc stripes(s: var Xxh32State, data: openArray[byte], first, last: int) {.inline.} =
  stripesImpl(s, data, first, last, not useSafe)

proc update*(s: var Xxh32State, data: openArray[byte]) =
  s.total += uint64(data.len)
  var pos = 0
  if s.bufLen > 0:
    let take = min(16 - s.bufLen, data.len)
    for k in 0 ..< take:
      s.buf[s.bufLen + k] = data[k]
    s.bufLen += take
    pos = take
    if s.bufLen < 16:
      return
    s.stripes(s.buf, 0, 16)
    s.bufLen = 0
  let full = pos + (data.len - pos) div 16 * 16
  s.stripes(data, pos, full)
  for k in full ..< data.len:
    s.buf[k - full] = data[k]
  s.bufLen = data.len - full

func merge(s: Xxh32State, total: uint64): uint32 {.inline.} =
  ## The accumulators merged (the seed alone below 16 bytes), plus the
  ## length: the hash before `finalize`.
  result =
    if total >= 16:
      rotateLeftBits(s.v1, 1) + rotateLeftBits(s.v2, 7) + rotateLeftBits(s.v3, 12) +
        rotateLeftBits(s.v4, 18)
    else:
      s.seed + Prime5
  result += uint32(total and 0xFFFF_FFFF'u64)

func digest*(s: Xxh32State): uint32 =
  finalize(s.merge(s.total), s.buf.toOpenArray(0, s.bufLen - 1))

proc xxh32Impl(data: openArray[byte], seed: uint32, fast: static bool): uint32 =
  var s = initXxh32(seed)
  let full = data.len div 16 * 16
  s.stripesImpl(data, 0, full, fast)
  finalize(s.merge(uint64(data.len)), data.toOpenArray(full, data.len - 1))

proc xxh32Safe*(data: openArray[byte], seed = 0'u32): uint32 =
  xxh32Impl(data, seed, false)

proc xxh32Fast*(data: openArray[byte], seed = 0'u32): uint32 =
  xxh32Impl(data, seed, true)

proc xxh32*(data: openArray[byte], seed = 0'u32): uint32 =
  ## XXH32 of `data`.
  xxh32Impl(data, seed, not useSafe)
