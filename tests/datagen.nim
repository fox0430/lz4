## Deterministic test data shared by the tests, fuzzers and benchmarks.
##
## Everything is generated from a seed, so nothing large has to be stored in
## the repository. `corpusFiles` adds real text from the Nim standard
## library sources when they are available.

import std/[algorithm, compilesettings, os, strutils]

type Rng* = object
  state: uint64

proc initRng*(seed: uint64): Rng =
  Rng(state: seed)

proc next*(r: var Rng): uint64 =
  ## splitmix64
  r.state += 0x9E3779B97F4A7C15'u64
  var z = r.state
  z = (z xor (z shr 30)) * 0xBF58476D1CE4E5B9'u64
  z = (z xor (z shr 27)) * 0x94D049BB133111EB'u64
  z xor (z shr 31)

proc below*(r: var Rng, n: int): int =
  ## A value in 0 ..< n (n > 0).
  int(r.next() mod uint64(n))

proc randomBytes*(n: int, seed = 1'u64): seq[byte] =
  var r = initRng(seed)
  result = newSeq[byte](n)
  var i = 0
  while i < n:
    var v = r.next()
    for _ in 0 ..< 8:
      if i >= n:
        break
      result[i] = byte(v and 0xFF)
      v = v shr 8
      inc i

proc zeros*(n: int): seq[byte] =
  newSeq[byte](n)

proc repeating*(n, period: int, seed = 2'u64): seq[byte] =
  ## A random pattern of `period` bytes repeated up to `n` bytes.
  let pat = randomBytes(period, seed)
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = pat[i mod period]

const words = [
  "the", "of", "and", "to", "in", "is", "that", "for", "it", "as", "with", "was", "on",
  "be", "by", "this", "are", "from", "or", "have", "an", "which", "one", "you", "were",
  "her", "all", "she", "there", "would", "their", "will", "when", "who", "him", "been",
  "has", "more", "if", "no", "compression", "block", "frame", "literal", "match",
  "offset", "stream", "buffer", "decoder", "encoder", "checksum", "dictionary",
  "window", "nim", "proc", "result", "seq", "byte", "openArray", "var", "let", "const",
]

proc textLike*(n: int, seed = 3'u64): seq[byte] =
  ## English-looking text with a skewed word distribution and punctuation.
  var r = initRng(seed)
  result = newSeqOfCap[byte](n + 16)
  var sentence = 0
  while result.len < n:
    # The smaller of two uniform indices skews the choice towards the
    # common words at the front of the list.
    var word = words[min(r.below(words.len), r.below(words.len))]
    if sentence == 0:
      word[0] = word[0].toUpperAscii
    for c in word:
      result.add byte(c)
    inc sentence
    if sentence > 6 and r.below(8) == 0:
      result.add byte('.')
      if r.below(5) == 0:
        result.add byte('\n')
      else:
        result.add byte(' ')
      sentence = 0
    else:
      result.add byte(' ')
  result.setLen(n)

proc mixed*(n: int, seed = 4'u64): seq[byte] =
  ## Runs of text, random bytes, zeros and short repeats, so that a single
  ## buffer exercises literals, long matches and incompressible sections.
  var r = initRng(seed)
  result = newSeqOfCap[byte](n)
  while result.len < n:
    let len = 1 + r.below(5000)
    case r.below(4)
    of 0:
      result.add textLike(len, r.next())
    of 1:
      result.add randomBytes(len, r.next())
    of 2:
      result.add zeros(len)
    else:
      result.add repeating(len, 1 + r.below(12), r.next())
  result.setLen(n)

proc corpusFiles*(maxFiles = 40): seq[string] =
  ## Paths of real text files: the first `maxFiles` (by name) sources of
  ## the Nim standard library this file was compiled with.
  const pure = querySetting(libPath) / "pure"
  var libFiles: seq[string]
  for f in walkFiles(pure / "*.nim"):
    libFiles.add f
  libFiles.sort()
  for f in libFiles:
    if result.len >= maxFiles:
      break
    result.add f

proc toBytes*(s: string): seq[byte] =
  @(s.toOpenArrayByte(0, s.high))

proc toString*(b: openArray[byte]): string =
  result = newString(b.len)
  if b.len > 0:
    copyMem(result[0].addr, b[0].unsafeAddr, b.len)

proc readBytes*(path: string): seq[byte] =
  toBytes(readFile(path))

var standardCache: seq[(string, seq[byte])]

proc standardInputs*(): seq[(string, seq[byte])] =
  ## The inputs the round-trip tests run over (built once, then cached).
  if standardCache.len > 0:
    return standardCache
  var r: seq[(string, seq[byte])]
  r.add ("empty", newSeq[byte]())
  for n in 1 .. 32:
    r.add ("random" & $n, randomBytes(n, uint64(n)))
    r.add ("zeros" & $n, zeros(n))
  for n in [65535, 65536, 65537, 65546, 65547, 65548]:
    r.add ("text" & $n, textLike(n, uint64(n)))
  r.add ("zeros1M", zeros(1 shl 20))
  r.add ("random300K", randomBytes(300_000, 7))
  r.add ("repeat1", repeating(100_000, 1))
  r.add ("repeat3", repeating(100_000, 3))
  r.add ("repeat7", repeating(100_000, 7))
  r.add ("repeat9", repeating(100_000, 9))
  r.add ("text1M", textLike(1 shl 20))
  r.add ("mixed1M", mixed(1 shl 20))
  standardCache = r
  r
