## Internal module, not part of the API: constants, little-endian helpers,
## output buffers and the compressors' byte readers and match counter,
## shared by the other modules. It exports `lz4/types` to them.

import std/[bitops, endians]
import ../types

export types

const
  MinMatch* = 4
  LastLiterals* = 5
  MfLimit* = 12
  MinLength* = MfLimit + 1
  MaxDistance* = 65535
  HashLog* = 12
  SkipTrigger* = 6
  MaxInputSize* = 0x7E000000 ## The format's input size limit
  AccelerationMax* = 65537 ## Largest supported acceleration
  WindowSize* = 65536 ## History a linked block can refer to
  RunMask* = 15
  MlMask* = 15

  FrameMagic* = 0x184D2204'u32
  SkippableMagicBase* = 0x184D2A50'u32
  SkippableMagicMask* = 0xFFFFFFF0'u32
  LegacyMagic* = 0x184C2102'u32
  LegacyBlockSize* = 8 shl 20

const useSafe* = defined(lz4Safe)
  ## Use the safe code paths (plain indexing) instead of the fast ones (raw
  ## pointers and wide copies). Both are always compiled and agree.

type Bytes* = ptr UncheckedArray[byte] ## Raw bytes for the fast code paths.

func dictTail*(dictLen: int): int {.inline.} =
  ## Where the usable part of a dictionary of `dictLen` bytes starts: only
  ## its last 64 KiB can be referred to.
  max(0, dictLen - WindowSize)

proc raiseLz4*(kind: Lz4ErrorKind, msg: string) {.noreturn, raises: [Lz4Error].} =
  raise (ref Lz4Error)(kind: kind, msg: msg)

proc checkOneBuffer*(srcLen: int) {.raises: [Lz4Error].} =
  ## Raises ekLimitExceeded when the output of `srcLen` input bytes may not
  ## fit in one buffer: the bounds of the frame procs, a little more than
  ## `srcLen`, are computed without overflow below this.
  if srcLen > high(int) div 2:
    raiseLz4(ekLimitExceeded, "the input is too large for one buffer")

# Byte-wise, endian-independent helpers. Callers must have checked the
# bounds; the indexing is a second line of defence that -d:danger removes.

func readLE16*(a: openArray[byte], i: int): uint16 {.inline.} =
  uint16(a[i]) or (uint16(a[i + 1]) shl 8)

func readLE32*(a: openArray[byte], i: int): uint32 {.inline.} =
  uint32(a[i]) or (uint32(a[i + 1]) shl 8) or (uint32(a[i + 2]) shl 16) or
    (uint32(a[i + 3]) shl 24)

func readLE64*(a: openArray[byte], i: int): uint64 {.inline.} =
  uint64(readLE32(a, i)) or (uint64(readLE32(a, i + 4)) shl 32)

proc writeLE16*(a: var openArray[byte], i: int, v: uint16) {.inline.} =
  a[i] = byte(v and 0xFF)
  a[i + 1] = byte(v shr 8)

proc writeLE32*(a: var openArray[byte], i: int, v: uint32) {.inline.} =
  a[i] = byte(v and 0xFF)
  a[i + 1] = byte((v shr 8) and 0xFF)
  a[i + 2] = byte((v shr 16) and 0xFF)
  a[i + 3] = byte(v shr 24)

proc writeLE64*(a: var openArray[byte], i: int, v: uint64) {.inline.} =
  writeLE32(a, i, uint32(v and 0xFFFF_FFFF'u64))
  writeLE32(a, i + 4, uint32(v shr 32))

# Output buffers: the streaming procs append to bytes or, for the string
# API, to a string. The one-shot procs fill a local buffer and move it to
# their result at the end: Nim frees a local string on an exception but not
# a string result.

type OutputBuffer* = seq[byte] | string

proc setLenNoInit*(s: var seq[byte], newLen: Natural) {.inline.} =
  ## `setLen` without zero-filling the bytes it adds, nor, with refc before
  ## Nim 2.2.8, those it removes.
  when compiles(s.setLenUninit(newLen)):
    s.setLenUninit(newLen)
  else:
    # refc before Nim 2.2.8 has no setLenUninit for seqs, and its setLen
    # zero-fills added bytes and the whole buffer when growing it. Grow with
    # a copy instead and write the length in the seq's header.
    if newLen > s.capacity:
      var t = newSeqUninit[byte](max(newLen, s.capacity + s.capacity div 2))
      if s.len > 0:
        copyMem(t[0].addr, s[0].addr, s.len)
      s = move t
    if s.capacity > 0:
      cast[ptr int](s)[] = newLen

proc setLenNoInit*(s: var string, newLen: Natural) =
  ## The same for strings, which Nim before 2.2.10 has no setLenUninit for.
  when defined(nimSeqsV2) and compiles(s.setLenUninit(newLen)):
    s.setLenUninit(newLen)
  else:
    if newLen > s.capacity:
      # setLen zero-fills when it grows the capacity: grow with a copy.
      var t = newStringUninit(max(newLen, s.capacity + s.capacity div 2))
      if s.len > 0:
        copyMem(t[0].addr, s[0].addr, s.len)
      t.setLen(newLen)
      s = move t
    else:
      s.setLen(newLen)

proc trimCapacity*(s: var OutputBuffer) =
  ## Moves a one-shot result to a buffer of its own size when more than a
  ## quarter of its buffer is unused, so that a result kept for long does not
  ## keep the rest.
  if s.len < s.capacity - s.capacity div 4:
    var t =
      when s is string:
        newStringUninit(s.len)
      else:
        newSeqUninit[byte](s.len)
    if s.len > 0:
      copyMem(t[0].addr, s[0].addr, s.len)
    s = move t

template asBytes*(b: OutputBuffer, first, last: int): untyped =
  ## `b[first .. last]` as an `openArray[byte]`, writable when `b` is.
  when b is string:
    b.toOpenArrayByte(first, last)
  else:
    b.toOpenArray(first, last)

proc addBytes*(s: var OutputBuffer, data: openArray[byte]) {.inline.} =
  let n = s.len
  s.setLenNoInit(n + data.len)
  if data.len > 0:
    copyMem(s[n].addr, data[0].unsafeAddr, data.len)

proc addLE32*(s: var OutputBuffer, v: uint32) {.inline.} =
  let n = s.len
  s.setLenNoInit(n + 4)
  writeLE32(s.asBytes(0, s.high), n, v)

template compilerGuard*(x: typed) =
  ## An empty asm that claims to change `x` (with gcc and clang), as xxHash's
  ## XXH_COMPILER_GUARD: it keeps gcc from vectorizing a loop around it.
  {.emit: ["\n#if defined(__GNUC__)\n__asm__(\"\" : \"+r\"(", x, "));\n#endif\n"].}

# Sequence writing, shared by the fast and the HC compressors: `wb(i, v)`
# writes byte `i` of the output, `dstAddr(i)` and `srcAddr(i)` give addresses,
# and `op` is the output position.

template writeLengthBytes*(wb, op: untyped, n0: int) =
  ## The extension bytes of a literal or match length: n0 div 255 bytes of
  ## 255, then n0 mod 255. The caller has checked that they fit.
  var n = n0
  while n >= 255:
    wb(op, 255)
    inc op
    n -= 255
    # Keeps gcc from vectorizing this rarely taken loop.
    compilerGuard(n)
  wb(op, byte(n))
  inc op

template writeLastLiterals*(
    wb, dstAddr, srcAddr, op: untyped, anchor, iend, olimit: int
): bool =
  ## Writes the input from `anchor` to `iend` as the last sequence of a
  ## block: a token and the literals. False when they do not fit before
  ## `olimit`; the check keeps -d:danger builds inside the output.
  let lastRun = iend - anchor
  if lastRun + 1 + (lastRun + 255 - RunMask) div 255 > olimit - op:
    false
  else:
    if lastRun >= RunMask:
      wb(op, byte(RunMask shl 4))
      inc op
      writeLengthBytes(wb, op, lastRun - RunMask)
    else:
      wb(op, byte(lastRun shl 4))
      inc op
    if lastRun > 0:
      copyMem(dstAddr(op), srcAddr(anchor), lastRun)
      op += lastRun
    true

# Unaligned little-endian loads for the fast code paths. The caller checks
# the bounds.

template loadLE16*(p: Bytes, i: int): uint16 =
  var v {.noinit.}: uint16
  littleEndian16(v.addr, p[i].addr)
  v

template loadLE32*(p: Bytes, i: int): uint32 =
  var v {.noinit.}: uint32
  littleEndian32(v.addr, p[i].addr)
  v

template loadLE64*(p: Bytes, i: int): uint64 =
  var v {.noinit.}: uint64
  littleEndian64(v.addr, p[i].addr)
  v

template storeLE16*(p: Bytes, i: int, v: uint16) =
  ## The unaligned little-endian store of the fast code paths.
  var x = v
  littleEndian16(p[i].addr, x.addr)

template bytesOf*(a: openArray[byte]): Bytes =
  ## Address of the first byte (nil when empty). Only dereferenced at
  ## positions checked to be inside `a`.
  (if a.len > 0: cast[Bytes](a[0].unsafeAddr) else: nil)

# Byte readers and the match counter, shared by the fast and the HC
# compressors, compiled in a safe and a fast version.

proc straddle(src, dict: openArray[byte], j, width: int): uint64 {.noinline.} =
  ## The `width` bytes at position j, which straddle the end of the
  ## dictionary (see readers), little-endian.
  for k in 0 ..< width:
    let p = j + k
    let v =
      if p >= dict.len:
        src[p - dict.len]
      else:
        dict[p]
    result = result or (uint64(v) shl (8 * k))

type Segments* = enum
  ## Where the bytes are (see readers).
  sgOne ## all in `src`; `dict` is not used
  sgTwo ## below dict.len in `dict`, then in `src` from dict.len on

template readers*(
    src, dict: openArray[byte],
    ext: static Segments,
    fast: static bool,
    absolute: static bool = false,
) {.dirty.} =
  ## Declares the byte readers of the safe or the fast version (users name
  ## them with `mixin`). With sgTwo, positions below `dict.len` are in
  ## `dict`; a read straddling its end goes byte by byte.
  ##
  ## With `absolute` (not with sgTwo), the fast version takes addresses
  ## instead of indexes: on recent x86 cores a load without an index
  ## register is a cycle faster. For 64-bit systems only.
  # Bound here: this template expands where another module instantiates the
  # compressors.
  bind sgTwo, straddle, Bytes, bytesOf, loadLE16, loadLE32, loadLE64
  bind readLE16, readLE32, readLE64
  when absolute and ext == sgTwo:
    {.error: "readers: absolute positions do not support sgTwo".}
  when fast and absolute:
    let org {.used.} = cast[int](bytesOf(src))
  else:
    const org {.used.} = 0
  when ext != sgTwo:
    const dl {.used.} = 0
  else:
    let dl {.used.} = dict.len
  when fast and absolute:
    template srcAddr(i: int): pointer {.used.} =
      cast[pointer](i)

    template sbS(i: int): byte {.used.} =
      cast[Bytes](i)[0]

    template rd16S(i: int): uint16 {.used.} =
      loadLE16(cast[Bytes](i), 0)

    template rd32S(i: int): uint32 {.used.} =
      loadLE32(cast[Bytes](i), 0)

    template rd64S(i: int): uint64 {.used.} =
      loadLE64(cast[Bytes](i), 0)

  elif fast:
    # `src` from position 0: with a dictionary, its address minus dl, only
    # ever indexed from dl on.
    let sp = cast[Bytes](cast[uint](bytesOf(src)) - uint(dl))
    template srcAddr(i: int): pointer {.used.} =
      sp[i].addr

    template sbS(i: int): byte {.used.} =
      sp[i]

    template rd16S(i: int): uint16 {.used.} =
      loadLE16(sp, i)

    template rd32S(i: int): uint32 {.used.} =
      loadLE32(sp, i)

    template rd64S(i: int): uint64 {.used.} =
      loadLE64(sp, i)

  else:
    template srcAddr(i: int): pointer {.used.} =
      src[i - dl].unsafeAddr

    template sbS(i: int): byte {.used.} =
      src[i - dl]

    template rd16S(i: int): uint16 {.used.} =
      readLE16(src, i - dl)

    template rd32S(i: int): uint32 {.used.} =
      readLE32(src, i - dl)

    template rd64S(i: int): uint64 {.used.} =
      readLE64(src, i - dl)

  # Reads of the input being compressed (ip and the literals before it),
  # which are never in the dictionary: no check.
  template isb(i: int): byte {.used.} =
    sbS(i)

  template ird16(i: int): uint16 {.used.} =
    rd16S(i)

  template ird32(i: int): uint32 {.used.} =
    rd32S(i)

  template ird64(i: int): uint64 {.used.} =
    rd64S(i)

  when ext != sgTwo:
    template sb(i: int): byte {.used.} =
      sbS(i)

    template rd16(i: int): uint16 {.used.} =
      rd16S(i)

    template rd32(i: int): uint32 {.used.} =
      rd32S(i)

    template rd64(i: int): uint64 {.used.} =
      rd64S(i)

  else:
    when fast:
      let xp = bytesOf(dict)
      template sbD(i: int): byte {.used.} =
        xp[i]

      template rd16D(i: int): uint16 {.used.} =
        loadLE16(xp, i)

      template rd32D(i: int): uint32 {.used.} =
        loadLE32(xp, i)

      template rd64D(i: int): uint64 {.used.} =
        loadLE64(xp, i)

    else:
      template sbD(i: int): byte {.used.} =
        dict[i]

      template rd16D(i: int): uint16 {.used.} =
        readLE16(dict, i)

      template rd32D(i: int): uint32 {.used.} =
        readLE32(dict, i)

      template rd64D(i: int): uint64 {.used.} =
        readLE64(dict, i)

    template sb(i: int): byte {.used.} =
      block:
        let j = i
        if j >= dl:
          sbS(j)
        else:
          sbD(j)

    template rdAny(i, width: int, S, D: untyped, T: typedesc): untyped =
      block:
        let j = i
        if j >= dl:
          S(j)
        elif j <= dl - width:
          D(j)
        else:
          T(straddle(src, dict, j, width))

    template rd16(i: int): uint16 {.used.} =
      rdAny(i, 2, rd16S, rd16D, uint16)

    template rd32(i: int): uint32 {.used.} =
      rdAny(i, 4, rd32S, rd32D, uint32)

    template rd64(i: int): uint64 {.used.} =
      rdAny(i, 8, rd64S, rd64D, uint64)

template countWith(m64, m32, m16, m8: untyped, pIn0, pMatch0, pInLimit: int): int =
  ## The number of equal bytes at pIn0 and pMatch0, reading the match with
  ## m64 ... m8 and the input with the readers in scope.
  var i = pIn0
  var m = pMatch0
  var n = -1
  # Little-endian loads: the lowest differing byte comes first. The first 8
  # bytes are compared before the loop, where most matches end.
  if i < pInLimit - 7:
    let diff = m64(m) xor ird64(i)
    if diff != 0:
      n = countTrailingZeroBits(diff) shr 3
    else:
      i += 8
      m += 8
      while i < pInLimit - 7:
        let diff = m64(m) xor ird64(i)
        if diff == 0:
          i += 8
          m += 8
        else:
          n = i - pIn0 + (countTrailingZeroBits(diff) shr 3)
          break
  if n < 0:
    if i < pInLimit - 3 and m32(m) == ird32(i):
      i += 4
      m += 4
    if i < pInLimit - 1 and m16(m) == ird16(i):
      i += 2
      m += 2
    if i < pInLimit and m8(m) == isb(i):
      inc i
    n = i - pIn0
  n

template countMatch*(pIn0, pMatch0, pInLimit: int, ext: static Segments): int =
  ## The number of equal bytes at pIn0 and pMatch0 (< pIn0), up to
  ## pInLimit, with the readers in scope. With sgTwo, a match is counted up
  ## to the end of the dictionary, then on from the start of `src`, so that
  ## no read straddles its end. (A template: a proc, even inlined, makes
  ## the fast compressor slower.)
  when ext == sgTwo:
    let pm = pMatch0
    if pm >= dl:
      countWith(rd64S, rd32S, rd16S, sbS, pIn0, pm, pInLimit)
    else:
      let lim = min(pInLimit, pIn0 + (dl - pm))
      var k = countWith(rd64D, rd32D, rd16D, sbD, pIn0, pm, lim)
      if pIn0 + k == lim and lim < pInLimit:
        k += countWith(rd64S, rd32S, rd16S, sbS, lim, dl, pInLimit)
      k
  else:
    countWith(rd64S, rd32S, rd16S, sbS, pIn0, pMatch0, pInLimit)
