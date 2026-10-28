## Internal module, not part of the API.
##
## High compression (levels 2 to 12): a port of lz4hc.c. Level 2 is lz4mid,
## levels 3 to 9 search hash chains, levels 10 to 12 use the optimal parser.
##
## The history (previous linked blocks or a dictionary) is placed in front of
## the data, in the same buffer or in one of its own, rather than in C's
## external dictionary segments. Positions are indexes that grow through a
## whole frame; `base` maps them to the current buffer, so a streaming
## encoder can move its buffer without touching the tables. Like the block
## compressor, the code comes in a safe and a fast version.
##
## The original license:
##
##   LZ4 HC - High Compression Mode of LZ4
##   Copyright (C) 2011-2020, Yann Collet.
##
##   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
##
##   Redistribution and use in source and binary forms, with or without
##   modification, are permitted provided that the following conditions are
##   met:
##
##       * Redistributions of source code must retain the above copyright
##   notice, this list of conditions and the following disclaimer.
##       * Redistributions in binary form must reproduce the above
##   copyright notice, this list of conditions and the following disclaimer
##   in the documentation and/or other materials provided with the
##   distribution.
##
##   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
##   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
##   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
##   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
##   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
##   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
##   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
##   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
##   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
##   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
##   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import std/bitops
import common

const
  HcLevelMin* = 2 ## Levels below this use the fast compressor
  HcLevelMax* = 12
  HcHashLog = 15
  HcHashSize = 1 shl HcHashLog
  HcChainSize = 1 shl 16
  OptimalMl = (MlMask - 1) + MinMatch
  OptNum = 1 shl 12
  TrailingLiterals = 3
  MidHashLog = HcHashLog - 1 ## lz4mid: two tables share the hash array
  MidTableSize = 1 shl MidHashLog
  ResetLimit = int(high(int32)) - MaxInputSize - 2 * WindowSize
    ## Indexes beyond this restart from scratch (hcStart), which keeps them
    ## in an int on 32-bit systems. Restarting does not change the output.
  LinkedLimit = 1 shl 30
    ## Linked history beyond this is reloaded. 1 GiB keeps indexes in 31
    ## bits, so 32-bit systems give the same output.

type
  HcStrategy = enum
    hsMid
    hsHashChain
    hsOptimal

  HcParams = object
    strategy: HcStrategy
    nbSearches: int
    targetLength: int

  OptCell = object
    price, off, mlen, litlen: int

  HcState* = object
    ## The match finder state (256 KiB; keep it on the heap). It cannot be
    ## assigned: hcCopyState copies it, all but `opt`.
    hashTable: array[HcHashSize, uint32]
    chainTable: array[HcChainSize, uint16]
    opt: seq[OptCell]
      ## the optimal parser's scratch space, made on first use and not
      ## zeroed: each match writes the cells it reads
    level: int ## compression level (see hcStart, hcLoadHistory)
    base: int ## index = position in the current buffer + base
    lowLimit: int ## index of the first byte that may be referred to
    dictLimit: int
      ## index where the prefix starts: below it is a dictionary searched as
      ## an external one
    nextToUpdate: int ## first index not yet inserted in the tables
    endIdx: int ## index after the last byte given so far
    dictId: int
      ## the dictionary whose state this is (setDictId) or holds unchanged
      ## (hcCopyState, hcRestore), or 0

  HcBox* = object
    ## An HcState of its own on the heap, made on first use (`[]`). A copy
    ## of a `carried` box (the history of linked blocks) gets a copy of its
    ## state; other states are started again on every use.
    p: ref HcState
    carried: bool

  HcMatch = object
    len, off, back: int
    left: int ## Attempts left by widerMatchIn

proc `=copy`*(dst: var HcState, src: HcState) {.error.}

const levelParams: array[HcLevelMax + 1, HcParams] = [
  # Levels 0 and 1 use the fast compressor; these entries are unused.
  HcParams(strategy: hsHashChain, nbSearches: 4, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 4, targetLength: 16),
  # lz4mid has no search depth or target length.
  HcParams(strategy: hsMid, nbSearches: 0, targetLength: 0),
  HcParams(strategy: hsHashChain, nbSearches: 4, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 8, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 16, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 32, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 64, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 128, targetLength: 16),
  HcParams(strategy: hsHashChain, nbSearches: 256, targetLength: 16),
  HcParams(strategy: hsOptimal, nbSearches: 96, targetLength: 64),
  HcParams(strategy: hsOptimal, nbSearches: 512, targetLength: 128),
  HcParams(strategy: hsOptimal, nbSearches: 16384, targetLength: OptNum),
]

func isHcLevel*(level: int): bool =
  ## Whether `level` uses the HC compressor.
  level >= HcLevelMin

func paramsOf(level: int): HcParams =
  levelParams[min(level, HcLevelMax)]

func analysesPatterns(params: HcParams): bool =
  ## Whether the hash chains look for repeated patterns: from level 9 on.
  params.nbSearches > 128

proc newHcState*(): ref HcState =
  ## A fresh state with zeroed tables.
  new(result)

func usesChains*(level: int): bool =
  ## lz4mid uses the hash table only; the other levels use the chain table.
  paramsOf(level).strategy != hsMid

func base*(s: HcState): int =
  ## The index of position 0 of the current buffer.
  s.base

proc hcCopyState*(dst: var HcState, src: HcState) =
  ## dst = src, without copying the chain table when the level does not use
  ## it (lz4mid).
  dst.hashTable = src.hashTable
  if usesChains(src.level):
    dst.chainTable = src.chainTable
  dst.level = src.level
  dst.base = src.base
  dst.lowLimit = src.lowLimit
  dst.dictLimit = src.dictLimit
  dst.nextToUpdate = src.nextToUpdate
  dst.endIdx = src.endIdx
  dst.dictId = src.dictId

proc setLevel*(s: var HcState, level: int) =
  ## Compresses the next blocks of `s` at `level`, with the tables made at
  ## the level of `s`: from level 3 on, every level makes the same chains.
  doAssert usesChains(level) == usesChains(s.level), "tables of another search"
  s.level = level

proc `=copy`*(dst: var HcBox, src: HcBox) =
  ## Gives `dst` a copy of a carried state of `src` (see HcBox).
  if dst.p == src.p:
    # The same box, or both empty.
    dst.carried = src.carried
    return
  if not src.carried:
    # Nothing to carry over: `dst` keeps its own state, dropping any history
    # so that only a carried box holds one.
    if dst.carried:
      dst.p = nil
    dst.carried = false
    return
  dst.carried = true
  if src.p == nil:
    dst.p = nil
    return
  if dst.p == nil:
    dst.p = newHcState()
  hcCopyState(dst.p[], src.p[])

proc newHcBox*(carried: bool): HcBox =
  ## A box holding a fresh state; `carried` when the state carries data from
  ## one use to the next.
  HcBox(p: newHcState(), carried: carried)

proc setCarried*(b: var HcBox, carried: bool) =
  ## Sets whether the state carries data from one use to the next: only a
  ## copy of a carried box gets a copy of it.
  b.carried = carried

func isEmpty*(b: HcBox): bool {.inline.} =
  b.p == nil

proc `[]`*(b: var HcBox): var HcState {.inline.} =
  ## The state, made first when the box is empty.
  if b.p == nil:
    b.p = newHcState()
  b.p[]

proc clearTables(s: var HcState) =
  zeroMem(s.hashTable.addr, sizeof(s.hashTable))
  if usesChains(s.level):
    zeroMem(s.chainTable.addr, sizeof(s.chainTable))
  s.endIdx = 0

proc hcStart*(s: var HcState, startPos, level: int) =
  ## Starts a new history at `startPos` at `level`. Indexes go on 64 KiB past
  ## the previous history, so its entries are out of reach; the tables are
  ## cleared only when indexes grow too large.
  s.level = level
  s.dictId = 0
  var start = s.endIdx
  if start > ResetLimit:
    s.clearTables()
    start = 0
  start += WindowSize
  s.nextToUpdate = start
  s.lowLimit = start
  s.dictLimit = start
  s.endIdx = start
  s.base = start - startPos

# The compressor, compiled in a safe and a fast version.

template hashOf(v: uint32): int =
  int((v * 2654435761'u32) shr (32 - HcHashLog))

template midHash4(v: uint32): int =
  ## The first half of the hash table.
  int((v * 2654435761'u32) shr (32 - MidHashLog))

template midHash8(v: uint64): int =
  ## The second half of the hash table (a 7-byte hash of 8 bytes).
  MidTableSize + int(((v shl 8) * 58295818150454627'u64) shr (64 - MidHashLog))

template chainAt(s: HcState, i: int): int =
  int(s.chainTable[i and 0xFFFF])

proc hcCount(
    src, dict: openArray[byte],
    pIn0, pMatch0, pInLimit: int,
    ext: static Segments,
    fast: static bool,
): int {.inline.} =
  ## The number of equal bytes at pIn0 and pMatch0 (< pIn0) (see
  ## countMatch).
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  countMatch(pIn0, pMatch0, pInLimit, ext)

proc hcInsert(
    s: var HcState,
    src, dict: openArray[byte],
    ip: int,
    ext: static Segments,
    fast: static bool,
) {.inline.} =
  ## Updates the chains up to `ip` (excluded).
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  let base = s.base
  let target = ip + base
  var idx = s.nextToUpdate
  while idx < target:
    let h = hashOf(rd32(idx - base))
    var delta = idx - int(s.hashTable[h])
    if delta > MaxDistance:
      delta = MaxDistance
    s.chainTable[idx and 0xFFFF] = uint16(delta)
    s.hashTable[h] = uint32(idx)
    inc idx
  s.nextToUpdate = target

proc countBack(
    src, dict: openArray[byte],
    ip, match, iMin, mMin: int,
    ext: static Segments,
    fast: static bool,
): int {.inline.} =
  ## Minus the number of equal bytes before `ip` and `match`.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  var back = 0
  let lim = max(iMin - ip, mMin - match)
  while back - lim > 3:
    let v = ird32(ip + back - 4) xor rd32(match + back - 4)
    if v != 0:
      # Little-endian loads: the highest differing byte is the closest.
      return back - (countLeadingZeroBits(v) shr 3)
    back -= 4
  while back > lim and isb(ip + back - 1) == sb(match + back - 1):
    dec back
  back

proc countPattern(
    src, dict: openArray[byte],
    ip0, iEnd: int,
    pattern32: uint32,
    ext: static Segments,
    fast: static bool,
): int {.inline.} =
  ## Counts a pattern of period 1, 2 or 4.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  let pattern = uint64(pattern32) or (uint64(pattern32) shl 32)
  var ip = ip0
  while ip < iEnd - 7:
    let diff = rd64(ip) xor pattern
    if diff == 0:
      ip += 8
      continue
    return ip - ip0 + (countTrailingZeroBits(diff) shr 3)
  var patternByte = pattern
  while ip < iEnd and sb(ip) == byte(patternByte and 0xFF):
    inc ip
    patternByte = patternByte shr 8
  ip - ip0

proc reverseCountPattern(
    src, dict: openArray[byte],
    ip0, iLow: int,
    pattern: uint32,
    ext: static Segments,
    fast: static bool,
): int {.inline.} =
  ## Counts the pattern backwards from `ip0`.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  var ip = ip0
  while ip >= iLow + 4:
    if rd32(ip - 4) != pattern:
      break
    ip -= 4
  var k = 3
  while ip > iLow and k >= 0:
    if sb(ip - 1) != byte((pattern shr (8 * k)) and 0xFF):
      break
    dec ip
    dec k
  ip0 - ip

func lowestMatchIdx(s: HcState, ipIndex: int): int {.inline.} =
  ## The lowest index a search at ipIndex may take a match from: 64 KiB back
  ## or the start of the history, and never below position 0 of the buffer.
  let withinStartDistance = s.lowLimit + (MaxDistance + 1) > ipIndex
  max(
    if withinStartDistance:
      s.lowLimit
    else:
      ipIndex - MaxDistance,
    s.base,
  )

func protectDictEnd(s: HcState, matchIndex: int): bool {.inline.} =
  ## False for the last 3 bytes of a dictionary searched as an external one,
  ## where no match may start.
  matchIndex >= s.dictLimit or matchIndex < s.dictLimit - 3

proc dictSearch(
    d: HcState,
    src, dict: openArray[byte],
    ip, iLowLimit, iHighLimit, nbAttempts0: int,
    best: var HcMatch,
    ext: static Segments,
    fast: static bool,
) {.noinline.} =
  ## Searches the dictionary's chains with the attempts left by
  ## widerMatchIn, for a match longer than `best`. As in an external
  ## dictionary, candidates are not filtered first, and a match ends with the
  ## dictionary.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  let dictStart = d.lowLimit - d.base
  let dictEnd = d.endIdx - d.base
  let lookBackLength = ip - iLowLimit
  let pattern = ird32(ip)
  var nbAttempts = nbAttempts0
  var dictIndex = int(d.hashTable[hashOf(pattern)])
  while nbAttempts > 0:
    let matchPos = dictIndex - d.base
    if matchPos < dictStart or ip - matchPos > MaxDistance:
      break
    dec nbAttempts
    if rd32(matchPos) == pattern:
      let back =
        if lookBackLength > 0:
          countBack(src, dict, ip, matchPos, iLowLimit, dictStart, ext, fast)
        else:
          0
      let limit = min(iHighLimit, ip + (dictEnd - matchPos))
      let matchLength =
        MinMatch +
        hcCount(src, dict, ip + MinMatch, matchPos + MinMatch, limit, ext, fast) - back
      if matchLength > best.len:
        best = HcMatch(len: matchLength, off: ip - matchPos, back: back)
    dictIndex -= d.chainAt(dictIndex)

template widerMatchIn(
    s: var HcState,
    src, dict: openArray[byte],
    ip0, iLowLimit0, iHighLimit0, longest0, maxNbAttempts: int,
    patternAnalysis0, chainSwap0: bool,
    ext: static Segments,
    fast: static bool,
): HcMatch =
  ## Inserts the positions up to `ip` and finds the longest match there,
  ## with the readers of `src` and `dict` in scope. (A template: as a proc,
  ## its setup made short blocks much slower.)
  block:
    let ip = ip0
    let iLowLimit = iLowLimit0
    let iHighLimit = iHighLimit0
    let patternAnalysis = patternAnalysis0
    let chainSwap = chainSwap0
    let base = s.base
    let ipIndex = ip + base
    let lowestMatchIndex = s.lowestMatchIdx(ipIndex)
    # Where backward extensions stop: the start of the prefix for a match in
    # it, the start of the history for one in a dictionary. Clamped, as a
    # streaming encoder may have moved them out of its buffer.
    let prefixPos = max(s.dictLimit - base, 0)
    let dictPos = max(s.lowLimit - base, 0)
    let lowestPos = lowestMatchIndex - base
    let lookBackLength = ip - iLowLimit
    var nbAttempts = maxNbAttempts
    var matchChainPos = 0
    let pattern = ird32(ip)
    var repeat = 0 # 0 untested, 1 not a repeat, 2 confirmed
    var srcPatternLength = 0
    var longest = longest0
    var offset = 0
    var sBack = 0
    s.hcInsert(src, dict, ip, ext, fast)
    var matchIndex = int(s.hashTable[hashOf(pattern)])
    template measure(matchPos, lowPos: int) =
      # The match at matchPos, extended back to lowPos at most.
      let back =
        if lookBackLength > 0:
          countBack(src, dict, ip, matchPos, iLowLimit, lowPos, ext, fast)
        else:
          0
      matchLength =
        MinMatch +
        hcCount(src, dict, ip + MinMatch, matchPos + MinMatch, iHighLimit, ext, fast)
      matchLength -= back
      if matchLength > longest:
        longest = matchLength
        offset = ipIndex - matchIndex
        sBack = back

    while matchIndex >= lowestMatchIndex and nbAttempts > 0:
      # (`measure`, defined above, sets it.)
      var matchLength {.inject.} = 0
      dec nbAttempts
      let matchPos = matchIndex - base
      if matchIndex >= s.dictLimit:
        # First a filter: a longer match also covers the bytes at `longest`.
        let at = matchPos - lookBackLength + longest - 1
        if at >= 0 and ird16(iLowLimit + longest - 1) == rd16(at) and
            rd32(matchPos) == pattern:
          measure(matchPos, prefixPos)
      elif matchIndex <= s.dictLimit - MinMatch and rd32(matchPos) == pattern:
        # In a dictionary: no filter, and never from its last 3 bytes.
        measure(matchPos, dictPos)

      if chainSwap and matchLength == longest:
        # Follow the chain of the position whose next occurrence is farthest.
        if matchIndex + longest <= ipIndex:
          const kTrigger = 4
          var distanceToNextMatch = 1
          let last = longest - MinMatch + 1
          var step = 1
          var accel = 1 shl kTrigger
          var p = 0
          while p < last:
            let candidateDist = s.chainAt(matchIndex + p)
            step = accel shr kTrigger
            inc accel
            if candidateDist > distanceToNextMatch:
              distanceToNextMatch = candidateDist
              matchChainPos = p
              accel = 1 shl kTrigger
            p += step
          if distanceToNextMatch > 1:
            if distanceToNextMatch > matchIndex:
              break
            matchIndex -= distanceToNextMatch
            continue

      let distNextMatch = s.chainAt(matchIndex)
      if patternAnalysis and distNextMatch == 1 and matchChainPos == 0:
        let matchCandidateIdx = matchIndex - 1
        # May be a repeated pattern.
        if repeat == 0:
          if (pattern and 0xFFFF) == (pattern shr 16) and
              (pattern and 0xFF) == (pattern shr 24):
            repeat = 2
            srcPatternLength =
              countPattern(src, dict, ip + 4, iHighLimit, pattern, ext, fast) + 4
          else:
            repeat = 1
        if repeat == 2 and matchCandidateIdx >= lowestMatchIndex and
            s.protectDictEnd(matchCandidateIdx):
          let matchPtr = matchCandidateIdx - base
          if rd32(matchPtr) == pattern:
            let forwardPatternLength =
              countPattern(src, dict, matchPtr + 4, iHighLimit, pattern, ext, fast) + 4
            var backLength =
              reverseCountPattern(src, dict, matchPtr, lowestPos, pattern, ext, fast)
            # Not below lowestMatchIndex.
            backLength =
              matchCandidateIdx - max(matchCandidateIdx - backLength, lowestMatchIndex)
            let currentSegmentLength = backLength + forwardPatternLength
            if currentSegmentLength >= srcPatternLength and
                forwardPatternLength <= srcPatternLength:
              # The whole pattern, maybe followed by more matching bytes.
              matchIndex = matchCandidateIdx + forwardPatternLength - srcPatternLength
              if not s.protectDictEnd(matchIndex):
                # (Not from the end of the dictionary: on from the prefix.)
                matchIndex = s.dictLimit
            elif not s.protectDictEnd(matchCandidateIdx - backLength):
              matchIndex = s.dictLimit
            else:
              # The farthest position in the current segment.
              matchIndex = matchCandidateIdx - backLength
              if lookBackLength == 0:
                let maxML = min(currentSegmentLength, srcPatternLength)
                if longest < maxML:
                  if ipIndex - matchIndex > MaxDistance:
                    break
                  longest = maxML
                  offset = ipIndex - matchIndex
                let distToNextPattern = s.chainAt(matchIndex)
                if distToNextPattern > matchIndex:
                  break
                matchIndex -= distToNextPattern
            continue

      matchIndex -= s.chainAt(matchIndex + matchChainPos)

    HcMatch(len: longest, off: offset, back: sBack, left: nbAttempts)

proc hcImpl(
    s: var HcState,
    src, dict: openArray[byte],
    start, iend: int,
    dst: var openArray[byte],
    ctx: ptr HcState,
    ext: static Segments,
    withCtx, fast: static bool,
): int =
  ## Compresses `src[start ..< iend]`, which must follow the history
  ## (index(start) = s.endIdx), into `dst`. Returns the size, or 0 when it
  ## does not fit. With `withCtx`, `ctx` is searched as in dictSearch.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  when fast:
    let dp = bytesOf(dst)
    template wb(i: int, v: byte) =
      dp[i] = v

    template ob(i: int): byte =
      dp[i]

    template dstAddr(i: int): pointer =
      dp[i].addr

  else:
    template wb(i: int, v: byte) =
      dst[i] = v

    template ob(i: int): byte =
      dst[i]

    template dstAddr(i: int): pointer =
      dst[i].addr

  let level = s.level
  let params = paramsOf(level)
  let olimit = dst.len
  var op = 0
  var anchor = start
  var ip = start
  s.endIdx += iend - start
  s.dictId = 0 # no longer a dictionary's state (see hcRestore)

  template encodeSequence(matchLength, offset: int): bool =
    # Returns false when the output is full.
    var ok = true
    block encode:
      var length = ip - anchor
      let token = op
      inc op
      if length div 255 + length + (2 + 1 + LastLiterals) > olimit - op:
        ok = false
        break encode
      if length >= RunMask:
        wb(token, byte(RunMask shl 4))
        writeLengthBytes(wb, op, length - RunMask)
      else:
        wb(token, byte(length shl 4))
      if length > 0:
        when fast:
          # 8 bytes at a time, into the room the check above reserves.
          var i = 0
          while i < length:
            copyMem(dp[op + i].addr, srcAddr(anchor + i), 8)
            i += 8
        else:
          copyMem(dst[op].addr, srcAddr(anchor), length)
        op += length
      wb(op, byte(offset and 0xFF))
      wb(op + 1, byte(offset shr 8))
      op += 2
      length = matchLength - MinMatch
      if length div 255 + (1 + LastLiterals) > olimit - op:
        ok = false
        break encode
      if length >= MlMask:
        wb(token, ob(token) + byte(MlMask))
        writeLengthBytes(wb, op, length - MlMask)
      else:
        wb(token, ob(token) + byte(length))
      ip += matchLength
      anchor = ip
    ok

  block compression:
    if iend - start < MinLength:
      break compression
    let mflimit = iend - MfLimit
    let matchlimit = iend - LastLiterals

    template withDict(m: HcMatch, p, iLowLimit: int): HcMatch =
      # withCtx: the dictionary's chains after the block's (C's dictCtx),
      # with the attempts left, while p is within 64 KiB of the history's
      # start.
      when withCtx:
        var md = m
        if md.left > 0 and s.lowLimit + (MaxDistance + 1) > p + s.base:
          ctx[].dictSearch(src, dict, p, iLowLimit, matchlimit, md.left, md, ext, fast)
        md
      else:
        m

    template wider(
        p, iLowLimit, longest, attempts: int, patternAnalysis, chainSwap: bool
    ): HcMatch =
      # widerMatchIn, then withDict.
      withDict(
        s.widerMatchIn(
          src, dict, p, iLowLimit, matchlimit, longest, attempts, patternAnalysis,
          chainSwap, ext, fast,
        ),
        p,
        iLowLimit,
      )

    if params.strategy == hsMid:
      # lz4mid: 4-byte and 8-byte hashes in the two halves of the table,
      # no chains.
      let base = s.base
      # Candidates come from the history, never below position 0. In a
      # dictionary before the prefix, a match ends with the dictionary and
      # is not extended backwards.
      let ownIdx = max(s.lowLimit, base)
      let prefixPos = max(s.dictLimit, base) - base
      let lowPos =
        when withCtx:
          max(ctx.lowLimit - ctx.base, 0)
        else:
          ownIdx - base
      # withCtx: the dictionary's chains are searched only where the block's
      # own tables give nothing.
      when withCtx:
        doAssert usesChains(ctx.level), "an lz4mid dictionary loaded for another search"
      let ilimitIdx = iend - 8 + base
      template add4(p, idx: int) =
        s.hashTable[midHash4(rd32(p))] = uint32(idx)

      template add8(p, idx: int) =
        s.hashTable[midHash8(rd64(p))] = uint32(idx)

      template countAt(p, pos: int): int =
        if pos >= prefixPos:
          hcCount(src, dict, p, pos, matchlimit, ext, fast)
        else:
          hcCount(src, dict, p, pos, min(matchlimit, p + prefixPos - pos), ext, fast)

      while ip <= mflimit:
        let ipIndex = ip + base
        var matchLength = 0
        var matchDistance = 0
        var found = false
        block search:
          let h8 = midHash8(ird64(ip))
          let pos8 = int(s.hashTable[h8]) - base
          s.hashTable[h8] = uint32(ipIndex)
          if ip - pos8 <= MaxDistance and pos8 >= lowPos:
            matchLength = countAt(ip, pos8)
            if matchLength >= MinMatch:
              matchDistance = ip - pos8
              found = true
              break search
          # A short match, and maybe a longer one at ip + 1.
          let h4 = midHash4(ird32(ip))
          let pos4 = int(s.hashTable[h4]) - base
          s.hashTable[h4] = uint32(ipIndex)
          if ip - pos4 <= MaxDistance and pos4 >= lowPos:
            matchLength = countAt(ip, pos4)
            if matchLength >= MinMatch:
              matchDistance = ip - pos4
              found = true
              if pos4 >= prefixPos:
                let h8b = midHash8(ird64(ip + 1))
                let pos8b = int(s.hashTable[h8b]) - base
                let m2Distance = ip + 1 - pos8b
                if m2Distance <= MaxDistance and pos8b >= prefixPos and ip < mflimit:
                  let ml2 = hcCount(src, dict, ip + 1, pos8b, matchlimit, ext, fast)
                  if ml2 > matchLength:
                    s.hashTable[h8b] = uint32(ipIndex + 1)
                    inc ip
                    matchLength = ml2
                    matchDistance = m2Distance
              break search
          when withCtx:
            if ip - prefixPos < MaxDistance - 8:
              # Two attempts in the dictionary's chains.
              var md = HcMatch(len: MinMatch - 1)
              ctx[].dictSearch(src, dict, ip, ip, matchlimit, 2, md, ext, fast)
              if md.len >= MinMatch:
                matchLength = md.len
                matchDistance = md.off
                found = true
        if not found:
          # Skip faster over incompressible data.
          ip += 1 + ((ip - anchor) shr 9)
          continue
        # Extend the match backwards, within the prefix.
        while ip > anchor and ip - prefixPos > matchDistance and
            isb(ip - 1) == sb(ip - matchDistance - 1):
          dec ip
          inc matchLength
        add8(ip + 1, ipIndex + 1)
        add8(ip + 2, ipIndex + 2)
        add4(ip + 1, ipIndex + 1)
        if not encodeSequence(matchLength, matchDistance):
          return 0
        # The end of the match.
        let endMatchIdx = ip + base
        if endMatchIdx - 2 < ilimitIdx:
          if ip - prefixPos > 5:
            add8(ip - 5, endMatchIdx - 5)
          add8(ip - 3, endMatchIdx - 3)
          add8(ip - 2, endMatchIdx - 2)
          add4(ip - 2, endMatchIdx - 2)
          add4(ip - 1, endMatchIdx - 1)
    elif params.strategy == hsHashChain:
      let maxNbAttempts = params.nbSearches
      let patternAnalysis = params.analysesPatterns
      template search(p, iLowLimit, longest: int): HcMatch =
        wider(p, iLowLimit, longest, maxNbAttempts, patternAnalysis, false)

      var start0, start2, start3: int
      var m0, m1, m2, m3: HcMatch
      while ip <= mflimit:
        m1 = search(ip, ip, MinMatch - 1)
        if m1.len < MinMatch:
          inc ip
          continue
        # Saved, in case we would skip too much.
        start0 = ip
        m0 = m1
        var search3 = false
        while true:
          if not search3:
            # Second search.
            if ip + m1.len <= mflimit:
              start2 = ip + m1.len - 2
              m2 = search(start2, ip, m1.len)
              start2 += m2.back
            else:
              m2 = HcMatch()
            if m2.len <= m1.len:
              # No better match: encode ML1 immediately.
              if not encodeSequence(m1.len, m1.off):
                return 0
              break
            if start0 < ip:
              # First match was skipped at least once.
              if start2 < ip + m0.len:
                # Squeezing ML1 between ML0 (original ML1) and ML2.
                ip = start0
                m1 = m0
            if start2 - ip < 3:
              # First match too small: removed.
              ip = start2
              m1 = m2
              continue
          search3 = false
          # Third search.
          if start2 - ip < OptimalMl:
            var newMl = m1.len
            if newMl > OptimalMl:
              newMl = OptimalMl
            if ip + newMl > start2 + m2.len - MinMatch:
              newMl = start2 - ip + m2.len - MinMatch
            let correction = newMl - (start2 - ip)
            if correction > 0:
              start2 += correction
              m2.len -= correction
          if start2 + m2.len <= mflimit:
            start3 = start2 + m2.len - 3
            m3 = search(start3, start2, m2.len)
            start3 += m3.back
          else:
            m3 = HcMatch()
          if m3.len <= m2.len:
            # No better match: encode ML1 and ML2.
            if start2 < ip + m1.len:
              m1.len = start2 - ip
            if not encodeSequence(m1.len, m1.off):
              return 0
            ip = start2
            if not encodeSequence(m2.len, m2.off):
              return 0
            break
          if start3 < ip + m1.len + 3:
            # Not enough space for match 2: remove it.
            if start3 >= ip + m1.len:
              # Seq1 can be written now; Seq3 becomes Seq1.
              if start2 < ip + m1.len:
                let correction = ip + m1.len - start2
                start2 += correction
                m2.len -= correction
                if m2.len < MinMatch:
                  start2 = start3
                  m2 = m3
              if not encodeSequence(m1.len, m1.off):
                return 0
              ip = start3
              m1 = m3
              start0 = start2
              m0 = m2
              continue
            start2 = start3
            m2 = m3
            search3 = true
            continue
          # Three ascending matches: write the first one, ML1.
          if start2 < ip + m1.len:
            if start2 - ip < OptimalMl:
              if m1.len > OptimalMl:
                m1.len = OptimalMl
              if ip + m1.len > start2 + m2.len - MinMatch:
                m1.len = start2 - ip + m2.len - MinMatch
              let correction = m1.len - (start2 - ip)
              if correction > 0:
                start2 += correction
                m2.len -= correction
            else:
              m1.len = start2 - ip
          if not encodeSequence(m1.len, m1.off):
            return 0
          # ML2 becomes ML1, ML3 becomes ML2.
          ip = start2
          m1 = m2
          start2 = start3
          m2 = m3
          search3 = true
    else:
      # Optimal parser.
      let nbSearches = params.nbSearches
      let sufficientLen = min(params.targetLength, OptNum - 1)
      if s.opt.len == 0:
        s.opt = newSeqUninit[OptCell](OptNum + TrailingLiterals)
      let fullUpdate = level >= HcLevelMax

      template literalsPrice(litlen: int): int =
        (if litlen >= RunMask: litlen + 1 + (litlen - RunMask) div 255
        else: litlen)

      template sequencePrice(litlen, mlen: int): int =
        1 + 2 + literalsPrice(litlen) + (
          if mlen >= MlMask + MinMatch: 1 + (mlen - (MlMask + MinMatch)) div 255
          else: 0
        )

      template longerMatch(p, minLen: int): HcMatch =
        let md = wider(p, p, minLen, nbSearches, true, true)
        if md.len <= minLen:
          HcMatch()
        else:
          md

      while ip <= mflimit:
        let llen = ip - anchor
        var bestMlen, bestOff: int
        var cur: int
        var lastMatchPos = 0
        let firstMatch = longerMatch(ip, MinMatch - 1)
        if firstMatch.len == 0:
          inc ip
          continue
        if firstMatch.len > sufficientLen:
          # Good enough: encode it immediately.
          if not encodeSequence(firstMatch.len, firstMatch.off):
            return 0
          continue

        # Literal prices.
        for rPos in 0 ..< MinMatch:
          s.opt[rPos] = OptCell(
            mlen: 1, off: 0, litlen: llen + rPos, price: literalsPrice(llen + rPos)
          )
        # Prices with the first match.
        for mlen in MinMatch .. firstMatch.len:
          s.opt[mlen] = OptCell(
            mlen: mlen,
            off: firstMatch.off,
            litlen: llen,
            price: sequencePrice(llen, mlen),
          )
        lastMatchPos = firstMatch.len
        for addLit in 1 .. TrailingLiterals:
          s.opt[lastMatchPos + addLit] = OptCell(
            mlen: 1,
            off: 0,
            litlen: addLit,
            price: s.opt[lastMatchPos].price + literalsPrice(addLit),
          )

        # Check further positions.
        var encodeNow = false
        cur = 1
        while cur < lastMatchPos:
          let curPtr = ip + cur
          if curPtr > mflimit:
            break
          if fullUpdate:
            # Not worth searching if the next position costs the same or
            # less, unless the cost rises sharply after it.
            if s.opt[cur + 1].price <= s.opt[cur].price and
                s.opt[cur + MinMatch].price < s.opt[cur].price + 3:
              inc cur
              continue
          elif s.opt[cur + 1].price <= s.opt[cur].price:
            inc cur
            continue
          let newMatch =
            if fullUpdate:
              longerMatch(curPtr, MinMatch - 1)
            else:
              longerMatch(curPtr, lastMatchPos - cur)
          if newMatch.len == 0:
            inc cur
            continue
          if newMatch.len > sufficientLen or newMatch.len + cur >= OptNum:
            # Immediate encoding.
            bestMlen = newMatch.len
            bestOff = newMatch.off
            lastMatchPos = cur + 1
            encodeNow = true
            break
          # Before the match: prices with literals at the beginning.
          let baseLitlen = s.opt[cur].litlen
          for litlen in 1 ..< MinMatch:
            let price =
              s.opt[cur].price - literalsPrice(baseLitlen) +
              literalsPrice(baseLitlen + litlen)
            let p = cur + litlen
            if price < s.opt[p].price:
              s.opt[p] =
                OptCell(mlen: 1, off: 0, litlen: baseLitlen + litlen, price: price)
          # Prices using the match at position cur.
          for ml in MinMatch .. newMatch.len:
            let p = cur + ml
            var price, ll: int
            if s.opt[cur].mlen == 1:
              ll = s.opt[cur].litlen
              price =
                (if cur > ll: s.opt[cur - ll].price else: 0) + sequencePrice(ll, ml)
            else:
              ll = 0
              price = s.opt[cur].price + sequencePrice(0, ml)
            if p > lastMatchPos + TrailingLiterals or price <= s.opt[p].price:
              if ml == newMatch.len and lastMatchPos < p:
                lastMatchPos = p
              s.opt[p] = OptCell(mlen: ml, off: newMatch.off, litlen: ll, price: price)
          # Complete the following positions with literals.
          for addLit in 1 .. TrailingLiterals:
            s.opt[lastMatchPos + addLit] = OptCell(
              mlen: 1,
              off: 0,
              litlen: addLit,
              price: s.opt[lastMatchPos].price + literalsPrice(addLit),
            )
          inc cur

        if not encodeNow:
          bestMlen = s.opt[lastMatchPos].mlen
          bestOff = s.opt[lastMatchPos].off
          cur = lastMatchPos - bestMlen

        # encode: walk the selected path back to its start.
        block:
          var candidatePos = cur
          var selectedMatchLength = bestMlen
          var selectedOffset = bestOff
          while true:
            let nextMatchLength = s.opt[candidatePos].mlen
            let nextOffset = s.opt[candidatePos].off
            s.opt[candidatePos].mlen = selectedMatchLength
            s.opt[candidatePos].off = selectedOffset
            selectedMatchLength = nextMatchLength
            selectedOffset = nextOffset
            if nextMatchLength > candidatePos:
              break # the first match to encode
            candidatePos -= nextMatchLength
        # Encode all recorded sequences in order.
        var rPos = 0
        while rPos < lastMatchPos:
          let ml = s.opt[rPos].mlen
          let offset = s.opt[rPos].off
          if ml == 1:
            inc ip
            inc rPos
            continue
          rPos += ml
          if not encodeSequence(ml, offset):
            return 0

  if not writeLastLiterals(wb, dstAddr, srcAddr, op, anchor, iend, olimit):
    return 0
  op

proc hcCompress*(
    s: var HcState,
    src: openArray[byte],
    start, iend: int,
    dst: var openArray[byte],
    fast: static bool = not useSafe,
): int =
  ## Compresses `src[start ..< iend]`, which must follow the history of `s`
  ## (see hcStart, hcLinked, hcLoadHistory), into `dst`, at the level the
  ## history was started with. Returns the size, or 0 when it does not fit.
  hcImpl(s, src, src, start, iend, dst, nil, ext = sgOne, withCtx = false, fast = fast)

proc hcCompressCtx*(
    s: var HcState,
    src: openArray[byte],
    start, iend: int,
    dst: var openArray[byte],
    ctx: HcState,
    fast: static bool = not useSafe,
): int =
  ## Compresses `src[start ..< iend]` after a dictionary in `src` whose
  ## state is `ctx`, searching that state after the block's own instead of
  ## copying it. The history of `s` must start right after the dictionary
  ## (hcStart). At lz4mid, `ctx` must be loaded with hash chains (see
  ## Lz4fDictLevel).
  hcImpl(
    s,
    src,
    src,
    start,
    iend,
    dst,
    ctx.unsafeAddr,
    ext = sgOne,
    withCtx = true,
    fast = fast,
  )

const
  Lz4fDictCtxMax* = 4096
    ## Frames search a dictionary's state for blocks up to this long, and
    ## copy it for longer ones. The two give different blocks.
  Lz4fDictLevel* = 9
    ## The level frames load their dictionaries at: with hash chains,
    ## whatever the frame's level. An lz4mid block searches them, as it
    ## cannot copy them.

proc midFill(
    s: var HcState,
    src, dict: openArray[byte],
    size: int,
    ext: static Segments,
    fast: static bool,
) =
  ## Fills the hash table for the history of `size` bytes at s.lowLimit.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, dict, ext, fast)
  if size <= 8:
    return
  let base = s.base
  let target = s.lowLimit + size - 8
  var idx = s.nextToUpdate
  while idx < target:
    s.hashTable[midHash4(rd32(idx - base))] = uint32(idx)
    s.hashTable[midHash8(rd64(idx + 1 - base))] = uint32(idx + 1)
    idx += 3
  idx =
    if size > 32768 + 8:
      target - 32768
    else:
      s.nextToUpdate
  while idx < target:
    s.hashTable[midHash8(rd64(idx - base))] = uint32(idx)
    inc idx
  s.nextToUpdate = target

proc hcLoadHistory*(
    s: var HcState, src: openArray[byte], histStart, histEnd, level: int, apart: bool
) =
  ## Makes `src[histStart ..< histEnd]` (at most the last 64 KiB) the
  ## history of the next block at `level`. The tables are not cleared:
  ## hcStart moves the indexes past their entries. With `apart`, the history
  ## is searched as an external dictionary: matches in the block do not
  ## extend back into it, the chains never insert its last 3 positions, and
  ## lz4mid's matches in it end with it.
  let first = max(histStart, histEnd - WindowSize)
  let size = histEnd - first
  s.hcStart(first, level)
  s.endIdx = s.lowLimit + size
  if not usesChains(level):
    midFill(s, src, src, size, ext = sgOne, fast = not useSafe)
  elif size >= 4:
    s.hcInsert(src, src, histEnd - 3, ext = sgOne, fast = not useSafe)
  if apart:
    s.dictLimit = s.endIdx
    s.nextToUpdate = s.endIdx
    if usesChains(level):
      # The chains of the positions left out, which C reads as 0.
      for i in max(s.lowLimit, s.endIdx - 3) ..< s.endIdx:
        s.chainTable[i and 0xFFFF] = 0

func dictId*(s: HcState): int =
  ## The dictionary whose state `s` is or holds unchanged, or 0.
  s.dictId

proc setDictId*(s: var HcState, id: int) =
  ## Marks `s`, just loaded with a dictionary (hcLoadHistory), as the state
  ## of the dictionary `id` (not 0), so that copies of it can be told apart
  ## (see hcRestore).
  s.dictId = id

proc hcRestore*(
    s: var HcState,
    d: HcState,
    src: openArray[byte],
    start, iend: int,
    fast: static bool = not useSafe,
) =
  ## Makes `s` a copy of `d` again after compressing `src[start ..< iend]`
  ## from one (hcCopyState): puts back the entries of `d` that the block
  ## changed. For a short block this costs less than copying all of `d`.
  mixin sb, rd16, rd32, rd64, isb, ird16, ird32, ird64, srcAddr
  readers(src, src, sgOne, fast)
  let base = d.base
  if usesChains(d.level):
    # hcInsert wrote the chains and the hash slots of these positions.
    for idx in d.nextToUpdate ..< s.nextToUpdate:
      let h = hashOf(rd32(idx - base))
      s.hashTable[h] = d.hashTable[h]
      s.chainTable[idx and 0xFFFF] = d.chainTable[idx and 0xFFFF]
  else:
    # lz4mid wrote hash slots of positions in the block, at least 8 bytes
    # before its end; slots it did not write are put back as they are.
    for p in start .. iend - 8:
      let h4 = midHash4(rd32(p))
      s.hashTable[h4] = d.hashTable[h4]
      let h8 = midHash8(rd64(p))
      s.hashTable[h8] = d.hashTable[h8]
  s.nextToUpdate = d.nextToUpdate
  s.endIdx = d.endIdx
  s.dictId = d.dictId

proc hcLinked*(s: var HcState, src: openArray[byte], start: int) =
  ## Prepares the next linked block at `src[start ..]`: positions more than
  ## 64 KiB before it are no longer inserted, and very long histories are
  ## reloaded from their last 64 KiB.
  if s.endIdx > LinkedLimit:
    s.hcLoadHistory(src, max(0, start - WindowSize), start, s.level, apart = false)
    return
  let oldest = start + s.base - WindowSize
  if s.nextToUpdate < oldest:
    s.nextToUpdate = oldest

proc hcMoveHistory*(s: var HcState, n: int) =
  ## Moves the positions of the history by -`n`: the buffer moved `n` bytes
  ## towards its start, or with `n < 0` the history lies `-n` bytes further
  ## on. The indexes, and so the tables, stay as they are.
  s.base += n
