## Internal module, not part of the API: the block decoder and the fast
## compressor, for the blocks of `lz4/blocks` and the frames.
##
## The decoder checks every read and write explicitly, so it stays memory
## safe with -d:danger. The compressor is a port of lz4.c (see the license
## notice below) and also checks every write against the destination.
##
## Both come in a safe version that indexes openArrays and a fast one with
## raw pointers, unaligned loads and wide copies; both give the same
## results. The fast one is used unless built with -d:lz4Safe.

import common, hc

type DecodeStatus* = enum
  ## Result of the internal decoder. The public procs map it to an
  ## `Lz4Error` kind, which depends on the caller.
  dsOk
  dsOutputTooSmall ## The output would not fit in the destination.
  dsMalformed ## Truncated data, or a block that ends with a match.
  dsOffsetZero ## A match with offset 0.
  dsOffsetOutOfRange ## An offset before the start of the referable data.

# Decompression

const WildSlack = 32
  ## Output room the fast decoder wants after a match before copying in
  ## whole chunks, which may write up to 31 bytes past the match.

proc decodeSequences(
    src: openArray[byte],
    dst: var openArray[byte],
    dict: openArray[byte],
    dstStart, dstCap, lowLimit: int,
    copy, fast: static bool,
    dstEnd: var int,
): DecodeStatus =
  ## The parser shared by the decoders and the length scan. With `copy` it
  ## writes to `dst`; without it, only the output position moves, up to
  ## `dstCap`. With `fast`, copies may write past the current sequence, but
  ## never past `dstCap`. Matches may refer back to `lowLimit`, and before
  ## it into `dict`.
  let srcLen = src.len
  when fast:
    let s = bytesOf(src)
    template sb(i: int): int =
      int(s[i])

    template bytesAt(a: uint): Bytes =
      cast[Bytes](a)

    when copy:
      let d = bytesOf(dst)
      let dp = bytesOf(dict)

      template outAt(i: int): var byte =
        d[i]

      template srcAddr(i: int): pointer =
        s[i].addr

      template dstAddr(i: int): pointer =
        d[i].addr

      template dictAddr(i: int): pointer =
        dp[i].addr

      template copy32s(to, fro: Bytes, n: int) =
        # Copies `n` (> 0) bytes in 32-byte chunks, writing up to 31 bytes
        # more. `fro` may be 16 or more bytes before `to`.
        var i = 0
        while true:
          copyMem(to[i].addr, fro[i].addr, 16)
          copyMem(to[i + 16].addr, fro[i + 16].addr, 16)
          i += 32
          if i >= n:
            break

      template shortMatch(to, fro: Bytes) =
        # The common short match: at most 18 bytes, offset 8 or more.
        copyMem(to, fro, 8)
        copyMem(to[8].addr, fro[8].addr, 8)
        copyMem(to[16].addr, fro[16].addr, 2)

      template chunkMatch(to, fro: Bytes, offset, matchLen: int) =
        # Copies a match `offset` (1 or more) bytes back in chunks, writing
        # up to 31 bytes past it; the caller checked the room.
        if offset >= 16:
          copy32s(to, fro, matchLen)
        elif offset >= 8:
          var i = 0
          while i < matchLen:
            copyMem(to[i].addr, fro[i].addr, 8)
            i += 8
        elif offset == 1:
          # A run of one byte: 8 copies of it at a time.
          let pattern = 0x0101_0101_0101_0101'u64 * uint64(fro[0])
          var i = 0
          while i < matchLen:
            copyMem(to[i].addr, pattern.unsafeAddr, 8)
            i += 8
        else:
          # Offsets 2 to 7: the first 8 bytes one by one, then 8-byte chunks
          # from a multiple of the offset that is at least 8.
          for i in 0 ..< 8:
            to[i] = fro[i]
          let step = offset * ((8 + offset - 1) div offset)
          var i = 8
          while i < matchLen:
            copyMem(to[i].addr, fro[i + offset - step].addr, 8)
            i += 8

  else:
    template sb(i: int): int =
      int(src[i])

    when copy:
      template outAt(i: int): var byte =
        dst[i]

      template srcAddr(i: int): pointer =
        src[i].unsafeAddr

      template dstAddr(i: int): pointer =
        dst[i].addr

      template dictAddr(i: int): pointer =
        dict[i].unsafeAddr

  when copy:
    template dictMatch(op, matchLen, inDict: int) =
      # Copies a match that starts `inDict` (> 0) bytes before the end of
      # the dictionary and may continue from dst[lowLimit].
      let ms = dict.len - inDict
      var wide = false
      when fast:
        # Wholly inside the dictionary, with room on both sides.
        wide = inDict - matchLen >= 16 and dstCap - op - matchLen >= WildSlack
        if wide:
          var i = 0
          while i < matchLen:
            copyMem(d[op + i].addr, dp[ms + i].addr, 16)
            i += 16
      if not wide:
        let fromDict = min(inDict, matchLen)
        copyMem(dstAddr(op), dictAddr(ms), fromDict)
        let at = op + fromDict
        let rest = matchLen - fromDict
        if rest <= at - lowLimit:
          if rest > 0:
            copyMem(dstAddr(at), dstAddr(lowLimit), rest)
        else:
          for i in 0 ..< rest:
            outAt(at + i) = outAt(lowLimit + i)

  # Match lengths are capped so that the sum (plus MinMatch) stays within
  # high(int) even when dstCap is high(int).
  let lenCap = min(dstCap, high(int) - 259)
  var ip = 0
  var op = dstStart
  when fast:
    # The fast loop: while the output has WildSlack bytes of room and the
    # input is not near its end, a few checks per sequence cover all reads
    # and wide writes. It stops at the first sequence it does not finish,
    # which the loop below decodes again from its token.
    if srcLen > 0 and dstCap - op >= WildSlack:
      # The positions are kept as addresses, so that the loads on which the
      # next position depends come from a register.
      let sBase = cast[uint](s)
      let dBase =
        when copy:
          cast[uint](d)
        else:
          0'u
      let iEnd = sBase + uint(srcLen)
      let oLow = dBase + uint(lowLimit)
      template inp(k: int): int =
        int(bytesAt(ia)[k])

      # A token without a length byte has at most 14 literals, copied in 16
      # bytes when they start at iShort or before. A sequence starts at
      # oLimit or before, and a match other than a short one ends there or
      # before.
      let iShort =
        if srcLen >= 17:
          iEnd - 17
        else:
          0
      let oLimit = dBase + uint(dstCap - WildSlack)
      var ia = sBase + uint(ip)
      var oa = dBase + uint(op)
      var seqIa, seqOa: uint
      block fastLoop:
        template bail() =
          ip = int(seqIa - sBase)
          op = int(seqOa - dBase)
          break fastLoop

        while true:
          seqIa = ia
          seqOa = oa
          if unlikely(oa > oLimit):
            bail()
          let token = inp(0)
          var litLen = token shr 4
          if litLen == RunMask:
            inc ia
            while true:
              if ia >= iEnd:
                bail()
              let b = inp(0)
              inc ia
              if b > srcLen - litLen:
                bail()
              litLen += b
              if b != 255:
                break
            # Room for 32-byte chunks on both sides.
            if litLen > int(iEnd - ia) - WildSlack or litLen > int(oLimit - oa):
              bail()
            when copy:
              copy32s(bytesAt(oa), bytesAt(ia), litLen)
            ia += uint(litLen) + 2
          elif likely(ia < iShort):
            when copy:
              copyMem(cast[pointer](oa), cast[pointer](ia + 1), 16)
            # In one step from the token: the next position depends on it.
            ia += uint(litLen) + 3
          else:
            bail()
          oa += uint(litLen)

          let offset = int(loadLE16(bytesAt(ia - 2), 0))
          let back = int(oa - oLow)
          var matchLen = token and MlMask
          if matchLen != MlMask:
            matchLen += MinMatch
            if likely(offset >= 8 and offset <= back):
              # A short match, with room for its 18 bytes.
              when copy:
                shortMatch(bytesAt(oa), bytesAt(oa - uint(offset)))
              oa += uint(matchLen)
              continue
          else:
            while true:
              if ia >= iEnd - 1:
                bail()
              let b = inp(0)
              inc ia
              matchLen += b
              if matchLen > lenCap:
                bail()
              if b != 255:
                break
            matchLen += MinMatch
          if matchLen > cast[int](oLimit - oa):
            bail()
          if offset > back:
            let inDict = offset - back
            if inDict > dict.len:
              bail()
            when copy:
              dictMatch(int(oa - dBase), matchLen, inDict)
          elif offset == 0:
            bail()
          else:
            when copy:
              chunkMatch(bytesAt(oa), bytesAt(oa - uint(offset)), offset, matchLen)
          oa += uint(matchLen)

  while true:
    # A block has at least one token and must not end right after a match.
    if ip >= srcLen:
      return dsMalformed
    let token = sb(ip)
    inc ip

    var litLen = token shr 4
    if litLen == RunMask:
      while true:
        if ip >= srcLen:
          return dsMalformed
        let b = sb(ip)
        inc ip
        # The literals must be in the input; checking before adding also
        # keeps the sum from overflowing.
        if b > srcLen - litLen:
          return dsMalformed
        litLen += b
        if b != 255:
          break
    if litLen > srcLen - ip:
      return dsMalformed
    if litLen > dstCap - op:
      return dsOutputTooSmall
    when copy:
      var wide = false
      when fast:
        # A short run with room on both sides: one 16-byte copy.
        wide = litLen <= 16 and srcLen - ip >= 16 and dstCap - op >= 16
        if wide:
          copyMem(dstAddr(op), srcAddr(ip), 16)
      if not wide and litLen > 0:
        copyMem(dstAddr(op), srcAddr(ip), litLen)
    ip += litLen
    op += litLen

    if ip == srcLen:
      dstEnd = op
      return dsOk

    if srcLen - ip < 2:
      return dsMalformed
    let offset = sb(ip) or (sb(ip + 1) shl 8)
    ip += 2
    if offset == 0:
      return dsOffsetZero
    # How many bytes of the match are in the dictionary (none when <= 0).
    let inDict = offset - (op - lowLimit)
    if inDict > dict.len:
      return dsOffsetOutOfRange

    var matchLen = token and MlMask
    if matchLen == MlMask:
      while true:
        if ip >= srcLen:
          return dsMalformed
        let b = sb(ip)
        inc ip
        # Stop adding once the match cannot fit, but read to the end of the
        # length: a block cut off inside it is malformed whatever the output.
        if matchLen <= lenCap:
          matchLen += b
        if b != 255:
          break
      if matchLen > lenCap:
        return dsOutputTooSmall
    matchLen += MinMatch
    if matchLen > dstCap - op:
      return dsOutputTooSmall

    when copy:
      if inDict > 0:
        dictMatch(op, matchLen, inDict)
      else:
        let mp = op - offset
        when fast:
          let to = cast[Bytes](d[op].addr)
          let fro = cast[Bytes](d[mp].addr)
          if matchLen <= 18 and offset >= 8 and dstCap - op >= 18:
            shortMatch(to, fro)
          elif dstCap - op - matchLen >= WildSlack:
            chunkMatch(to, fro, offset, matchLen)
          else:
            # Near the end of the output: 8-byte chunks that stay inside the
            # match, then the last bytes one by one.
            var i = 0
            var back = offset
            if offset < 8:
              while i < min(8, matchLen):
                d[op + i] = d[mp + i]
                inc i
              back = offset * ((8 + offset - 1) div offset)
            while matchLen - i >= 8:
              copyMem(d[op + i].addr, d[op + i - back].addr, 8)
              i += 8
            while i < matchLen:
              d[op + i] = d[mp + i]
              inc i
        else:
          if offset >= matchLen:
            # The ranges do not overlap.
            copyMem(dstAddr(op), dstAddr(mp), matchLen)
          else:
            # Overlapping match: copy forwards so that the bytes written by
            # this match are repeated.
            for i in 0 ..< matchLen:
              outAt(op + i) = outAt(mp + i)
    op += matchLen

proc decodeBlock*(
    src: openArray[byte],
    dst: var openArray[byte],
    dict: openArray[byte],
    dstStart, lowLimit: int,
    dstEnd: var int,
    fast: static bool = not useSafe,
): DecodeStatus {.inline.} =
  ## Decodes the block `src` into `dst` at `dstStart`, writing at most up to
  ## `dst.len`. Matches may refer back to `lowLimit` (0 <= lowLimit <=
  ## dstStart), and before it into `dict`, which stands for the bytes right
  ## before `dst[lowLimit]`. The bytes in `lowLimit ..< dstStart` are the
  ## prefix (the previous blocks of a linked frame). On success `dstEnd` is
  ## the end of the decoded data; on failure the contents of `dst[dstStart
  ## ..]` are unspecified.
  ##
  ## With `fast`, wide copies may also overwrite the bytes of `dst` after
  ## `dstEnd`.
  ##
  ## Termination rules 2 and 3 of the specification (the last 5 bytes are
  ## literals, the last match starts 12 bytes before the end) are not
  ## enforced; rule 1 (the block ends with literals) is.
  decodeSequences(
    src,
    dst,
    dict,
    dstStart,
    dst.len,
    lowLimit,
    copy = true,
    fast = fast,
    dstEnd = dstEnd,
  )

proc decodedLength*(
    src: openArray[byte],
    prefixLen, limit: int,
    total: var int,
    fast: static bool = not useSafe,
): DecodeStatus =
  ## Computes the decoded length of `src` without copying, for a block
  ## decoded after `prefixLen` bytes of prefix. Returns the status decoding
  ## would return with an output of `limit` bytes: every check, offsets
  ## included, is made, so a block that passes always decodes. The safe and
  ## the fast versions (`fast`) give the same results.
  var none: array[0, byte]
  let cap =
    if limit > high(int) - prefixLen:
      high(int)
    else:
      prefixLen + limit
  var e = 0
  result = decodeSequences(
    src, none, none, prefixLen, cap, 0, copy = false, fast = fast, dstEnd = e
  )
  if result == dsOk:
    total = e - prefixLen

proc raiseDecodeError*(
    s: DecodeStatus, tooSmall: Lz4ErrorKind, outOfRange = ekMalformed
) {.noreturn, raises: [Lz4Error].} =
  ## Raises the error for a failed decode. `tooSmall` is used when the output
  ## does not fit, `outOfRange` for an offset before the referable data
  ## (ekUnsupported when a dictionary is missing).
  case s
  of dsOutputTooSmall:
    if tooSmall == ekMalformed:
      # Only frames pass it: the block is larger than its Block Max Size.
      raiseLz4(ekMalformed, "malformed block: larger than the frame's block size")
    raiseLz4(tooSmall, "the decompressed data does not fit in the output")
  of dsMalformed, dsOk:
    raiseLz4(ekMalformed, "malformed block")
  of dsOffsetZero:
    # The fuzzers match this error text.
    raiseLz4(ekMalformed, "malformed block: offset 0")
  of dsOffsetOutOfRange:
    if outOfRange == ekUnsupported:
      raiseLz4(ekUnsupported, "the block refers to a dictionary that was not given")
    raiseLz4(outOfRange, "malformed block: offset before the start of the data")

proc raiseDoesNotFit*(
    src: openArray[byte],
    prefixLen, bound: int,
    tooSmall, beyond: Lz4ErrorKind,
    outOfRange = ekMalformed,
) {.noreturn, raises: [Lz4Error].} =
  ## Raises the error for the block `src` (after `prefixLen` bytes of
  ## prefix) whose output ran out. It is scanned up to `bound` bytes of
  ## output first, so that an invalid block gives its own error whatever the
  ## output size.
  var total = 0
  let s = decodedLength(src, prefixLen, bound, total)
  if s == dsOk:
    raiseDecodeError(dsOutputTooSmall, tooSmall)
  raiseDecodeError(s, beyond, outOfRange)

# Compression (fast)
#
# compressImpl is a port of LZ4_compress_generic_validated from lz4.c
# 1.10.0: the history is in front of the block in the same buffer, or in a
# dictionary kept apart. The original license:
#
#   LZ4 - Fast LZ compression algorithm
#   Copyright (C) 2011-2023, Yann Collet.
#
#   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

const Limit64K* = 65536 + MfLimit - 1
  ## Below this length, an independent block uses the 16-bit table, since
  ## every position fits in 16 bits.

type
  HashTable* = array[1 shl HashLog, uint32]
    ## 4096 positions (offsets from a base) indexed by a hash of 5 bytes.

  HashTable16* = array[1 shl (HashLog + 1), uint16]
    ## 8192 positions indexed by a hash of 4 bytes, for independent blocks
    ## shorter than Limit64K. It has the same size in bytes, so one table
    ## can serve as either (see `as16`).

  DictKind* = enum
    ## The liblz4 API whose dictionary indexing to use: blocks and frames
    ## index dictionaries differently.
    dkBlock ## LZ4_loadDict, then *_continue
    dkFrame ## LZ4F_createCDict (frames, lz4 -D)

  DictState* = object
    ## A dictionary indexed once for independent blocks at one level, which
    ## compressing only reads (see `compressAfterDict`): that of a BlockDict
    ## and that of a frame's independent blocks (or of its first linked ones,
    ## see compressLinkedCtx).
    len*: int ## the dictionary's length, at most 64 KiB (0: none)
    level*: int
    kind: DictKind
    id*: int ## unique to the dictionary (copies share it): see newDictId
    table: ref HashTable # fast levels: the positions of the dictionary
    hc: ref HcState # HC levels: the state of the dictionary

func accelerationOf*(level: int): int =
  ## The acceleration of the fast compressor for a compression level:
  ## negative levels speed up, 0 and 1 use acceleration 1 (levels from 2 on
  ## use the HC compressor).
  if level < -(AccelerationMax - 1):
    AccelerationMax
  elif level < 0:
    -level + 1
  else:
    1

template div255(n: int): int =
  # n div 255 for 0 <= n < 2^32, in 32-bit unsigned arithmetic.
  int(uint32(n) div 255)

template hash5*(v: uint64): int =
  ## The 5-byte hash of the 32-bit table.
  int(((v shl 24) * 889523592379'u64) shr (64 - HashLog))

proc compressImpl[T: HashTable | HashTable16](
    table: var T,
    src, dict: openArray[byte],
    start, iend, lowLimit, base: int,
    dst: var openArray[byte],
    acceleration: int,
    dictTable: ptr HashTable,
    reused, split, extDict, ctx, fast: static bool,
): int =
  ## See `compressGeneric`. `reused` is for a table that may hold entries
  ## below `lowLimit`. With `extDict`, positions below `dict.len` are in
  ## `dict` and the others in `src`. With `ctx`, entries of `table` below
  ## `start` are not this block's: `dictTable` is looked up instead.
  let olimit = dst.len
  # Reads of the input (isb, ird32, ...) and of a match (sb, rd32, ...,
  # which may be in the dictionary with `extDict`).
  const ext = if extDict: sgTwo else: sgOne
  mixin sb, rd32, isb, ird32, ird64, srcAddr, org
  # The fast version takes addresses for positions on 64-bit systems, as C
  # takes pointers: a load then costs a cycle less. Not with a dictionary
  # apart, whose small blocks were slower so.
  readers(src, dict, ext, fast, absolute = sizeof(int) == 8 and ext == sgOne)
  let start = start + org
  let iend = iend + org
  let lowLimit = lowLimit + org
  let base = base + org
  when fast:
    let d = bytesOf(dst)
    let tp = cast[ptr UncheckedArray[typeof(table[0])]](table[0].addr)
    template dstAddr(i: int): pointer =
      d[i].addr

    template wb(i: int, v: byte) =
      d[i] = v

    template ob(i: int): byte =
      d[i]

    template tget(h: int): int =
      int(tp[h])

    template tput(h, v: int) =
      tp[h] = typeof(table[0])(v)

  else:
    template dstAddr(i: int): pointer =
      dst[i].addr

    template wb(i: int, v: byte) =
      dst[i] = v

    template ob(i: int): byte =
      dst[i]

    template tget(h: int): int =
      int(table[h])

    template tput(h, v: int) =
      table[h] = typeof(table[0])(v)

  when ctx:
    # Entries from here on are this block's; dictionary entries are offset
    # by dictDelta, as their table ends at WindowSize.
    let ctxFirst = start - base
    let dictDelta = ctxFirst - WindowSize
    when fast:
      let dtp = cast[ptr UncheckedArray[uint32]](dictTable[][0].addr)
      template dget(h: int): int =
        int(dtp[h])

    else:
      template dget(h: int): int =
        int(dictTable[][h])

  template seqAt(p: int): uint64 =
    # The bytes at p that the hash reads (8 for the 5-byte hash).
    when T is HashTable16:
      uint64(ird32(p))
    else:
      ird64(p)

  template hashOf(v: uint64): int =
    when T is HashTable16:
      # LZ4_hash4 with HASHLOG + 1 bits.
      int((uint32(v) * 2654435761'u32) shr (32 - (HashLog + 1)))
    else:
      hash5(v)

  template hashAt(p: int): int =
    hashOf(seqAt(p))

  template inReach(matchIndex, current: int): bool =
    # A 16-bit table only covers inputs shorter than Limit64K, where every
    # candidate is within MaxDistance.
    when T is HashTable16:
      true
    else:
      matchIndex + MaxDistance >= current

  var op = 0
  var anchor = start
  var ip = start

  block compression:
    if iend - start < MinLength:
      break compression
    let mflimitPlusOne = iend - MfLimit + 1
    let matchlimit = iend - LastLiterals

    tput(hashAt(ip), ip - base)
    inc ip
    var forwardSeq = seqAt(ip)
    var forwardH = hashOf(forwardSeq)

    while true:
      # Find a match, widening the step while none is found.
      var match = 0
      block search:
        var forwardIp = ip
        var step = 1
        var searchMatchNb = acceleration shl SkipTrigger
        while true:
          # The bytes hashed at forwardIp are kept to compare with the
          # match: reading them again made hard-to-compress input slower.
          let h = forwardH
          let sq = forwardSeq
          let current = forwardIp - base
          var matchIndex = tget(h)
          when ctx:
            if matchIndex < ctxFirst:
              matchIndex = dictDelta + dget(h)
          ip = forwardIp
          forwardIp += step
          step = searchMatchNb shr SkipTrigger
          inc searchMatchNb
          if unlikely(forwardIp > mflimitPlusOne):
            break compression
          match = base + matchIndex
          when reused:
            # Entries below lowLimit stand for it (see compressGeneric).
            match = max(match, lowLimit)
          forwardSeq = seqAt(forwardIp)
          forwardH = hashOf(forwardSeq)
          tput(h, current)
          if not inReach(matchIndex, current):
            continue
          if rd32(match) == uint32(sq):
            break search

      # Catch up: extend the match backwards. With `split`, a match in the
      # block stops at its start.
      let low =
        when split:
          if match >= start: start else: lowLimit
        else:
          lowLimit
      # The two bounds in one branch, as C tests them.
      while (ord(ip > anchor) and ord(match > low)) != 0 and
          unlikely(isb(ip - 1) == sb(match - 1)):
        dec ip
        dec match

      # Encode the literals.
      let litLength = ip - anchor
      var token = op
      inc op
      # Room for the length bytes, the literals, an offset, the next token
      # and 5 last literals: 8 bytes past the literals.
      if unlikely(litLength + (2 + 1 + LastLiterals) + div255(litLength) > olimit - op):
        return 0
      if litLength >= RunMask:
        wb(token, byte(RunMask shl 4))
        writeLengthBytes(wb, op, litLength - RunMask)
      else:
        wb(token, byte(litLength shl 4))
      when fast:
        # 8 bytes at a time, at most 8 past the literals, which the check
        # above keeps inside dst.
        var i = 0
        while true:
          copyMem(d[op + i].addr, srcAddr(anchor + i), 8)
          i += 8
          if i >= litLength:
            break
      else:
        if litLength > 0:
          copyMem(dst[op].addr, srcAddr(anchor), litLength)
      op += litLength

      while true:
        let off = ip - match
        when fast:
          storeLE16(d, op, uint16(off))
        else:
          wb(op, byte(off and 0xFF))
          wb(op + 1, byte(off shr 8))
        op += 2
        let matchCode = countMatch(ip + MinMatch, match + MinMatch, matchlimit, ext)
        ip += matchCode + MinMatch
        if unlikely((1 + LastLiterals) + div255(matchCode + 240) > olimit - op):
          return 0
        if matchCode >= MlMask:
          wb(token, ob(token) + byte(MlMask))
          writeLengthBytes(wb, op, matchCode - MlMask)
        else:
          wb(token, ob(token) + byte(matchCode))
        anchor = ip

        if ip >= mflimitPlusOne:
          break compression

        tput(hashAt(ip - 2), ip - 2 - base)

        # A match right here, without literals.
        let h = hashAt(ip)
        let current = ip - base
        var matchIndex = tget(h)
        when ctx:
          if matchIndex < ctxFirst:
            matchIndex = dictDelta + dget(h)
        match = base + matchIndex
        when reused:
          match = max(match, lowLimit)
        tput(h, current)
        if inReach(matchIndex, current) and rd32(match) == ird32(ip):
          token = op
          inc op
          wb(token, 0)
          continue
        break

      inc ip
      forwardSeq = seqAt(ip)
      forwardH = hashOf(forwardSeq)

  if not writeLastLiterals(wb, dstAddr, srcAddr, op, anchor, iend, olimit):
    return 0
  op

proc compressGeneric*[T: HashTable | HashTable16](
    table: var T,
    src: openArray[byte],
    start, iend, lowLimit, base: int,
    dst: var openArray[byte],
    acceleration: int,
    reused: static bool = false,
    split: static bool = false,
    fast: static bool = not useSafe,
): int =
  ## Compresses `src[start ..< iend]` into `dst` and returns the size, or 0
  ## when it does not fit (nothing is written past `dst.len`; the table may
  ## have been updated).
  ##
  ## `table` holds positions as offsets from `base` (base <= start): an entry
  ## e stands for base + e. `lowLimit ..< start` is the history (previous
  ## blocks or a dictionary), and `lowLimit` is how far back a match may be
  ## extended byte by byte; with `split`, a match in the block only back to
  ## `start`, as C does after an external dictionary. An entry that stands
  ## for a position below `lowLimit` must be more than MaxDistance before
  ## `start`, as the empty entries of a dictionary's table are (see
  ## loadDictTable). A clear table has base = lowLimit = start. An
  ## independent block may reuse a table whose entries are all below its
  ## first index; they then stand for `start` as well, so `reused` must be
  ## set. `iend - base` must fit in 31 bits (16 bits below Limit64K for a
  ## HashTable16, which is only for independent blocks). Only positions >=
  ## start are stored.
  ##
  ## With `fast`, literals are copied 8 bytes at a time, which may also
  ## overwrite the bytes of `dst` after the result (so for the other
  ## compressors below).
  compressImpl(
    table,
    src,
    src,
    start,
    iend,
    lowLimit,
    base,
    dst,
    acceleration,
    nil,
    reused = reused,
    split = split,
    extDict = false,
    ctx = false,
    fast = fast,
  )

func dictBase*(dictLen: int): int =
  ## The base of a dictionary's table when the dictionary is at position 0:
  ## its positions are stored from WindowSize - dictLen on, so that an empty
  ## entry (0) stands for a position 64 KiB before the block.
  dictLen - WindowSize

proc compressWithDict*(
    table: var HashTable,
    src, dict: openArray[byte],
    dst: var openArray[byte],
    acceleration: int,
    fast: static bool = not useSafe,
): int =
  ## Compresses all of `src` as one block that may refer to `dict`, kept in
  ## its own buffer, into `dst`. `table` holds the positions of `dict`. The
  ## result equals compressGeneric on `[dict | src]` with base =
  ## dictBase(dict.len) and `split`, without making that buffer.
  compressImpl(
    table,
    src,
    dict,
    dict.len,
    dict.len + src.len,
    0,
    dictBase(dict.len),
    dst,
    acceleration,
    nil,
    reused = false,
    split = true,
    extDict = true,
    ctx = false,
    fast = fast,
  )

proc compressWithDictCtx*(
    table: var HashTable,
    first: int,
    dictTable: HashTable,
    src, dict: openArray[byte],
    dst: var openArray[byte],
    acceleration: int,
    fast: static bool = not useSafe,
): int =
  ## The result of `compressWithDict` on a copy of `dictTable`, without
  ## making that copy: `table` only gets the positions of `src`, stored from
  ## `first` on, and older entries are looked up in `dictTable`. Every entry
  ## of `table` must be below `first` (> 0), and `first + src.len` must fit
  ## in 31 bits.
  compressImpl(
    table,
    src,
    dict,
    dict.len,
    dict.len + src.len,
    0,
    dict.len - first,
    dst,
    acceleration,
    dictTable.unsafeAddr,
    reused = false,
    split = true,
    extDict = true,
    ctx = true,
    fast = fast,
  )

template as16*(t: var HashTable): var HashTable16 =
  ## The memory of a HashTable used as a HashTable16 (same size).
  cast[ptr HashTable16](t.addr)[]

const DictCtxMax* = 1024
  ## Inputs up to this long search a prepared dictionary's table rather than
  ## a copy of it; longer ones are faster with the copy.

const FastResetMax = 1024
  ## Independent blocks shorter than this reuse the 16-bit table without
  ## clearing it (see compressIndependent).

proc compressIndependent*(
    table: var HashTable,
    next16: var int,
    src: openArray[byte],
    start, iend: int,
    dst: var openArray[byte],
    acceleration: int,
): int =
  ## Compresses `src[start ..< iend]` as an independent block with the table
  ## for that length (the 16-bit one below Limit64K, in the same memory).
  ## `next16` says what the table holds: 0 when clear, -1 when it holds
  ## something else, otherwise the 16-bit index the next block may start at.
  ## A short block starts there instead of clearing the table.
  let n = iend - start
  if n < MinLength:
    # Stored as literals without touching the table.
    return
      compressGeneric(table.as16, src, start, iend, start, start, dst, acceleration)
  if n < Limit64K:
    let first = next16
    if first > 0 and n < FastResetMax and first + n < 0xFFFF:
      next16 = first + n
      return compressGeneric(
        table.as16,
        src,
        start,
        iend,
        start,
        start - first,
        dst,
        acceleration,
        reused = true,
      )
    if first != 0:
      zeroMem(table.addr, sizeof(table))
    next16 = n
    compressGeneric(table.as16, src, start, iend, start, start, dst, acceleration)
  else:
    if next16 != 0:
      zeroMem(table.addr, sizeof(table))
    next16 = -1
    compressGeneric(table, src, start, iend, start, start, dst, acceleration)

proc compressDictCtx*(
    table: var HashTable,
    nextCtx: var int,
    dictTable: HashTable,
    src, dict: openArray[byte],
    dst: var openArray[byte],
    acceleration: int,
): int =
  ## `compressWithDictCtx` for an input of up to DictCtxMax bytes, reusing
  ## `table` from one call to the next without clearing it. `nextCtx` says
  ## what `table` holds: 0 when something else, otherwise the index the
  ## next input may start at, all entries being below it.
  var first = nextCtx
  if first == 0 or first > (1 shl 30) - src.len:
    zeroMem(table.addr, sizeof(table))
    first = 1
  nextCtx = first + src.len
  compressWithDictCtx(table, first, dictTable, src, dict, dst, acceleration)

proc loadDictTable*(
    table: var HashTable,
    src: openArray[byte],
    dictLen: int,
    every = false,
    fast: static bool = not useSafe,
) =
  ## Clears `table` and records every third position of the dictionary
  ## `src[0 ..< dictLen]` (at most 64 KiB), with base dictBase(dictLen).
  ## With `every`, the positions left out then fill the entries still empty.
  when fast:
    let sp = bytesOf(src)
    template rd64(i: int): uint64 =
      loadLE64(sp, i)

  else:
    template rd64(i: int): uint64 =
      readLE64(src, i)

  zeroMem(table.addr, sizeof(table))
  let first = WindowSize - dictLen
  var p = 0
  while p <= dictLen - 8:
    table[hash5(rd64(p))] = uint32(first + p)
    p += 3
  if every:
    # In order, only into entries the first pass left empty.
    template fill(q: int) =
      let h = hash5(rd64(q))
      if table[h] == 0:
        table[h] = uint32(first + q)

    p = 1
    while p <= dictLen - 8:
      fill(p)
      if p + 1 <= dictLen - 8:
        fill(p + 1)
      p += 3

type DictMode* = enum
  ## How a block after a dictionary is compressed. The prepared
  ## dictionaries and the overloads that take one as it is follow it, so
  ## that they give the same blocks.
  dmLiterals ## shorter than MinLength: literals only
  dmCtx ## its own state, searching the dictionary's
  dmCopy ## from a copy of the dictionary's state

func dictMode*(level, n: int, kind: DictKind): DictMode =
  ## The mode of a block of `n` bytes at `level`. Both modes give the same
  ## blocks, except at the HC levels of frames, where the mode is LZ4F's.
  let ctx =
    if not isHcLevel(level):
      n <= DictCtxMax
    elif kind == dkFrame:
      n <= Lz4fDictCtxMax or not usesChains(level)
    else:
      false
  if n < MinLength:
    dmLiterals
  elif ctx:
    dmCtx
  else:
    dmCopy

const
  RestoreMax = 4096
    ## The longest HC block after a dictionary that puts back what it
    ## changed in a copy of its state (see compressAfterDict), where that
    ## was faster than copying the state (256 KiB) again.
  MidRestoreMax = 1024
    ## The same at lz4mid, which puts back 2 slots for every position but
    ## copies half as much.

var lastDictId: int # see newDictId

proc newDictId(): int =
  ## A number no other dictionary state of the process has, so that a
  ## compressor can tell whether it holds a copy of a dictionary's state.
  # Atomic: dictionaries may be made in several threads at once.
  atomicInc(lastDictId)

proc initDictState*(dict: openArray[byte], level: int, kind: DictKind): DictState =
  ## Indexes all of `dict` (at most 64 KiB) for independent blocks at
  ## `level`, as liblz4 does for `kind`.
  result = DictState(len: dict.len, level: level, kind: kind)
  if dict.len == 0:
    return
  result.id = newDictId()
  if isHcLevel(level):
    # Hash chains, whose tables are the same at every level from 3 on.
    let loadLevel =
      if kind == dkFrame and not usesChains(level): Lz4fDictLevel else: level
    result.hc = newHcState()
    result.hc[].hcLoadHistory(dict, 0, dict.len, loadLevel, apart = true)
    result.hc[].setDictId(result.id)
  else:
    new(result.table)
    # Frames index every position, blocks every third one.
    loadDictTable(result.table[], dict, dict.len, every = kind == dkFrame)

proc compressAfterDict*(
    table: var HashTable,
    nextCtx: var int,
    hc: var HcBox,
    d: DictState,
    level: int,
    src, dict: openArray[byte],
    dst: var openArray[byte],
    inPlace: static bool,
): int =
  ## Compresses an independent block that may refer to the dictionary of
  ## `d` (`d.len > 0`) at `level` into `dst`, with the tables of a
  ## compressor. Without `inPlace`, the block is all of `src` and the
  ## dictionary is `dict`; with `inPlace`, the dictionary is
  ## `src[0 ..< d.len]` and the block the rest of `src`. Both give the same
  ## result. The fast compressor sets `table` and `nextCtx`. The HC
  ## compressor takes the dictionary in the same buffer only, and after a
  ## short block leaves a copy of the dictionary's state in `hc`.
  let n =
    when inPlace:
      src.len - d.len
    else:
      src.len
  template blockBytes(): untyped =
    when inPlace:
      src.toOpenArray(d.len, src.high)
    else:
      src

  template dictBytes(): untyped =
    when inPlace:
      src.toOpenArray(0, d.len - 1)
    else:
      dict

  doAssert isHcLevel(level) == isHcLevel(d.level), "a dictionary of another compressor"
  let acceleration = accelerationOf(level)
  case dictMode(level, n, d.kind)
  of dmLiterals:
    # No state to start or copy, no table to touch.
    compressGeneric(table.as16, blockBytes, 0, n, 0, 0, dst, acceleration)
  of dmCtx:
    # A short block, searching the dictionary's state rather than copying it.
    if isHcLevel(level):
      # Frames only.
      when inPlace:
        hc[].hcStart(d.len, level)
        hc[].hcCompressCtx(src, d.len, src.len, dst, d.hc[])
      else:
        raiseAssert "an HC block apart from its dictionary"
    else:
      compressDictCtx(
        table, nextCtx, d.table[], blockBytes, dictBytes, dst, acceleration
      )
  of dmCopy:
    if isHcLevel(level):
      when inPlace:
        # A short block puts back the entries it changed, which is cheaper
        # than copying the 256 KiB state again.
        if hc[].dictId != d.id:
          hcCopyState(hc[], d.hc[])
        # A copy has the dictionary's level, a restored one its last block's.
        hc[].setLevel(level)
        let size = hc[].hcCompress(src, d.len, src.len, dst)
        if n <= (if usesChains(level): RestoreMax else: MidRestoreMax):
          hc[].hcRestore(d.hc[], src, d.len, src.len)
        size
      else:
        raiseAssert "an HC block apart from its dictionary"
    else:
      table = d.table[]
      nextCtx = 0
      when inPlace:
        compressGeneric(
          table,
          src,
          d.len,
          src.len,
          0,
          dictBase(d.len),
          dst,
          acceleration,
          split = true,
        )
      else:
        compressWithDict(table, src, dict, dst, acceleration)

proc compressLinkedCtx*(
    hc: var HcState,
    d: DictState,
    src: openArray[byte],
    start, iend: int,
    dst: var openArray[byte],
): int =
  ## A linked block of a frame, `src[start ..< iend]`, after the history of
  ## `hc`, which starts right after the dictionary of `d`.
  hc.hcCompressCtx(src, start, iend, dst, d.hc[])

proc copyDictTable*(table: var HashTable, d: DictState) =
  ## Sets `table` to the table of the dictionary of `d` (fast levels).
  table = d.table[]

proc copyDictHc*(s: var HcState, d: DictState, level: int) =
  ## Makes `s` a copy of the HC state of the dictionary of `d` for blocks at
  ## `level`.
  hcCopyState(s, d.hc[])
  s.setLevel(level)
