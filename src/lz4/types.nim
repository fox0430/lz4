## The types of the API that are not tied to one module: the error, the
## frame options and the frame header. `lz4` exports this module.

type
  Lz4ErrorKind* = enum
    ekMalformed
      ## Malformed compressed data (magic, header or block layout),
      ## including truncated input. Checksum mismatches are not included.
    ekOutputTooSmall
      ## The caller-provided output buffer is too small
      ## (`decompressBlockInto`).
    ekChecksum ## A header, block or content checksum does not match.
    ekUnsupported ## The data needs a dictionary that was not given.
    ekLimitExceeded ## `maxOutputSize` or the input size limit was exceeded.
    ekInvalidArgument
      ## An argument is invalid (for example a content size
      ## that does not match the data written).

  Lz4Error* = object of CatchableError
    kind*: Lz4ErrorKind

  BlockSizeId* = enum
    ## Block Max Size of a frame. The header stores the ordinal plus 4.
    bs64KiB
    bs256KiB
    bs1MiB
    bs4MiB

  FrameOptions* = object
    ## Frame compression settings. Defaults follow the lz4 CLI, except
    ## `blockSize` (the LZ4F default; the CLI uses 4 MiB). Declare as
    ## `FrameOptions(...)`: a zeroed object gets linked blocks and no
    ## content checksum.
    blockSize*: BlockSizeId = bs64KiB
      ## the largest block; `compressFrame` picks a smaller one for an input
      ## that fits in it
    blockIndependent*: bool = true ## false: blocks may refer to the previous 64 KiB
    blockChecksum*: bool = false
    contentChecksum*: bool = true
    writeContentSize*: bool = false
    level*: int = 0
      ## compression level: 0 and 1 fast, 2 lz4mid, 3 to 12 HC. Linked
      ## frames at level 2 reload their history every 1 GiB (every 2 GiB
      ## with liblz4), so a few blocks differ from liblz4's.
    dictId*: uint32 = 0 ## written in the header when not 0

  FrameKind* = enum
    fkNormal
    fkSkippable
    fkLegacy

  FrameInfo* = object
    ## The header of the first frame of some input (see `readFrameInfo`).
    ## A legacy frame has independent blocks of 8 MiB, which `blockSize`
    ## cannot express: it keeps its default (see `blockMaxSize`).
    kind*: FrameKind
    blockSize*: BlockSizeId = bs64KiB
    blockIndependent*: bool
    blockChecksum*: bool
    contentChecksum*: bool
    hasContentSize*: bool
    contentSize*: uint64
    hasDictId*: bool
    dictId*: uint32
    skippableSize*: uint32 ## user data length, for kind == fkSkippable

const MaxHeaderSize* = 19 ## The longest frame header.
