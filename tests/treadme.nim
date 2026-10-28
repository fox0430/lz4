## The Nim examples of README.md compile and run.

import std/[os, osproc, strutils, tempfiles, unittest]

const root = currentSourcePath().parentDir.parentDir

proc nimBlocks(markdown: string): seq[string] =
  ## The contents of the ```nim fenced blocks (any case), without the
  ## indentation of their fence. An unclosed block is an error.
  var inBlock = false
  var indent = 0
  var current = ""
  for line in markdown.splitLines:
    let stripped = line.strip
    if not inBlock and stripped.toLowerAscii == "```nim":
      inBlock = true
      indent = line.len - line.strip(trailing = false).len
      current = ""
    elif inBlock and stripped == "```":
      inBlock = false
      result.add current
    elif inBlock:
      current.add (if line.len >= indent: line[indent .. ^1] else: line) & "\n"
  doAssert not inBlock, "README.md: a ```nim block is not closed"

suite "README.md":
  test "the Nim examples compile and run":
    let blocks = nimBlocks(readFile(root / "README.md"))
    check blocks.len >= 2
    let dir = createTempDir("nim-lz4-readme-", "")
    defer:
      removeDir(dir)
    # The examples are built like this test: -d:danger, -d:lz4Safe and
    # --mm:refc are passed on (testDanger, testSafe, testRefc).
    var flags =
      "--hints:off --nimcache:" & quoteShell(dir / "cache") & " --path:" &
      quoteShell(root / "src")
    when defined(danger):
      flags.add " -d:danger"
    when defined(lz4Safe):
      flags.add " -d:lz4Safe"
    when not defined(nimSeqsV2):
      flags.add " --mm:refc"
    for k, code in blocks:
      let file = dir / ("example" & $k & ".nim")
      writeFile(file, code)
      let (output, status) = execCmdEx(
        quoteShell(getCurrentCompilerExe()) & " r " & flags & " " & quoteShell(file)
      )
      if status != 0:
        checkpoint "example " & $k & ":\n" & code & "\n" & output
      check status == 0
