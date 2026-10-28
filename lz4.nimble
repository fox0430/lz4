# Package

version = "0.1.0"
author = "fox0430"
description = "LZ4 implementation in pure Nim"
license = "MIT AND BSD-2-Clause"
srcDir = "src"

# Dependencies

requires "nim >= 2.2.0"

# Tasks

import std/[os, strutils]

const interopTests = ["tinterop_lib.nim", "tinterop_cli.nim"]

proc testFiles(): seq[string] =
  for f in listFiles("tests"):
    let name = f.extractFilename
    if name.startsWith("t") and name.endsWith(".nim"):
      result.add f

task testPure, "Run the tests that need neither liblz4 nor the lz4 CLI":
  for f in testFiles():
    if f.extractFilename notin interopTests:
      exec "nim c -r --hints:off " & quoteShell(f)

task testDanger, "Run all tests built with -d:danger (no runtime checks)":
  # The library must stay memory safe without Nim's runtime checks, so the
  # explicit checks are what these runs exercise.
  for f in testFiles():
    exec "nim c -r --hints:off -d:danger " & quoteShell(f)

task testSafe, "Run all tests with the safe versions in the public API (-d:lz4Safe)":
  for f in testFiles():
    exec "nim c -r --hints:off -d:lz4Safe " & quoteShell(f)

task testRefc, "Run all tests with the refc memory manager (--mm:refc)":
  for f in testFiles():
    exec "nim c -r --hints:off --mm:refc " & quoteShell(f)

task testHuge, "Run the tests with inputs above 1 GiB (about 4 GiB of memory, minutes)":
  # Not in testFiles (tests/huge.nim does not start with "t"): too heavy for
  # every run. Fast and safe code paths, both with runtime checks.
  exec "nim c -r --hints:off tests/huge.nim"
  exec "nim c -r --hints:off -d:lz4Safe tests/huge.nim"

task docs, "Build the API documentation into htmldocs/ (runs the examples)":
  # The public modules only, not src/lz4/private (no --project), all with
  # the same docRoot, so that their pages land in one tree
  # (htmldocs/lz4/...) and link to each other; then one index.
  rmDir("htmldocs")
  let flags =
    "--hints:off --index:on --outdir:htmldocs" & " --docRoot:" &
    quoteShell(thisDir() / "src")
  exec "nim doc " & flags & " src/lz4.nim"
  for f in listFiles("src/lz4"):
    if f.endsWith(".nim"):
      exec "nim doc " & flags & " " & quoteShell(f)
  exec "nim buildIndex --hints:off -o:htmldocs/theindex.html htmldocs"

task bench, "Run the benchmarks against liblz4":
  exec "nim c -r --hints:off -d:danger bench/bench.nim"

const sanitizers = "-fsanitize=address,signed-integer-overflow,shift"
const asanFlags =
  "-d:danger -d:useMalloc --cc:clang --debugger:native" & " --passC:" & sanitizers &
  " --passC:-fno-sanitize-recover=all" & " --passL:" & sanitizers

task fuzz, "Run the mutation fuzzer for a short time":
  exec "nim c -r --hints:off -d:release fuzz/fuzz_mutate.nim 100000"

task fuzzAsan, "Run the mutation fuzzer built with -d:danger, ASan and UBSan":
  exec "nim c -r --hints:off " & asanFlags & " fuzz/fuzz_mutate.nim 100000"

task fuzzLibFuzzer, "Build the libFuzzer targets in fuzz/ (needs clang)":
  const lf = "-fsanitize=fuzzer,address,signed-integer-overflow,shift"
  for f in listFiles("fuzz"):
    let name = f.extractFilename
    if name.startsWith("lf_") and name.endsWith(".nim"):
      exec "nim c --hints:off --noMain -d:danger -d:useMalloc --cc:clang" &
        " --debugger:native --passC:" & lf &
        " --passC:-fno-sanitize-recover=all --passL:" & lf & " " & quoteShell(f)
