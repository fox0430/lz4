## Assertions shared by the unit tests.

import std/unittest
import lz4

template expectKind*(k: Lz4ErrorKind, body: untyped) =
  ## Checks that `body` raises an `Lz4Error` of kind `k`.
  try:
    body
    checkpoint "no error raised"
    fail()
  except Lz4Error as e:
    if e.kind != k:
      checkpoint "got " & $e.kind & ": " & e.msg
    check e.kind == k
