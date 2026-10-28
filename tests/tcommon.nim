import std/unittest
import lz4/private/common

suite "common":
  test "little-endian helpers":
    var b = newSeq[byte](8)
    writeLE16(b, 0, 0xBEEF'u16)
    check b[0] == 0xEF and b[1] == 0xBE
    check readLE16(b, 0) == 0xBEEF'u16
    writeLE32(b, 0, 0x184D2204'u32)
    check b[0 .. 3] == @[0x04'u8, 0x22, 0x4D, 0x18]
    check readLE32(b, 0) == FrameMagic
    writeLE64(b, 0, 0x0102030405060708'u64)
    check b == @[8'u8, 7, 6, 5, 4, 3, 2, 1]
    check readLE64(b, 0) == 0x0102030405060708'u64
    var s: seq[byte]
    s.addLE32(0xDEADBEEF'u32)
    check s == @[0xEF'u8, 0xBE, 0xAD, 0xDE]

  test "raiseLz4 carries the kind":
    try:
      raiseLz4(ekChecksum, "bad")
    except Lz4Error as e:
      check e.kind == ekChecksum
      check e.msg == "bad"

  test "object field defaults (Nim >= 2.0)":
    type O = object
      a: int = 7

    check O().a == 7

  test "setLenNoInit grows within the capacity and beyond it":
    # With refc, Nim's string setLenUninit did not grow within the capacity.
    var s = newStringOfCap(100)
    s.add "abc"
    s.setLenNoInit(50)
    check s.len == 50 and s[0 .. 2] == "abc"
    s.setLenNoInit(2)
    check s == "ab"
    s.setLenNoInit(1000)
    check s.len == 1000 and s[0 .. 1] == "ab"
    var b = newSeqOfCap[byte](100)
    b.add [1'u8, 2, 3]
    b.setLenNoInit(50)
    check b.len == 50 and b[0 .. 2] == @[1'u8, 2, 3]
    # Neither shortening nor growing within the capacity fills the bytes:
    # with refc, Nim before 2.2.8 zero-filled both.
    b.setLenNoInit(1)
    check b == @[1'u8]
    b.setLenNoInit(3)
    check b == @[1'u8, 2, 3]
    b.setLenNoInit(1000)
    check b.len == 1000 and b[0 .. 2] == @[1'u8, 2, 3]
    var e: seq[byte]
    e.setLenNoInit(0)
    check e.len == 0
    e.setLenNoInit(5)
    check e.len == 5
    var o = "xy"
    o.addBytes([1'u8, 2])
    check o == "xy\1\2"

  test "trimCapacity moves only a mostly unused buffer":
    var b = newSeqOfCap[byte](1000)
    b.add [1'u8, 2, 3]
    b.trimCapacity()
    check b == @[1'u8, 2, 3] and b.capacity < 1000
    var s = newStringOfCap(1000)
    s.add "abc"
    s.trimCapacity()
    check s == "abc" and s.capacity < 1000
    var full = newSeqOfCap[byte](1000)
    full.setLen(800)
    let cap = full.capacity
    full.trimCapacity()
    check full.len == 800 and full.capacity == cap
    var e = newSeqOfCap[byte](10)
    e.trimCapacity()
    check e.len == 0
