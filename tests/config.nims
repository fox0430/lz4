switch("path", "$projectDir/../src")
# Optimise the tests but keep every runtime check (bounds, ranges, overflow):
# an IndexDefect or RangeDefect in the library is a bug the tests must catch.
switch("opt", "speed")

# The link flags of tests/clz4.nim (default -llz4). CI points this at a
# static liblz4.a so that the system liblz4.so is not picked up instead.
if existsEnv("CLZ4_LINK"):
  switch("define", "clz4Link=" & getEnv("CLZ4_LINK"))
