switch("path", "$projectDir/../src")
switch("path", "$projectDir/../tests")
if existsEnv("CLZ4_LINK"):
  switch("define", "clz4Link=" & getEnv("CLZ4_LINK"))
