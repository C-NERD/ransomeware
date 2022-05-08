# Package

version       = "0.1.0"
author        = "C-NERD"
description   = "Ransomeware for client"
license       = "Proprietary"
srcDir        = "src"
binDir        = "bin"
bin           = @["ransomeware"]

backend       = "c"

# Dependencies
requires "nim >= 1.0.0", "nimcrypto == 0.5.4", "spinny == 0.3.1"

task make, "compile a release version":
    exec "nimble --gc:orc --d:nimCallDepthLimit=30000 -d:danger -d:release --threads:on build"