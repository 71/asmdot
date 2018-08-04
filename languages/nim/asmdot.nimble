# Package

version       = "0.1.0"
author        = "Grégoire Geis"
description   = "Lightweight and fast assembler for ARM and x86."
license       = "MIT"
skipDirs      = @[ "test" ]

# Dependencies

requires "nim >= 0.17.0"

# Tasks

task debug, "Compiles the project in debug mode.":
  exec "nim c -d:debug asmdot/arm.nim"
  exec "nim c -d:debug asmdot/mips.nim"
  exec "nim c -d:debug asmdot/x86.nim"

task release, "Compiles the project in release mode.":
  exec "nim c -d:release asmdot/arm.nim"
  exec "nim c -d:release asmdot/mips.nim"
  exec "nim c -d:release asmdot/x86.nim"

task test, "Run tests in debug mode.":
  exec "nim c -d:debug -r test/testall.nim"
