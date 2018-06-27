ASM.
====

Providing an extensible Python framework for building a **fast, zero-copy** assembler.


## History and goals

This project originally aimed to create a fast, minimalist and unopinionated assembler in C
that could live in a single file, and support multiple architectures.

Thus, a Python library was built to transform various instructions from different architectures
into a simple, common AST that supports bitwise and logical expressions, basic flow control
and variables into C code.  
Since code would be generated automatically, other options such as naming conventions and parameter
types could be easily modified when generating it.

However, I soon realized that, since a complete AST was built, it could be easily to extend this
process to not only support C, but also other programming languages.  
At first, the goal was thus to produce bindings to the C API, which is *very* efficient; but since a
complete AST was built anyway, and that a mechanism already existed to distinguish source files and
include files, I decided to make the whole process available in different languages.

As such, ASM. was born. **Parsers** transform data files that define instructions in various architectures
to an AST, which is then transformed by **emitters** into source code in various programming languages.

### Goals and non-goals
- **ASM. is a lightweight assembler library. It is designed to be as simple as possible.**
- **ASM. has no support for labels or macros**: developers are expected to build their own
  interface on top of the provided functions.
- **ASM. is not a binary, it's a library**. You cannot use it directly.
- **ASM. has no built-in parser**: if you want an assembler that works with arbitrary strings, use
  [Keystone](https://www.keystone-engine.org).
- **ASM. has different instructions for different architectures**: if you want a common
  interface for all architectures, use [GNU Lightning](https://www.gnu.org/software/lightning)
  or [libjit](https://www.gnu.org/software/libjit).


## Usage

### Using `make`
A [Makefile](./Makefile) is provided to automate most tasks, including generating sources,
as well as building and testing every generated library.

The `emit`, `build` and `test` recipes are made available, and invoke all language-specific
recipes that are defined. To execute tasks in a language-specific manner, the recipes
`emit-lang`, `build-lang`, and `test-lang` are also available, where `lang` is either one
of these values:
- `c` (uses any C compiler).
- `csharp` (uses `dotnet`).
- `haskell` (uses `cabal`).
- `nim` (uses `nimble`).
- `python` (uses `pytest`).
- `rust` (uses `cargo`).

### Generating the sources
Each language directory contains a `generate.py` file, which can be directly invoked
from the command line.

Here is an example output of the C generation script:
```
usage: generate.py [-h] [-ns] [-nt] [-o output-dir/] [-v] [-np] [-ah]
                   [-cc CALLING-CONVENTION]

Generate ASM. sources.

optional arguments:
  -h, --help            Show the help message.
  -ns, --no-sources     Do not generate sources.
  -nt, --no-tests       Do not generate tests.
  -o output-dir/, --output output-dir/
                        Change the output directory (default: directory of
                        calling emitter).
  -v, --verbose         Increase verbosity (can be given multiple times to
                        increase it further).

C:
  -np, --no-prefix      Do not prefix function names by their architecture.
  -ah, --as-header      Generate headers instead of regular files.

  -cc CALLING-CONVENTION, --calling-convention CALLING-CONVENTION
                        Specify the calling convention of generated functions.
```

### Using the C API
```c
#include "./x86.h"

void* buffer = malloc(0xff);
void* origin = buffer;

inc_r32(&buffer, eax);
ret(&buffer);

free(origin);
```

### Using the Nim API
```nim
# The Nim language goes very well with ASM., thanks to its UFCS support.
import asmdot/x86

var
  bytes = newSeqOfCap[byte](10)
  buf = addr bytes[0]

buf.inc(eax)
buf.ret()
```

### Using the Python API
```python
from asm.x86 import Reg32, X86Assembler

asm = X86Assembler(10)

asm.inc_r32(Reg32.eax)
asm.ret()
```

### Using the Rust API
```rust
use asm::x86::{Register32, X86Assembler};

let mut buf = vec!();

buf.inc_r32(Register32::EAX)?;
buf.ret()?;
```


## Installing
We're not there yet, but if you want to experiment with the project or contribute,
you're welcome to clone it and play around.

```bash
# Clone project
git clone https://github.com/6A/asmdot.git

# Get dependencies
python -m pip install -r asmdot/requirements.txt

# Play around
python languages/c/generate.py --help

# Optional: get the test runner and run tests
python -m pip install pytest && make test-python
```


## Docs
Documentation is available in the [docs](./docs) directory.


## Status
- Architectures:
  * [ARM](./asmdot/arch/arm): **WIP**.
  * [MIPS](./asmdot/arch/mips): **WIP**.
  * [X86](./asmdot/arch/x86): **WIP**.

- Sources:
  * [C](./languages/c).
  * [C#](./languages/csharp)
  * [Haskell](./languages/haskell) 
  * [Nim](./languages/nim)
  * [Python](./languages/python)
  * [Rust](./languages/rust)


## License
All the content of the repository is [MIT-licensed](./LICENSE.md), except the [data](./src/data)
directory which is [Unlicensed](http://unlicense.org).
