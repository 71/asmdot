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

### Generating the sources
```
Usage: main.py [-h] [-v] -a arch.py -e emitter.py
               [-o output/]

Generate assembler sources and bindings.

Optional arguments:
  -h, --help                Shows a help message that accounts for all chosen
                            architectures and emitters.
  -v, --verbose             Increase verbosity.

  -a, --arch arch.py        Use the specified architecture parser.
  -e, --emitter emitter.py  Use the specified emitter.

  -o, --output output/      Change the output directory.

C:
  -p, --prefix          Prefix function names by their architecture.
  -cc, --calling-convention CALLING-CONVENTION
                        Specify the calling convention of generated functions.
```

### Using the C API
```c
#include "./include/x86.h"

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
python -m pip install -r src/requirements.txt

# Play around
python src/main.py --help

# Optional: get the test runner
python -m pip install pytest

# Optional: run tests
make test-python
```


## Docs
Documentation is available in the [docs](./docs) directory.


## Status
- Architectures:
  * [ARM](./src/data/arm.txt) (parsed by [arm.py](./src/arch/arm.py), **WIP**).
  * [X86](./src/data/x86.txt) (parsed by [x86.py](./src/arch/x86.py), **WIP**).

- Sources:
  * [C](./dist/c) (generated by [c.py](./src/lang/c.py)).
  * [C#](./dist/csharp) (generated by [csharp.py](./src/lang/csharp.py)).
  * [Haskell](./dist/haskell) (generated by [haskell.py](./src/lang/haskell.py)).
  * [Nim](./dist/nim) (generated by [nim.py](./src/lang/nim.py)).
  * [Python](./dist/python) (generated by [python.py](./src/lang/python.py)).
  * [Rust](./dist/rust) (generated by [rust.py](./src/lang/rust.py)).


## License
All the content of the repository is [MIT-licensed](./LICENSE.md), except the [data](./src/data)
directory which is [Unlicensed](http://unlicense.org).
