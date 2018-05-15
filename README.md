ASM.
====

Providing an extensible Python framework for building a **fast, zero-copy** assembler.

## History and goal

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

## Usage
```
usage: translate.py [-h] -a arch.py -e emitter.py [-p] [-b]
                    [-r {size,success,void}] [-u] [-o OUTPUT-DIR] [-v]
                    [-cc CALLING-CONVENTION]

Generate assembler sources and bindings.

optional arguments:
  -h, --help            Shows a help message that accounts for all chosen
                        architectures and emitters.
  -a, --arch arch.py
                        Use the specified architecture translator.
  -e, --emitter emitter.py
                        Use the specified emitter.
  -p, --prefix          Prefix function names by their architecture.
  -b, --bindings        Generate bindings instead of generating full
                        functions.
  -r, --return {size,success,void}
                        Specify what functions should return.
  -u, --update-pointer  Updates the value of the given pointer by the increase
                        in index in generated functions.
  -o, --output OUTPUT-DIR
                        Change the output directory.
  -v, --verbose

c:
  -cc, --calling-convention CALLING-CONVENTION
                        Specify the calling convention of generated functions.
```

## Status
- Architectures:
  * [ARM](./src/c/arm.c) (generated by [arm.py](./asm/arch/arm.py), **WIP**).
  * [X86](./src/c/x86.c) (generated by [x86.py](./asm/arch/x86.py), **WIP**).
- Sources:
  * [C](./src/c) (generated by [c.py](./asm/lang/c.py)).
  * [C#](./src/csharp) (generated by [csharp.py](./asm/lang/csharp.py)).
  * [Nim](./src/nim) (generated by [nim.py](./asm/lang/nim.py)).
- Bindings:
  * [C](./include) (generated by [c.py](./asm/lang/c.py)).
  * [C#](./bindings/csharp) (generated by [csharp.py](./asm/lang/csharp.py)).
  * [Python](./bindings/python) (generated by [python.py](./asm/lang/python.py)).

## Hacking
Python 3.6 is required to run the scripts, since the scripts make heavy use of the new typing
features added in this release. A type-aware linter such as [mypy](http://mypy-lang.org/) is
thus recommended for editing.

### Structure
```
Data files:     arm.txt   x86.txt
                 ║         ║
Parsers:        arm.py    x86.py
                 ╠═════════╝
                AST
                 ╠═════════╦═══════════╗
Emitters:       c.py      csharp.py   python.py
                 ╠═════════╩═══════════╝
                 ║
                 ╠═════════╦═══════════╦═══════════╦════════╗
Gen. sources:   arm.c     x86.c       arm.py      x86.py   ...
```

- Data files are available in the [data](./asm/data) directory.
- Parsers are available in the [arch](./asm/arch) directory.
- The AST is defined in [ir.py](./asm/ir.py).
- Emitters are available in the [lang](./asm/lang) directory.
- Generated source files are either output to the [bindings](./bindings),
  [src](./src) or [include](./include) directories.

Additionally, the [translate.py](./translate.py) script handles the high-level logic of the source code generation, as well as the CLI. It basically manages the communication from one step to the next.

### Adding instructions
Instructions can be added to the [data files](./asm/data) using a simple language that I hope is self-explanatory.  
Typically, a data file contains a single instruction by line, with a format specific to the
target architecture.

Right now, all ARM instructions have been added. Help on x86 and other architectures would be
appreciated.

### Improving parsers
Parsers transform data files to an AST, line by line. Behind the scenes,
parsers are simple scripts that use [Parsy](https://github.com/python-parsy/parsy) as
well as some internal utilities.

Please see the [arch](./asm/arch) directory for some example parsers.

### Adding emitters
Emitters are Python modules of the following form, and are used to extend
the build process. They are used to automate the generation of native code
in various languages, as well as bindings.

All they have to do is transform the simple AST into source code.

Please see the [lang](./asm/lang) directory for some example emitters.

### Using the AST
The AST is defined in the [ast.py](./src/ast.py) file, and mostly consists of the following elements.

#### Function
Every instruction is translated into a function, that itself has a `name`, `full_name`,
`body`, as well as parameters. `full_name` only changes when a single instruction can take
multiple parameters. For example, `mov` is the `name` of both `mov_r32_r32` and `mov_r64_r64`.

Additionally, the body is a simple list of `Statement`s.

#### Statement
Many kinds of statements exist, and they typically make up the whole body of a function. They
contain other informations, such as variable names, or `Expression`s.

#### Expression
Once again, many kinds of expressions exist. For example, `Binary` expressions have an
operator, as well as left and right operands. There are also `Ternary` expressions,
`Call` expressions, etc. In most cases, a translation from an `Expression` tree to a string
is extremely easy.

#### Example
Manipulation of the IR AST can be seen in the [C code generation script](./asm/lang/c.py).

### Utilities
Many utilities are provided to make scripts easier to create and reason about.

If you see anything you don't know about, please file an issue. In the meantime,
that section is a **TODO**.

## Testing
Tests are available in the [tests](./tests) directory, and mostly consist of Python
scripts that compare generated code to [Capstone](http://www.capstone-engine.org) outputs.

As the structure of the project was recently changed, testing is not yet working.

## Miscellaneous notes

#### `clang` produces more efficient code than `gcc` does for the generated `.c` files
This code...
```c
int uxtab16(char cond, bool rn, bool rd, void* buf) {
    *(int*)buf = 58721120 | cond | (rn ? 4096 : 0) | (rd ? 65536 : 0);
    return 4;
}
```
...produces the following assembly...
```assembly
# With GCC 8.1
uxtab16(char, bool, bool, void*):
  test sil, sil
  movsx eax, dil
  movzx edi, dl
  setne sil
  sal edi, 16
  movzx esi, sil
  sal esi, 12
  or edi, esi
  or edi, eax
  mov eax, 4
  or edi, 58721120
  mov DWORD PTR [rcx], edi
  ret

# With Clang 6.0.0
uxtab16(char, bool, bool, void*):
  shl esi, 12
  shl edx, 16
  or esi, edi
  or esi, edx
  or esi, 58721120
  mov dword ptr [rcx], esi
  mov eax, 4
  ret
```
