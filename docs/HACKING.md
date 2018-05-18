Hacking
=======

Python 3.6 is required to run the scripts, since the scripts make heavy use of the new typing
features added in this release. A type-aware linter such as [mypy](http://mypy-lang.org/) is
thus recommended for editing.

## Structure
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

- Data files are available in the [data](../asm/data) directory.
- Parsers are available in the [arch](../asm/arch) directory.
- The AST is defined in [ast.py](../asm/ast.py).
- Emitters are available in the [lang](../asm/lang) directory.
- Generated source files are either output to the [bindings](../bindings),
  [src](../src) or [include](../include) directories.

Additionally, the [translate.py](../translate.py) script handles the high-level logic of the source code generation, as well as the CLI. It basically manages the communication from one step to the next.

## Adding instructions
Instructions can be added to the [data files](../asm/data) using a simple language that I hope is self-explanatory.  
Typically, a data file contains a single instruction by line, with a format specific to the
target architecture.

Right now, all ARM instructions have been added. Help on x86 and other architectures would be
appreciated.

## Improving parsers
Parsers transform data files to an AST, line by line. Behind the scenes,
parsers are simple scripts that use [Parsy](https://github.com/python-parsy/parsy) as
well as some internal utilities.

Please see the [arch](../asm/arch) directory for some example parse.

Note that instruction formats between all architectures are **different**; thus all parsers
behave differently, and do not follow specific rules.

## Adding emitters
Emitters are Python modules of the following form, and are used to extend
the build process. They are used to automate the generation of native code
in various languages, as well as bindings.

All they have to do is transform the simple AST into source code.

Please see the [lang](../asm/lang) directory for some example emitters.

The following rules shall be followed when emitting source code:
1. Conventions of the programming language shall be followed.
2. The code shall be readable by a human reader, and shall contain documentation comments.
3. Only the `\n` character shall be written at the end of each line.

## Using the AST
The AST is defined in the [ast.py](../asm/ast.py) file, and mostly consists of the following elements.

#### Function
Every instruction is translated into a function, that itself has a `name`, `full_name`,
`body`, as well as parameters. `full_name` only changes when a single instruction can take
multiple parameters. For example, `mov` is the `name` of both `mov_r32_r32` and `mov_r64_r64`.

Additionally, the body is a simple list of `Statement`s.

#### Declaration
Declarations are top-level elements used by the functions generated for an architecture.

Currently, the only existing declaration is the `Enumeration`, which contains enumeration
members and can be translated to many languages.

#### Statement
Many kinds of statements exist, and they typically make up the whole body of a function. They
contain other informations, such as variable names, or `Expression`s.

#### Expression
Once again, many kinds of expressions exist. For example, `Binary` expressions have an
operator, as well as left and right operands. There are also `Ternary` expressions,
`Call` expressions, etc. In most cases, a translation from an `Expression` tree to a string
is extremely easy.


#### Example
Manipulation of the IR AST can be seen in the [C code generation script](../asm/lang/c.py).

## Utilities
Many utilities are provided to make scripts easier to create and reason about.

If you see anything you don't know about, please file an issue. In the meantime,
that section is a **TODO**.
