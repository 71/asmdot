Hacking
=======

Python 3.6 is required to run the scripts, since the scripts make heavy use of the new typing
features added in this release. A type-aware linter such as [mypy](http://mypy-lang.org/) is
thus recommended for editing.

## Structure
- `asmdot/`: Sources of the library.
  * `arch/`: Definition of the supported architectures.
    - `__init__.py`: `Architecture` class, and utilities.
    - `testsource.py`: `TestSource` class, and utilities.
    
    - `arm/`: Definition of the ARM architecture.
      * `__init__.py`:
      * `arch.py`: Parsing `data.txt` to AST.
      * `data.txt`: Definition of all known ARM instructions.
      * `tests.py`: Definition of various ARM tests.
    - `...`
  
  * `__init__.py`: Utilities and useful exported symbols.
  * `ast.py`: Definition of the AST (functions, types, etc).
  * `emit.py`: Base definition of `Emitter`, which transforms the AST into source code.
  * `helpers.py`: Miscellaneous helpers.
  * `options.py`: `Options` class, which is inherited by other classes.

  * `setup.py`: Package definition.
  * `metadata.ini`: Metadata about the package.
  * `requirements.txt`: Requirements to run the source generator.

- `languages/`: Supported languages and generated code.
  * `c/`: Generated C code, and C emitter.
    - `include/`, `src/`, `test/`: Generated code.
    - `generate.py`: C source and tests emitter.
    - `README.md`: C-specific documentation.
  * `...`

- `templates/`: Beginner-friendly templates for creating your own...
  * `arch.py`: ... architecture parser.
  * `lang.py`: ... language emitter.
  * `testsource.py`: ... tests.

- `HACKING.md`: Documentation on the code itself.


## Adding emitters
Emitters are Python modules of the following form, and are used to extend
the build process. They are used to automate the generation of native code
in various languages.

All they have to do is transform the simple AST into source code.

Please see the [languages](./languages) directory for some example emitters. Additionally, a
[beginner-friendly template is available](./templates/lang.py) to easily get
started creating a custom emitter.

The following rules shall be followed when emitting source code:
1. Conventions of the programming language shall be followed.
2. The code shall be readable by a human reader, and shall contain documentation comments.
3. Only the `\n` character shall be written at the end of each line.


## Using the AST
The AST is defined in the [ast.py](./asmdot/ast.py) file, and mostly consists of
the following elements.

#### Function
Every instruction is translated into a function, that itself has a `initname`, `fullname`,
`body`, as well as parameters. `fullname` only changes when a single instruction can take
multiple parameters, and should be used instead of `initname` when a language does not
support overloading. For example, `mov` is the `initname` of both `mov_r32_r32` and `mov_r64_r64`.

Additionally, the `name` property returns the value returned by `Emitter.get_function_name`,
which can be used to transform what a function is named in the scope of the emitter.

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
Manipulation of the IR AST can be seen in the [Rust code generation script](./languages/rust/generate.py).

## Utilities
Many utilities are provided to make scripts easier to create and reason about.

If you see anything you don't know about, please file an issue. In the meantime,
that section is a **TODO**.
