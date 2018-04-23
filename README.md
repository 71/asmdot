ASM²
====

This repository contains tools written in Python that aim
to produce the source code of a minimalist and efficient assembler,
as well as bindings to said assembler to other languages.

This is currently a WIP, and nothing is expected to work.

## Usage
```
usage: translate.py [-h] [-b lang.py] -a arch.py [-p] [-nb]
                    [-r {size,success,void}] [-o OUTPUT-DIR]
                    [-cc CALLING-CONVENTION]

Generate assembler sources and bindings.

Optional arguments:
  -h, --help                     Show this help message and exit.
  -b lang.py, --binder lang.py   Use the specified bindings generator.
  -a arch.py, --arch arch.py     Use the specified architecture translator.
  -p, --prefix                   Prefix function names by their architecture.
  -nb, --no-body                 Do not generate function bodies, thus only generating
                                 function signatures.
  -r {size,success,void}         Specify what functions should return.
  -o                             Change the output directory (default: ./build/)
  -cc CALLING-CONVENTION         Specify the calling convention of generated functions.
```

## Structure
- Data files are available in the [instructions](./instructions) directory.
- Script files that convert data files to c files are available in the [src](./src) directory.
- The [common.py](./src/common.py) file contains tools used by all translators for their execution,
  as well as most of the logic.
- The [translate.py](./translate.py) file provides a wrapper around the script.

## Hacking

### Adding instructions
Instructions can be added to the data files using a simplelanguage that I hope is self-explanatory.  
Typically, a data file contains a single instruction by line, with a format specific to the
target architecture.

### Improving translators
Translators transform data files to C code, line by line. Behind the scenes,
translators are simple scripts that use [PLY](https://github.com/dabeaz/ply) to
parse instructions and produce C code from it.  
The following snippet shows the minimum code required to create a translator.

```python
from common import *

lexer = make_lexer()
parser = make_parser()

@translator('arch')
def translate(input, output):
    for line in input:
        if line == "":
            continue

        ouput.write( parser.parse(line, lexer=lexer) )
```

### Adding binders
Binders are Python modules of the following form, and are used to extend
the build process. They are mostly used to automatically generate bindings
to the C library.

```python
from common import *

output = None

@architecture_entered
def enter(arch):
    global output

    output = open('bindings/lang/filename', 'w')
    output.write("""# Header...""")

@architecture_left
def leave(arch):
    output.close()

@function_defined
def define(name, params):
    output.write('# Function defined: {}.'.format(name))
```
