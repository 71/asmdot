ASM²
====

This repository contains tools written in Python that aim
to produce the source code of a minimalist and efficient assembler,
as well as bindings to said assembler to other languages.

This is currently a WIP, and nothing is expected to work.

## Usage
```
usage: .\translate.py [-h] [--x86] [--arm] [-p] [-nb] [-r {size,success,void}]
                      [-o OUTPUT] [-cc CALLING_CONVENTION]
                      [-b [BINDER [BINDER ...]]]

Generate assembler source.

optional arguments:
  -h, --help            show this help message and exit
  --x86                 generate x86 sources
  --arm                 generate arm sources
  -p, --prefix          prefix methods by their architecture
  -nb, --no-body        do not generate bodies
  -r {size,success,void}, --return {size,success,void}
                        change what functions return
  -o OUTPUT, --output OUTPUT
                        change the output dir
  -cc CALLING_CONVENTION, --calling-convention CALLING_CONVENTION
                        change the calling convention
  -b [BINDER [BINDER ...]], --binder [BINDER [BINDER ...]]
                        use the given binder
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
Translators transform data files to C code, line by line.

### Adding binders
Binders, defined in the [bind](./src/bind) directory, are Python classes
that can be added to the build process to extend it.  
They all inherit the `Binder` class, and are notified when a new function is
defined, giving them the opportunity to generate code for this specific function.
