.ONESHELL:

CC ?= clang
AR = ar
PY = python3.5

BUILD_DIR = build
ADDITIONAL_FLAGS =

main: build-c

build-c:
    # Generate C files
    $(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/c.py" -o "$(BUILD_DIR)" -u

    # Build object files
    $(CC) -x c -c "$(BUILD_DIR)/arm.c" -c "$(BUILD_DIR)/x86.c"
    mv arm.o x86.o "$(BUILD_DIR)/"

    # Link the whole thing
    $(AR) cr "$(BUILD_DIR)/asmdot.a" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/x86.o"

emit-git:
    # Build include/
    $(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/c.py" -o "include/" $(ADDITIONAL_FLAGS)
    mv "include/arm.c" "include/arm.h"
    mv "include/x86.c" "include/x86.h"

    # Build sources
    $(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/c.py" -e "asm/lang/csharp.py" -e "asm/lang/nim.py" -o "src/" $(ADDITIONAL_FLAGS)

    # Build bindings
    $(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/python.py" -e "asm/lang/c.py" -o "bindings/" --bindings $(ADDITIONAL_FLAGS)

test:
    $(PY) -m pytest "tests/all.py"

clean:
    rm -rf "$(BUILD_DIR)/"
