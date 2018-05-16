.ONESHELL:

CC = clang
PY = python3.6

BUILD_DIR = build
ADDITIONAL_FLAGS =

main: build

emit-include:
	$(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/c.py" -o "include/" -u $(ADDITIONAL_FLAGS)
	mv "include/arm.c" "include/arm.h"
	mv "include/x86.c" "include/x86.h"

emit-src:
	$(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/c.py" -e "asm/lang/csharp.py" -e "asm/lang/nim.py" -o "src/" -u $(ADDITIONAL_FLAGS)

emit-bindings:
	$(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/python.py" -e "asm/lang/c.py" -o "bindings/" --bindings -u $(ADDITIONAL_FLAGS)

build:
	# Generate C files
	$(PY) translate.py -a "asm/arch/*.py" -e "asm/lang/c.py" -o "$(BUILD_DIR)" -u

	# Build object files
	$(CC) -x c -c "$(BUILD_DIR)/arm.c" -c "$(BUILD_DIR)/x86.c"
	mv arm.o x86.o "$(BUILD_DIR)/"

	# Link the whole thing
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.a" "$(BUILD_DIR)/*.o"
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.dll" "$(BUILD_DIR)/*.o"

emit: emit-include emit-src emit-bindings

test: emit-bindings build
	$(PY) -m pytest tests/

clean:
	rm -rf "$(BUILD_DIR)/"
