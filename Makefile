CC = gcc
PY = python3.6

BUILD_DIR = build
ADDITIONAL_FLAGS =

main: build emit

emit-include:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -o include/ $(ADDITIONAL_FLAGS)
	mv include/arm.c include/arm.h
	mv include/x86.c include/x86.h

emit-src:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/*.py -o dist/ $(ADDITIONAL_FLAGS)

build:
	# Generate C files
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -o "$(BUILD_DIR)"

	# Build object files
	$(CC) -O3 -c "$(BUILD_DIR)/arm.c" -c "$(BUILD_DIR)/x86.c"
	mv arm.o x86.o "$(BUILD_DIR)/"

	# Link the whole thing
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.a" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/x86.o"
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.dll" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/x86.o"

emit: emit-include emit-src

test: emit-src
	$(PY) -m pytest test/

clean:
	rm -rf "$(BUILD_DIR)/"
