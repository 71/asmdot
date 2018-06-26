CC = gcc
PY = python3.6

BUILD_DIR = build
ADDITIONAL_FLAGS =


# MISC
#
main: build-c emit

all: emit-all build test

clean:
	rm -rf "$(BUILD_DIR)/"


# EMITTING
#
emit-include:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -o include/ --no-prefix $(ADDITIONAL_FLAGS)
	mv include/arm.c include/arm.h
	mv include/mips.c include/mips.h
	mv include/x86.c include/x86.h

emit-c:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -t src/test/*.py -o dist/c/ $(ADDITIONAL_FLAGS)

emit-csharp:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/csharp.py -t src/test/*.py -o dist/csharp/ $(ADDITIONAL_FLAGS)

emit-haskell:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/haskell.py -t src/test/*.py -o dist/haskell/ $(ADDITIONAL_FLAGS)

emit-nim:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/nim.py -t src/test/*.py -o dist/nim/ $(ADDITIONAL_FLAGS)

emit-python:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/python.py -t src/test/*.py -o dist/python/ $(ADDITIONAL_FLAGS)

emit-rust:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/rust.py -t src/test/*.py -o dist/rust/ $(ADDITIONAL_FLAGS)

emit-all:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/*.py -t src/test/*.py -o dist/ $(ADDITIONAL_FLAGS)

emit: emit-include emit-all


# BUILDING
#
build-c:
	# Write C files
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -o "$(BUILD_DIR)" --prefix $(ADDITIONAL_FLAGS)

	# Build object files
	$(CC) -O3 -c "$(BUILD_DIR)/arm.c" -c "$(BUILD_DIR)/mips.c" -c "$(BUILD_DIR)/x86.c"
	mv arm.o mips.o x86.o "$(BUILD_DIR)/"

	# Link the whole thing
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.a" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/mips.o" "$(BUILD_DIR)/x86.o"
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.dll" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/mips.o" "$(BUILD_DIR)/x86.o"

build-csharp: emit-csharp
	cd dist/csharp/Asm.Net/ && dotnet build

build-haskell: emit-haskell
	cd dist/haskell/ && cabal build

build-nim: emit-nim
	cd dist/nim/ && nimble build

build-rust: emit-rust
	cd dist/rust/ && cargo build

build: build-c build-csharp build-haskell build-nim build-rust


# TESTING
#
test-c: emit-c
	for arch in arm mips x86 ; do \
			$(CC) -g dist/c/test/$$arch.c -o dist/c/test/$$arch && dist/c/test/$$arch ; \
	done

test-csharp: emit-csharp
	cd dist/csharp/Asm.Net.Tests/ && dotnet test

test-haskell: emit-haskell
	cd dist/haskell/ && cabal test

test-nim: emit-nim
	cd dist/nim/ && nim c -r test/*.nim

test-python: emit-python
	cd dist/python/ && $(PY) -m pytest

test-rust: emit-rust
	cd dist/rust/ && cargo test

test: test-csharp test-haskell test-nim test-python test-rust
