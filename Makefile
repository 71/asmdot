CC = gcc
PY = python3.6

BUILD_DIR = build
ADDITIONAL_FLAGS =


# MISC
#
main: build-lib emit

clean:
	rm -rf "$(BUILD_DIR)/"


# EMITTING
#
emit-include:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -o include/ $(ADDITIONAL_FLAGS)
	mv include/arm.c include/arm.h
	mv include/x86.c include/x86.h

emit-src:
	$(PY) src/main.py -a src/arch/*.py -e src/lang/*.py -o dist/ $(ADDITIONAL_FLAGS)

emit: emit-include emit-src


# BUILDING
#
build-lib:
	# Generate C files
	$(PY) src/main.py -a src/arch/*.py -e src/lang/c.py -o "$(BUILD_DIR)"

	# Build object files
	$(CC) -O3 -c "$(BUILD_DIR)/arm.c" -c "$(BUILD_DIR)/x86.c"
	mv arm.o x86.o "$(BUILD_DIR)/"

	# Link the whole thing
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.a" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/x86.o"
	$(CC) -shared -o "$(BUILD_DIR)/asmdot.dll" "$(BUILD_DIR)/arm.o" "$(BUILD_DIR)/x86.o"

build-csharp:
	cd dist/csharp/Asm.Net/ && dotnet build

build-haskell:
	cd dist/haskell/ && cabal build

build-nim:
	cd dist/nim/ && nimble build

build-rust:
	cd dist/rust/ && cargo build

build: build-lib build-csharp build-haskell build-nim build-rust


# TESTING
#
test-csharp: emit-src
	cd dist/csharp/Asm.Net.Tests/ && dotnet test

test-haskell: emit-src
	cd dist/haskell/ && cabal test

test-nim: emit-src
	cd dist/nim/ && nim c -r test/tests.nim

test-python: emit-src
	$(PY) -m pytest test/

test-rust: emit-src
	cd dist/rust/ && cargo test

test: test-csharp test-haskell test-nim test-python test-rust
