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
	$(PY) languages/c/generate.py -o languages/c/ --no-prefix --as-header $(ADDITIONAL_FLAGS)

emit-c:
	$(PY) languages/c/generate.py -o languages/c/ $(ADDITIONAL_FLAGS)

emit-csharp:
	$(PY) languages/csharp/generate.py -o languages/csharp/ $(ADDITIONAL_FLAGS)

emit-haskell:
	$(PY) languages/haskell/generate.py -o languages/haskell/ $(ADDITIONAL_FLAGS)

emit-nim:
	$(PY) languages/nim/generate.py -o languages/nim/ $(ADDITIONAL_FLAGS)

emit-python:
	$(PY) languages/python/generate.py -o languages/python/ $(ADDITIONAL_FLAGS)

emit-rust:
	$(PY) languages/rust/generate.py -o languages/rust/ $(ADDITIONAL_FLAGS)

emit: emit-include emit-c emit-csharp emit-haskell emit-nim emit-python emit-rust


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
