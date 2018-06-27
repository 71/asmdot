CC = gcc
PY = python3.6

BUILD_DIR = build
ADDITIONAL_FLAGS =

export PYTHONPATH = .


# MISC
#
main: build-c emit

all: emit-all build test

clean:
	rm -rf "$(BUILD_DIR)/"


# EMITTING
#
emit-include:
	$(PY) languages/c/generate.py -o languages/c/include/ --no-prefix --as-header --no-tests $(ADDITIONAL_FLAGS)

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
	$(PY) languages/c/generate.py --no-tests -o "$(BUILD_DIR)"

	# Build object files
	cd "$(BUILD_DIR)" && $(CC) -O3 -c arm.c -c mips.c -c x86.c

	# Link the whole thing
	cd "$(BUILD_DIR)" && $(CC) -shared -o asmdot.a arm.o mips.o x86.o

build-csharp: emit-csharp
	cd languages/csharp/Asm.Net/ && dotnet build

build-haskell: emit-haskell
	cd languages/haskell/ && cabal build

build-nim: emit-nim
	cd languages/nim/ && nimble build

build-rust: emit-rust
	cd languages/rust/ && cargo build

build: build-c build-csharp build-haskell build-nim build-rust


# TESTING
#
test-c: emit-c
	for arch in arm mips x86 ; do \
		$(CC) -g languages/c/test/$$arch.c -o languages/c/test/$$arch && languages/c/test/$$arch ; \
	done

test-csharp: emit-csharp
	cd languages/csharp/Asm.Net.Tests/ && dotnet test

test-haskell: emit-haskell
	cd languages/haskell/ && cabal test

test-nim: emit-nim
	cd languages/nim/ && nim c -r test/*.nim

test-python: emit-python
	cd languages/python/ && $(PY) -m pytest

test-rust: emit-rust
	cd languages/rust/ && cargo test

test: test-csharp test-haskell test-nim test-python test-rust
