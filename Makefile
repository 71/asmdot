.ONESHELL:

CC = gcc
AR = ar
PY = python3.5

BUILD_DIR   = build
INCLUDE_DIR = include

build-all:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(INCLUDE_DIR)
	$(PY) translate.py -a src/arm.py -a src/x86.py -b src/python.py -b src/csharp.py -o $(INCLUDE_DIR)
	$(CC) -x c -c $(INCLUDE_DIR)/arm.h -c $(INCLUDE_DIR)/x86.h
	mv arm.o x86.o $(BUILD_DIR)
	$(AR) cr $(BUILD_DIR)/asm.a $(BUILD_DIR)/arm.o $(BUILD_DIR)/x86.o

test-all:
	$(CC) -g tests/all.c -o test-all.exe -Wno-incompatible-pointer-types
	./test-all.exe
	rm test-all.exe

clean:
	rm -rf build/
