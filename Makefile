.ONESHELL:

CC = clang
AR = ar
PY = python3.5

BUILD_DIR = build

build-all:
	mkdir -p $(BUILD_DIR)
	mkdir -p include
	$(PY) translate.py -a src/arch/*.py -e src/lang/*.py -o $(BUILD_DIR) -u
	cp -r $(BUILD_DIR)/include/ include/
	$(CC) -x c -c include/arm.h -c include/x86.h
	mv arm.o x86.o $(BUILD_DIR)
	$(AR) cr $(BUILD_DIR)/asm.a $(BUILD_DIR)/arm.o $(BUILD_DIR)/x86.o

test-all:
	$(CC) -g tests/all.c -o test-all.exe -Wno-incompatible-pointer-types
	./test-all.exe
	rm test-all.exe

clean:
	rm -rf build/
