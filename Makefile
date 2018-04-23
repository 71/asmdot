.ONESHELL:

CC = gcc
AR = ar
PY = python3.5

build-all:
	mkdir -p build/
	$(PY) translate.py -a src/arm.py -a src/x86.py -b src/python.py -b src/csharp.py -o build
	cd build/
	$(CC) -x c -c arm.h -c x86.h
	$(AR) cr asm.a arm.o x86.o
	cd ..

clean:
	rm -rf build/
