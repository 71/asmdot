.ONESHELL:

CC = gcc
AR = ar
PY = python3.5

build-all:
	mkdir -p build/
	$(PY) translate.py --prefix --arm --x86 --output build
	cd build/
	$(CC) -x c -c arm.h -c x86.h
	$(AR) cr asm.a arm.o x86.o
	cd ..

clean:
	rm -rf build/
