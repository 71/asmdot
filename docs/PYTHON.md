Python
======

# Performances
On May 19th, 2018, it was decided that Python would no longer use bindings
to the C library, but instead directly generate code by itself.

This choice was taken because it appears that in most cases, the overhead added
by performing FFI outweights the performance improvements of using C instead of Python.

For reference, the following code was used to benchmark both alternatives.

```python
from bindings.python import voidptr
from bindings.python.arm import load_arm, Mode
from bindings.python.x86 import load_x86, Reg32

import struct

# Raw translation of the Nim source code (right now, only bindings are generated for Python).
class Assembler:
    def __init__(self, size: int) -> None:
        self.size = size
        self.buf = bytearray(size)
        self.pos = 0
    
    def cps(self, mode: Mode) -> None:
        mode = mode.value

        struct.pack_into('<I', self.buf, self.pos, 4043440128 or mode)
        self.pos += 4

    def inc_r32(self, operand: Reg32) -> None:
        operand = operand.value

        if operand > 7:
            self.buf[self.pos] = 65
            self.pos += 1

        self.buf[self.pos] = 64 + operand
        self.pos += 1

if __name__ == '__main__':
    # ARM benchmark:
    #   Encode a single instruction into a buffer 50,000 times.
    #   Every 50 iteration, reset the pointer to the start of the buffer.
    #
    # x86 benchmark:
    #   Encode a single instruction into a buffer 100,000 times.
    #   Every 100 iteration, reset the pointer to the start of the buffer.
    
    import ctypes, time

    arm = load_arm()
    x86 = load_x86()
    eax = Reg32(0x0)
    usr = Mode.USR

    # FFI time
    char_buffer = ctypes.create_string_buffer(256)
    void_pointer = ctypes.cast(char_buffer, voidptr)

    buf = ctypes.pointer(void_pointer)

    start_time = time.perf_counter()

    for i in range(1000):
        for j in range(100):
            x86.inc_r32(buf, eax)

        buf = ctypes.pointer(void_pointer)

    print('FFI x86 time:', time.perf_counter() - start_time)

    buf = ctypes.pointer(void_pointer)
    start_time = time.perf_counter()

    for i in range(1000):
        for j in range(50):
            arm.cps(buf, usr)

        buf = ctypes.pointer(void_pointer)

    print('FFI ARM time:', time.perf_counter() - start_time)

    # Pure Python time
    assembler = Assembler(256)
    start_time = time.perf_counter()

    for i in range(1000):
        for j in range(100):
            assembler.inc_r32(eax)
        
        assembler.pos = 0

    print('Python x86 time:', time.perf_counter() - start_time)

    start_time = time.perf_counter()

    for i in range(1000):
        for j in range(50):
            assembler.cps(usr)
        
        assembler.pos = 0
    
    print('Python ARM time:', time.perf_counter() - start_time)
```

Results:
| Implementation | Architecture | Time                |
| -------------- | ------------ | ------------------- |
| FFI            | ARM          | 0.04635770555265187 |
| Pure Python    | ARM          | 0.05121554772057621 |
| FFI            | x86          | 0.0714547106012631  |
| Pure Python    | x86          | 0.0478309351130789  |
