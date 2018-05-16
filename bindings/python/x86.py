from cffi import FFI

x86builder = FFI()

x86builder.cdef("int inc_r16(unsigned char, void**);")
x86builder.cdef("int inc_r32(unsigned char, void**);")
x86builder.cdef("int dec_r16(unsigned char, void**);")
x86builder.cdef("int dec_r32(unsigned char, void**);")
x86builder.cdef("int push_r16(unsigned char, void**);")
x86builder.cdef("int push_r32(unsigned char, void**);")
x86builder.cdef("int pop_r16(unsigned char, void**);")
x86builder.cdef("int pop_r32(unsigned char, void**);")
x86builder.cdef("int pop_r64(unsigned char, void**);")
x86builder.cdef("int pushf(void**);")
x86builder.cdef("int popf(void**);")
x86builder.cdef("int ret(void**);")

def loadx86(libpath = "asmdot"): return x86builder.dlopen(libpath)

