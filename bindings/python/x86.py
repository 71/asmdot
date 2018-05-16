from cffi import FFI

ffi = FFI()

ffi.cdef("int x86_inc_r16(reg16, void**);")
ffi.cdef("int x86_inc_r32(reg32, void**);")
ffi.cdef("int x86_dec_r16(reg16, void**);")
ffi.cdef("int x86_dec_r32(reg32, void**);")
ffi.cdef("int x86_push_r16(reg16, void**);")
ffi.cdef("int x86_push_r32(reg32, void**);")
ffi.cdef("int x86_pop_r16(reg16, void**);")
ffi.cdef("int x86_pop_r32(reg32, void**);")
ffi.cdef("int x86_pop_r64(reg64, void**);")
ffi.cdef("int x86_pushf(void**);")
ffi.cdef("int x86_popf(void**);")
ffi.cdef("int x86_ret(void**);")
