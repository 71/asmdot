from cffi import FFI

ffi = FFI()

ffi.cdef("bool inc_r16(reg16, void*);")
ffi.cdef("bool inc_r32(reg32, void*);")
ffi.cdef("bool dec_r16(reg16, void*);")
ffi.cdef("bool dec_r32(reg32, void*);")
ffi.cdef("bool push_r16(reg16, void*);")
ffi.cdef("bool push_r32(reg32, void*);")
ffi.cdef("bool pop_r16(reg16, void*);")
ffi.cdef("bool pop_r32(reg32, void*);")
ffi.cdef("bool pop_r64(reg64, void*);")
ffi.cdef("bool pushf(void*);")
ffi.cdef("bool popf(void*);")
ffi.cdef("bool ret(void*);")
