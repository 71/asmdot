from cffi import FFI

ffi = FFI()
ffi.cdef("bool x86_ret(void**);")
