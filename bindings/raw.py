from cffi import FFI

ffi = FFI()
ffi.cdef("bool ret(void**);")