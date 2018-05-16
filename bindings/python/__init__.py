from cffi import FFI

_ffi = FFI()

def allocate(size: int):
    """
    Returns a (void**, () -> str) tuple that contains a pointer to a pointer to an allocated buffer
    of the given size, and a function that returns the string representation of the buffer.
    """
    assert size > 0

    char_buffer = _ffi.new('char[]', size)
    void_pointer = _ffi.cast('void*', char_buffer)

    return _ffi.new('void**', void_pointer), lambda: _ffi.string(char_buffer)
