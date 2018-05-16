import ctypes
from typing import Callable, Tuple

voidptr = ctypes.c_void_p
voidptrptr = ctypes.POINTER(voidptr)

def allocate(size: int) -> Tuple[ctypes.pointer, Callable[[], bytes]]:
    """
    Returns a (void**, () -> str) tuple that contains a pointer to a pointer to an allocated buffer
    of the given size, and a function that returns the string representation of the buffer.
    """
    assert size > 0

    char_buffer = ctypes.create_string_buffer(size)
    void_pointer = ctypes.cast(char_buffer, voidptr)

    return ctypes.pointer(void_pointer), lambda: ctypes.string_at(char_buffer)
