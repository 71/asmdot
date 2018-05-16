import ctypes
from . import voidptr, voidptrptr

def load_x86(lib: str = "asmdot"):
    """Loads the ASM. library using the provided path, and returns a wrapper around the x86 architecture."""
    asm = ctypes.cdll.LoadLibrary(lib)

    asm.inc_r16.restype = ctypes.c_byte
    asm.inc_r16.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.inc_r32.restype = ctypes.c_byte
    asm.inc_r32.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.dec_r16.restype = ctypes.c_byte
    asm.dec_r16.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.dec_r32.restype = ctypes.c_byte
    asm.dec_r32.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.push_r16.restype = ctypes.c_byte
    asm.push_r16.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.push_r32.restype = ctypes.c_byte
    asm.push_r32.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.pop_r16.restype = ctypes.c_byte
    asm.pop_r16.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.pop_r32.restype = ctypes.c_byte
    asm.pop_r32.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.pop_r64.restype = ctypes.c_byte
    asm.pop_r64.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.pushf.restype = ctypes.c_byte
    asm.pushf.argtypes = [ voidptrptr ]

    asm.popf.restype = ctypes.c_byte
    asm.popf.argtypes = [ voidptrptr ]

    asm.ret.restype = ctypes.c_byte
    asm.ret.argtypes = [ voidptrptr ]

    return asm