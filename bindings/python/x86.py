import ctypes
from . import voidptr, voidptrptr

def load_x86(lib: str = "asmdot"):
    """Loads the ASM. library using the provided path, and returns a wrapper around the x86 architecture."""
    asm = ctypes.cdll.LoadLibrary(lib)

    asm.inc_r16.restype = None
    asm.inc_r16.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.inc_r32.restype = None
    asm.inc_r32.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.dec_r16.restype = None
    asm.dec_r16.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.dec_r32.restype = None
    asm.dec_r32.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.push_r16.restype = None
    asm.push_r16.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.push_r32.restype = None
    asm.push_r32.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.pop_r16.restype = None
    asm.pop_r16.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.pop_r32.restype = None
    asm.pop_r32.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.pop_r64.restype = None
    asm.pop_r64.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.pushf.restype = None
    asm.pushf.argtypes = [ voidptrptr ]

    asm.popf.restype = None
    asm.popf.argtypes = [ voidptrptr ]

    asm.ret.restype = None
    asm.ret.argtypes = [ voidptrptr ]

    return asm