import ctypes
from . import voidptr, voidptrptr
from enum import Enum, Flag

Reg8 = ctypes.c_uint8

Reg16 = ctypes.c_uint8

Reg32 = ctypes.c_uint8

Reg64 = ctypes.c_uint8

Reg128 = ctypes.c_uint8

def load_x86(lib: str = "asmdot"):
    """Loads the ASM. library using the provided path, and returns a wrapper around the x86 architecture."""
    asm = ctypes.cdll.LoadLibrary(lib)

    asm.inc_r16.restype = None
    asm.inc_r16.argtypes = [ voidptrptr, Reg16 ]
    asm.inc_r16.__doc__ = "Emits an 'inc' instruction."

    asm.inc_r32.restype = None
    asm.inc_r32.argtypes = [ voidptrptr, Reg32 ]
    asm.inc_r32.__doc__ = "Emits an 'inc' instruction."

    asm.dec_r16.restype = None
    asm.dec_r16.argtypes = [ voidptrptr, Reg16 ]
    asm.dec_r16.__doc__ = "Emits a 'dec' instruction."

    asm.dec_r32.restype = None
    asm.dec_r32.argtypes = [ voidptrptr, Reg32 ]
    asm.dec_r32.__doc__ = "Emits a 'dec' instruction."

    asm.push_r16.restype = None
    asm.push_r16.argtypes = [ voidptrptr, Reg16 ]
    asm.push_r16.__doc__ = "Emits a 'push' instruction."

    asm.push_r32.restype = None
    asm.push_r32.argtypes = [ voidptrptr, Reg32 ]
    asm.push_r32.__doc__ = "Emits a 'push' instruction."

    asm.pop_r16.restype = None
    asm.pop_r16.argtypes = [ voidptrptr, Reg16 ]
    asm.pop_r16.__doc__ = "Emits a 'pop' instruction."

    asm.pop_r32.restype = None
    asm.pop_r32.argtypes = [ voidptrptr, Reg32 ]
    asm.pop_r32.__doc__ = "Emits a 'pop' instruction."

    asm.pop_r64.restype = None
    asm.pop_r64.argtypes = [ voidptrptr, Reg64 ]
    asm.pop_r64.__doc__ = "Emits a 'pop' instruction."

    asm.pushf.restype = None
    asm.pushf.argtypes = [ voidptrptr ]
    asm.pushf.__doc__ = "Emits a 'pushf' instruction."

    asm.popf.restype = None
    asm.popf.argtypes = [ voidptrptr ]
    asm.popf.__doc__ = "Emits a 'popf' instruction."

    asm.ret.restype = None
    asm.ret.argtypes = [ voidptrptr ]
    asm.ret.__doc__ = "Emits a 'ret' instruction."

    return asm
