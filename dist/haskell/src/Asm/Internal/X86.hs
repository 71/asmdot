module Asm.Internal.X86 where

import Data.IORef
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

-- | An x86 8-bits register.
newtype Reg8 = Reg8 uint8

al, cl, dl, bl, spl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b :: Reg8
al = Reg8 0
cl = Reg8 1
dl = Reg8 2
bl = Reg8 3
spl = Reg8 4
bpl = Reg8 5
sil = Reg8 6
dil = Reg8 7
r8b = Reg8 8
r9b = Reg8 9
r10b = Reg8 10
r11b = Reg8 11
r12b = Reg8 12
r13b = Reg8 13
r14b = Reg8 14
r15b = Reg8 15


-- | An x86 16-bits register.
newtype Reg16 = Reg16 uint8

ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w :: Reg16
ax = Reg16 0
cx = Reg16 1
dx = Reg16 2
bx = Reg16 3
sp = Reg16 4
bp = Reg16 5
si = Reg16 6
di = Reg16 7
r8w = Reg16 8
r9w = Reg16 9
r10w = Reg16 10
r11w = Reg16 11
r12w = Reg16 12
r13w = Reg16 13
r14w = Reg16 14
r15w = Reg16 15


-- | An x86 32-bits register.
newtype Reg32 = Reg32 uint8

eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d :: Reg32
eax = Reg32 0
ecx = Reg32 1
edx = Reg32 2
ebx = Reg32 3
esp = Reg32 4
ebp = Reg32 5
esi = Reg32 6
edi = Reg32 7
r8d = Reg32 8
r9d = Reg32 9
r10d = Reg32 10
r11d = Reg32 11
r12d = Reg32 12
r13d = Reg32 13
r14d = Reg32 14
r15d = Reg32 15


-- | An x86 64-bits register.
newtype Reg64 = Reg64 uint8

rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15 :: Reg64
rax = Reg64 0
rcx = Reg64 1
rdx = Reg64 2
rbx = Reg64 3
rsp = Reg64 4
rbp = Reg64 5
rsi = Reg64 6
rdi = Reg64 7
r8 = Reg64 8
r9 = Reg64 9
r10 = Reg64 10
r11 = Reg64 11
r12 = Reg64 12
r13 = Reg64 13
r14 = Reg64 14
r15 = Reg64 15


-- | An x86 128-bits register.
newtype Reg128 = Reg128 uint8

inc_r16 :: IORef (Ptr ()) -> Reg16 -> IO ()
inc_r16 bufref operand = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (102 + get_prefix operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (64 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


inc_r32 :: IORef (Ptr ()) -> Reg32 -> IO ()
inc_r32 bufref operand = do
    if (operand > 7) then
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 65
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (64 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


dec_r16 :: IORef (Ptr ()) -> Reg16 -> IO ()
dec_r16 bufref operand = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (102 + get_prefix operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (72 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


dec_r32 :: IORef (Ptr ()) -> Reg32 -> IO ()
dec_r32 bufref operand = do
    if (operand > 7) then
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 65
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (72 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


push_r16 :: IORef (Ptr ()) -> Reg16 -> IO ()
push_r16 bufref operand = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (102 + get_prefix operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (80 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


push_r32 :: IORef (Ptr ()) -> Reg32 -> IO ()
push_r32 bufref operand = do
    if (operand > 7) then
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 65
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (80 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


pop_r16 :: IORef (Ptr ()) -> Reg16 -> IO ()
pop_r16 bufref operand = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (102 + get_prefix operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (88 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


pop_r32 :: IORef (Ptr ()) -> Reg32 -> IO ()
pop_r32 bufref operand = do
    if (operand > 7) then
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 65
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (88 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


pop_r64 :: IORef (Ptr ()) -> Reg64 -> IO ()
pop_r64 bufref operand = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (72 + get_prefix operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) (88 + operand)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


pushf :: IORef (Ptr ()) -> IO ()
pushf bufref  = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 156
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


popf :: IORef (Ptr ()) -> IO ()
popf bufref  = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 157
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


ret :: IORef (Ptr ()) -> IO ()
ret bufref  = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 195
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


