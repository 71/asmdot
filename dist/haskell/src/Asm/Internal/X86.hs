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


clc :: IORef (Ptr ()) -> IO ()
clc bufref  = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 248
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


stc :: IORef (Ptr ()) -> IO ()
stc bufref  = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 249
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


cli :: IORef (Ptr ()) -> IO ()
cli bufref  = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 250
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sti :: IORef (Ptr ()) -> IO ()
sti bufref  = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 251
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


cld :: IORef (Ptr ()) -> IO ()
cld bufref  = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 252
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


std :: IORef (Ptr ()) -> IO ()
std bufref  = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 253
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jo_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jo_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 112
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jno_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jno_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 113
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jb_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jb_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 114
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnae_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnae_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 114
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jc_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jc_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 114
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnb_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnb_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 115
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jae_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jae_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 115
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnc_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnc_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 115
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jz_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jz_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 116
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


je_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
je_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 116
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnz_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnz_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 117
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jne_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jne_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 117
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jbe_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jbe_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 118
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jna_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jna_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 118
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnbe_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnbe_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 119
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


ja_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
ja_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 119
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


js_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
js_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 120
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jns_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jns_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 121
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jp_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jp_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 122
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jpe_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jpe_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 122
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnp_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnp_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 123
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jpo_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jpo_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 123
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jl_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jl_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 124
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnge_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnge_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 124
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnl_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnl_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 125
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jge_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jge_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 125
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jle_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jle_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 126
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jng_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jng_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 126
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jnle_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jnle_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 127
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


jg_imm8 :: IORef (Ptr ()) -> int8 -> IO ()
jg_imm8 bufref operand = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 127
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) operand
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


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


add_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
add_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


or_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
or_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


adc_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
adc_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sbb_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
sbb_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


and_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
and_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sub_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
sub_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


xor_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
xor_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


cmp_rm8_imm8 :: IORef (Ptr ()) -> Reg8 -> int8 -> IO ()
cmp_rm8_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 128
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg8) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


add_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
add_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


add_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
add_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


add_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
add_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


add_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
add_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


or_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
or_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


or_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
or_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


or_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
or_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


or_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
or_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


adc_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
adc_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


adc_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
adc_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


adc_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
adc_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


adc_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
adc_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sbb_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
sbb_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


sbb_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
sbb_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sbb_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
sbb_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


sbb_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
sbb_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


and_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
and_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


and_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
and_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


and_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
and_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


and_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
and_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sub_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
sub_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


sub_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
sub_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sub_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
sub_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


sub_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
sub_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


xor_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
xor_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


xor_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
xor_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


xor_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
xor_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


xor_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
xor_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cmp_rm16_imm16 :: IORef (Ptr ()) -> Reg16 -> int16 -> IO ()
cmp_rm16_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


cmp_rm16_imm32 :: IORef (Ptr ()) -> Reg16 -> int32 -> IO ()
cmp_rm16_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cmp_rm32_imm16 :: IORef (Ptr ()) -> Reg32 -> int16 -> IO ()
cmp_rm32_imm16 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int16) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 2)


cmp_rm32_imm32 :: IORef (Ptr ()) -> Reg32 -> int32 -> IO ()
cmp_rm32_imm32 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 129
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int32) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


add_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
add_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


add_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
add_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 0)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


or_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
or_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


or_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
or_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 1)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


adc_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
adc_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


adc_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
adc_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 2)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sbb_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
sbb_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sbb_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
sbb_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 3)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


and_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
and_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


and_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
and_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 4)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sub_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
sub_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


sub_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
sub_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 5)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


xor_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
xor_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


xor_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
xor_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 6)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


cmp_rm16_imm8 :: IORef (Ptr ()) -> Reg16 -> int8 -> IO ()
cmp_rm16_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 102
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg16) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


cmp_rm32_imm8 :: IORef (Ptr ()) -> Reg32 -> int8 -> IO ()
cmp_rm32_imm8 bufref reg value = do
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint8) 131
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr Reg32) (reg + 7)
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)
        poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr int8) value
        writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 1)


