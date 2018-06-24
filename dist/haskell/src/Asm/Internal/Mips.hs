module Asm.Internal.Mips where

import Data.IORef
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

-- | A Mips register.
newtype Reg = Reg uint8

Zero, AT, V0, V1, A0, A1, A2, A3, T0, T1, T2, T3, T4, T5, T6, T7, S0, S1, S2, S3, S4, S5, S6, S7, T8, T9, K0, K1, GP, SP, FP, RA :: Reg
Zero = Reg 0
AT = Reg 1
V0 = Reg 2
V1 = Reg 3
A0 = Reg 4
A1 = Reg 5
A2 = Reg 6
A3 = Reg 7
T0 = Reg 8
T1 = Reg 9
T2 = Reg 10
T3 = Reg 11
T4 = Reg 12
T5 = Reg 13
T6 = Reg 14
T7 = Reg 15
S0 = Reg 16
S1 = Reg 17
S2 = Reg 18
S3 = Reg 19
S4 = Reg 20
S5 = Reg 21
S6 = Reg 22
S7 = Reg 23
T8 = Reg 24
T9 = Reg 25
K0 = Reg 26
K1 = Reg 27
GP = Reg 28
SP = Reg 29
FP = Reg 30
RA = Reg 31


add :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
add bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((32 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


addu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
addu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((33 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


and :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
and bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((36 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


div :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
div bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((26 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


divu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
divu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((27 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


jr :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
jr bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((8 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mfhi :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mfhi bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((16 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mflo :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mflo bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((18 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mhc0 :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mhc0 bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((1073741824 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mult :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mult bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((24 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


multu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
multu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((25 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


nor :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
nor bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((39 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


xor :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
xor bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((38 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


or :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
or bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((37 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


slt :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
slt bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((42 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sltu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sltu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((43 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sll :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sll bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((0 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


srl :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
srl bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((2 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sra :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sra bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((3 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sub :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sub bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((34 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


subu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
subu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((35 .|. (rs << 21)) .|. (rt << 16)) .|. (rd << 11)) .|. (shift << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


addi :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
addi bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((536870912 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


addiu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
addiu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((603979776 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


andi :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
andi bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((805306368 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


beq :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
beq bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((268435456 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


blez :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
blez bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((402653184 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bne :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
bne bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((335544320 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lbu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lbu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2415919104 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lhu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lhu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2483027968 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lui :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lui bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((1006632960 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ori :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
ori bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((872415232 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sb :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sb bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2684354560 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sh :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sh bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2751463424 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


slti :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
slti bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((671088640 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sltiu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sltiu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((738197504 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sw :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sw bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2885681152 .|. (rs << 21)) .|. (rt << 16)) .|. imm)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


j :: IORef (Ptr ()) -> uint32 -> IO ()
j bufref addr = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (2885681152 .|. (67108863 .&. (addr << 2)))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


jal :: IORef (Ptr ()) -> uint32 -> IO ()
jal bufref addr = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (2885681152 .|. (67108863 .&. (addr << 2)))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


