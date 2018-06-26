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


sll :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sll bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((0 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


movci :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
movci bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((1 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


srl :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
srl bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((2 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sra :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sra bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((3 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sllv :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sllv bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((4 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


srlv :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
srlv bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((6 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


srav :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
srav bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((7 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


jr :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
jr bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((8 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


jalr :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
jalr bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((9 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


movz :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
movz bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((10 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


movn :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
movn bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((11 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


syscall :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
syscall bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((12 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


breakpoint :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
breakpoint bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((13 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sync :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sync bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((15 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mfhi :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mfhi bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((16 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mthi :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mthi bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((17 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mflo :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mflo bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((18 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mfhi :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mfhi bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((19 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsllv :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsllv bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((20 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsrlv :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsrlv bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((22 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsrav :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsrav bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((23 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mult :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mult bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((24 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


multu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
multu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((25 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


div :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
div bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((26 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


divu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
divu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((27 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dmult :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dmult bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((28 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dmultu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dmultu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((29 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ddiv :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
ddiv bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((30 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ddivu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
ddivu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((31 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


add :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
add bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((32 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


addu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
addu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((33 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sub :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sub bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((34 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


subu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
subu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((35 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


and :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
and bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((36 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


or :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
or bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((37 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


xor :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
xor bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((38 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


nor :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
nor bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((39 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


slt :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
slt bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((42 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sltu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
sltu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((43 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dadd :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dadd bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((44 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


daddu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
daddu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((45 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsub :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsub bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((46 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsubu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsubu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((47 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tge :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
tge bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((48 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tgeu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
tgeu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((49 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tlt :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
tlt bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((50 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tltu :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
tltu bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((51 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


teq :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
teq bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((52 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tne :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
tne bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((54 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsll :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsll bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((56 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dslr :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dslr bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((58 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsra :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
dsra bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((59 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mhc0 :: IORef (Ptr ()) -> Reg -> Reg -> Reg -> uint8 -> IO ()
mhc0 bufref rd rs rt shift = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((1073741824 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


btlz :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
btlz bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bgez :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bgez bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bltzl :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bltzl bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bgezl :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bgezl bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sllv :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
sllv bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tgei :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
tgei bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


jalr :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
jalr bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tlti :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
tlti bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tltiu :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
tltiu bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


teqi :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
teqi bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tnei :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
tnei bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bltzal :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bltzal bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bgezal :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bgezal bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bltzall :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bltzall bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bgezall :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
bgezall bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


dsllv :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
dsllv bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


synci :: IORef (Ptr ()) -> Reg -> uint16 -> IO ()
synci bufref rs target = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


addi :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
addi bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((536870912 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


addiu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
addiu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((603979776 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


andi :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
andi bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((805306368 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


beq :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
beq bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((268435456 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((imm .&. 65535) >> 2))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


blez :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
blez bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((402653184 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((imm .&. 65535) >> 2))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bne :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
bne bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((335544320 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((imm .&. 65535) >> 2))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lw :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lw bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2348810240 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lbu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lbu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2415919104 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lhu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lhu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2483027968 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


lui :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
lui bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((1006632960 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ori :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
ori bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((872415232 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sb :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sb bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2684354560 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sh :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sh bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2751463424 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


slti :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
slti bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((671088640 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sltiu :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sltiu bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((738197504 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sw :: IORef (Ptr ()) -> Reg -> Reg -> uint16 -> IO ()
sw bufref rs rt imm = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((2885681152 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


j :: IORef (Ptr ()) -> uint32 -> IO ()
j bufref address = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (134217728 .|. ((address >> 2) .&. 67108863))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


jal :: IORef (Ptr ()) -> uint32 -> IO ()
jal bufref address = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (201326592 .|. ((address >> 2) .&. 67108863))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


