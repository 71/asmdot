module Asm.Internal.Arm where

import Data.IORef
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

-- | An ARM register.
newtype Reg = Reg uint8

r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, a1, a2, a3, a4, v1, v2, v3, v4, v5, v6, v7, v8, ip, sp, lr, pc, wr, sb, sl, fp :: Reg
r0 = Reg 0
r1 = Reg 1
r2 = Reg 2
r3 = Reg 3
r4 = Reg 4
r5 = Reg 5
r6 = Reg 6
r7 = Reg 7
r8 = Reg 8
r9 = Reg 9
r10 = Reg 10
r11 = Reg 11
r12 = Reg 12
r13 = Reg 13
r14 = Reg 14
r15 = Reg 15
a1 = Reg 0
a2 = Reg 1
a3 = Reg 2
a4 = Reg 3
v1 = Reg 4
v2 = Reg 5
v3 = Reg 6
v4 = Reg 7
v5 = Reg 8
v6 = Reg 9
v7 = Reg 10
v8 = Reg 11
ip = Reg 12
sp = Reg 13
lr = Reg 14
pc = Reg 15
wr = Reg 7
sb = Reg 9
sl = Reg 10
fp = Reg 11


-- | An ARM coprocessor.
newtype Coprocessor = Coprocessor uint8

cp0, cp1, cp2, cp3, cp4, cp5, cp6, cp7, cp8, cp9, cp10, cp11, cp12, cp13, cp14, cp15 :: Coprocessor
cp0 = Coprocessor 0
cp1 = Coprocessor 1
cp2 = Coprocessor 2
cp3 = Coprocessor 3
cp4 = Coprocessor 4
cp5 = Coprocessor 5
cp6 = Coprocessor 6
cp7 = Coprocessor 7
cp8 = Coprocessor 8
cp9 = Coprocessor 9
cp10 = Coprocessor 10
cp11 = Coprocessor 11
cp12 = Coprocessor 12
cp13 = Coprocessor 13
cp14 = Coprocessor 14
cp15 = Coprocessor 15


-- | Condition for an ARM instruction to be executed.
data Condition =
      EQ -- ^ Equal.
    | NE -- ^ Not equal.
    | HS -- ^ Unsigned higher or same.
    | LO -- ^ Unsigned lower.
    | MI -- ^ Minus / negative.
    | PL -- ^ Plus / positive or zero.
    | VS -- ^ Overflow.
    | VC -- ^ No overflow.
    | HI -- ^ Unsigned higher.
    | LS -- ^ Unsigned lower or same.
    | GE -- ^ Signed greater than or equal.
    | LT -- ^ Signed less than.
    | GT -- ^ Signed greater than.
    | LE -- ^ Signed less than or equal.
    | AL -- ^ Always (unconditional).
    | UN -- ^ Unpredictable (ARMv4 or lower).
    | CS -- ^ Carry set.
    | CC -- ^ Carry clear.
  deriving (Eq, Show)

instance Enum Condition where
  fromEnum EQ = 0
  fromEnum NE = 1
  fromEnum HS = 2
  fromEnum LO = 3
  fromEnum MI = 4
  fromEnum PL = 5
  fromEnum VS = 6
  fromEnum VC = 7
  fromEnum HI = 8
  fromEnum LS = 9
  fromEnum GE = 10
  fromEnum LT = 11
  fromEnum GT = 12
  fromEnum LE = 13
  fromEnum AL = 14
  fromEnum UN = 15
  fromEnum CS = 2
  fromEnum CC = 3

  toEnum 0 = EQ
  toEnum 1 = NE
  toEnum 2 = HS
  toEnum 3 = LO
  toEnum 4 = MI
  toEnum 5 = PL
  toEnum 6 = VS
  toEnum 7 = VC
  toEnum 8 = HI
  toEnum 9 = LS
  toEnum 10 = GE
  toEnum 11 = LT
  toEnum 12 = GT
  toEnum 13 = LE
  toEnum 14 = AL
  toEnum 15 = UN
  toEnum 2 = CS
  toEnum 3 = CC


-- | Processor mode.
data Mode =
      USRMode -- ^ User mode.
    | FIQMode -- ^ FIQ (high-speed data transfer) mode.
    | IRQMode -- ^ IRQ (general-purpose interrupt handling) mode.
    | SVCMode -- ^ Supervisor mode.
    | ABTMode -- ^ Abort mode.
    | UNDMode -- ^ Undefined mode.
    | SYSMode -- ^ System (privileged) mode.
  deriving (Eq, Show)

instance Enum Mode where
  fromEnum USRMode = 16
  fromEnum FIQMode = 17
  fromEnum IRQMode = 18
  fromEnum SVCMode = 19
  fromEnum ABTMode = 23
  fromEnum UNDMode = 27
  fromEnum SYSMode = 31

  toEnum 16 = USRMode
  toEnum 17 = FIQMode
  toEnum 18 = IRQMode
  toEnum 19 = SVCMode
  toEnum 23 = ABTMode
  toEnum 27 = UNDMode
  toEnum 31 = SYSMode


-- | Kind of a shift.
data Shift =
      LogicalShiftLeft -- ^ Logical shift left.
    | LogicalShiftRight -- ^ Logical shift right.
    | ArithShiftRight -- ^ Arithmetic shift right.
    | RotateRight -- ^ Rotate right.
    | RRX -- ^ Shifted right by one bit.
  deriving (Eq, Show)

instance Enum Shift where
  fromEnum LogicalShiftLeft = 0
  fromEnum LogicalShiftRight = 1
  fromEnum ArithShiftRight = 2
  fromEnum RotateRight = 3
  fromEnum RRX = 3

  toEnum 0 = LogicalShiftLeft
  toEnum 1 = LogicalShiftRight
  toEnum 2 = ArithShiftRight
  toEnum 3 = RotateRight
  toEnum 3 = RRX


-- | Kind of a right rotation.
data Rotation =
      NoRotation -- ^ Do not rotate.
    | RotateRight8 -- ^ Rotate 8 bits to the right.
    | RotateRight16 -- ^ Rotate 16 bits to the right.
    | RotateRight24 -- ^ Rotate 24 bits to the right.
  deriving (Eq, Show)

instance Enum Rotation where
  fromEnum NoRotation = 0
  fromEnum RotateRight8 = 1
  fromEnum RotateRight16 = 2
  fromEnum RotateRight24 = 3

  toEnum 0 = NoRotation
  toEnum 1 = RotateRight8
  toEnum 2 = RotateRight16
  toEnum 3 = RotateRight24


-- | Field mask bits.
data FieldMask =
      CFieldMask -- ^ Control field mask bit.
    | XFieldMask -- ^ Extension field mask bit.
    | SFieldMask -- ^ Status field mask bit.
    | FFieldMask -- ^ Flags field mask bit.
  deriving (Eq, Show)

instance Enum FieldMask where
  fromEnum CFieldMask = 1
  fromEnum XFieldMask = 2
  fromEnum SFieldMask = 4
  fromEnum FFieldMask = 8

  toEnum 1 = CFieldMask
  toEnum 2 = XFieldMask
  toEnum 4 = SFieldMask
  toEnum 8 = FFieldMask


-- | Interrupt flags.
data InterruptFlags =
      InterruptFIQ -- ^ FIQ interrupt bit.
    | InterruptIRQ -- ^ IRQ interrupt bit.
    | ImpreciseDataAbort -- ^ Imprecise data abort bit.
  deriving (Eq, Show)

instance Enum InterruptFlags where
  fromEnum InterruptFIQ = 1
  fromEnum InterruptIRQ = 2
  fromEnum ImpreciseDataAbort = 4

  toEnum 1 = InterruptFIQ
  toEnum 2 = InterruptIRQ
  toEnum 4 = ImpreciseDataAbort


-- | Addressing type.
data Addressing =
      PostIndexedIndexing -- ^ Post-indexed addressing.
    | PreIndexedIndexing -- ^ Pre-indexed addressing (or offset addressing if `write` is false).
    | OffsetIndexing -- ^ Offset addressing (or pre-indexed addressing if `write` is true).
  deriving (Eq, Show)

instance Enum Addressing where
  fromEnum PostIndexedIndexing = 0
  fromEnum PreIndexedIndexing = 1
  fromEnum OffsetIndexing = 1

  toEnum 0 = PostIndexedIndexing
  toEnum 1 = PreIndexedIndexing
  toEnum 1 = OffsetIndexing


-- | Offset adding or subtracting mode.
data OffsetMode =
      SubtractOffset -- ^ Subtract offset from the base.
    | AddOffset -- ^ Add offset to the base.
  deriving (Eq, Show)

instance Enum OffsetMode where
  fromEnum SubtractOffset = 0
  fromEnum AddOffset = 1

  toEnum 0 = SubtractOffset
  toEnum 1 = AddOffset


adc :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
adc bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((10485760 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


add :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
add bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((8388608 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


and :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
and bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((0 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


eor :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
eor bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((2097152 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


orr :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
orr bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((25165824 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


rsb :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
rsb bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((6291456 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


rsc :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
rsc bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((14680064 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sbc :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
sbc bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((12582912 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sub :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
sub bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((4194304 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bkpt :: IORef (Ptr ()) -> uint16 -> IO ()
bkpt bufref immed = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((3776970864 .|. ((immed .&. 65520) << 8)) .|. ((immed .&. 15) << 0))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


b :: IORef (Ptr ()) -> Condition -> IO ()
b bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (167772160 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bic :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
bic bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((29360128 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


blx :: IORef (Ptr ()) -> Condition -> IO ()
blx bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (19922736 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bx :: IORef (Ptr ()) -> Condition -> IO ()
bx bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (19922704 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


bxj :: IORef (Ptr ()) -> Condition -> IO ()
bxj bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (19922720 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


blxun :: IORef (Ptr ()) -> IO ()
blxun bufref  = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) 4194304000
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


clz :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
clz bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((24055568 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cmn :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
cmn bufref cond rn = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((24117248 .|. cond) .|. (rn << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cmp :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
cmp bufref cond rn = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((22020096 .|. cond) .|. (rn << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cpy :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
cpy bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((27262976 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cps :: IORef (Ptr ()) -> Mode -> IO ()
cps bufref mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (4043440128 .|. (mode << 0))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cpsie :: IORef (Ptr ()) -> InterruptFlags -> IO ()
cpsie bufref iflags = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (4043833344 .|. (iflags << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cpsid :: IORef (Ptr ()) -> InterruptFlags -> IO ()
cpsid bufref iflags = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (4044095488 .|. (iflags << 6))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cpsie_mode :: IORef (Ptr ()) -> InterruptFlags -> Mode -> IO ()
cpsie_mode bufref iflags mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((4043964416 .|. (iflags << 6)) .|. (mode << 0))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cpsid_mode :: IORef (Ptr ()) -> InterruptFlags -> Mode -> IO ()
cpsid_mode bufref iflags mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((4044226560 .|. (iflags << 6)) .|. (mode << 0))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldc :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Coprocessor -> OffsetMode -> Addressing -> IO ()
ldc bufref cond write rn cpnum offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((202375168 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (cpnum << 8)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldm :: IORef (Ptr ()) -> Condition -> Reg -> OffsetMode -> Addressing -> Reg -> bool -> bool -> IO ()
ldm bufref cond rn offset_mode addressing_mode registers write copy_spsr = do
    assert (copy_spsr `xor` (write == (registers .&. 32768)))
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((((135266304 .|. cond) .|. (rn << 16)) .|. (addressing_mode << 23)) .|. (offset_mode << 11)) .|. (addressing_mode << 23)) .|. registers) .|. (copy_spsr << 21)) .|. (write << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldr :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
ldr bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((68157440 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrb :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
ldrb bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((72351744 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrbt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> OffsetMode -> IO ()
ldrbt bufref cond rn rd offset_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((74448896 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrd :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
ldrd bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((208 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrex :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
ldrex bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((26218399 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrh :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
ldrh bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((1048752 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrsb :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
ldrsb bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((1048784 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrsh :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
ldrsh bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((1048816 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ldrt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> OffsetMode -> IO ()
ldrt bufref cond rn rd offset_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((70254592 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


cdp :: IORef (Ptr ()) -> Condition -> Coprocessor -> IO ()
cdp bufref cond cpnum = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((234881024 .|. cond) .|. (cpnum << 8))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mcr :: IORef (Ptr ()) -> Condition -> Reg -> Coprocessor -> IO ()
mcr bufref cond rd cpnum = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((234881040 .|. cond) .|. (rd << 12)) .|. (cpnum << 8))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mrc :: IORef (Ptr ()) -> Condition -> Reg -> Coprocessor -> IO ()
mrc bufref cond rd cpnum = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((235929616 .|. cond) .|. (rd << 12)) .|. (cpnum << 8))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mcrr :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Coprocessor -> IO ()
mcrr bufref cond rn rd cpnum = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((205520896 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (cpnum << 8))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mla :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> bool -> IO ()
mla bufref cond update_cprs rn rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((((2097296 .|. cond) .|. (update_cprs << 20)) .|. (rn << 12)) .|. (rd << 16)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mov :: IORef (Ptr ()) -> Condition -> bool -> Reg -> bool -> IO ()
mov bufref cond update_cprs rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((27262976 .|. cond) .|. (update_cprs << 20)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mrrc :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Coprocessor -> IO ()
mrrc bufref cond rn rd cpnum = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((206569472 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (cpnum << 8))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mrs :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
mrs bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((17760256 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mul :: IORef (Ptr ()) -> Condition -> bool -> Reg -> bool -> IO ()
mul bufref cond update_cprs rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((144 .|. cond) .|. (update_cprs << 20)) .|. (rd << 16)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


mvn :: IORef (Ptr ()) -> Condition -> bool -> Reg -> bool -> IO ()
mvn bufref cond update_cprs rd update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((31457280 .|. cond) .|. (update_cprs << 20)) .|. (rd << 12)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


msr#_imm :: IORef (Ptr ()) -> Condition -> FieldMask -> IO ()
msr#_imm bufref cond fieldmask = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((52490240 .|. cond) .|. (fieldmask << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


msr#_reg :: IORef (Ptr ()) -> Condition -> FieldMask -> IO ()
msr#_reg bufref cond fieldmask = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((18935808 .|. cond) .|. (fieldmask << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


pkhbt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
pkhbt bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((109051920 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


pkhtb :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
pkhtb bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((109051984 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


pld :: IORef (Ptr ()) -> Reg -> OffsetMode -> IO ()
pld bufref rn offset_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((4115722240 .|. (rn << 16)) .|. (offset_mode << 23))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qadd :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qadd bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((16777296 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qadd16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qadd16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((102764304 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qadd8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qadd8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((102764432 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qaddsubx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qaddsubx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((102764336 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qdadd :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qdadd bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((20971600 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qdsub :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qdsub bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((23068752 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qsub :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qsub bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((18874448 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qsub16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qsub16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((102764400 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qsub8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qsub8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((102764528 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


qsubaddx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
qsubaddx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((102764368 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


rev :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
rev bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((113184560 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


rev16 :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
rev16 bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((113184688 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


revsh :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
revsh bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((117378992 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


rfe :: IORef (Ptr ()) -> bool -> Reg -> OffsetMode -> Addressing -> IO ()
rfe bufref write rn offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((4161800704 .|. (write << 21)) .|. (rn << 16)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sadd16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
sadd16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((101715728 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sadd8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
sadd8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((101715856 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


saddsubx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
saddsubx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((101715760 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sel :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
sel bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((109055920 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


setendbe :: IORef (Ptr ()) -> IO ()
setendbe bufref  = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) 4043375104
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


setendle :: IORef (Ptr ()) -> IO ()
setendle bufref  = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) 4043374592
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


shadd16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
shadd16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((103812880 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


shadd8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
shadd8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((103813008 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


shaddsubx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
shaddsubx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((103812912 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


shsub16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
shsub16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((103812976 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


shsub8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
shsub8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((103813104 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


shsubaddx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
shsubaddx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((103812944 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlabb :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smlabb bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((16777344 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlabt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smlabt bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((16777376 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlatb :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smlatb bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((16777408 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlatt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smlatt bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((16777440 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlad :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> IO ()
smlad bufref cond exchange rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((117440528 .|. cond) .|. (exchange << 5)) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlal :: IORef (Ptr ()) -> Condition -> bool -> bool -> IO ()
smlal bufref cond update_cprs update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((14680208 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlalbb :: IORef (Ptr ()) -> Condition -> IO ()
smlalbb bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (20971648 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlalbt :: IORef (Ptr ()) -> Condition -> IO ()
smlalbt bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (20971680 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlaltb :: IORef (Ptr ()) -> Condition -> IO ()
smlaltb bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (20971712 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlaltt :: IORef (Ptr ()) -> Condition -> IO ()
smlaltt bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (20971744 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlald :: IORef (Ptr ()) -> Condition -> bool -> IO ()
smlald bufref cond exchange = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((121634832 .|. cond) .|. (exchange << 5))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlawb :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smlawb bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((18874496 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlawt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smlawt bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((18874560 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlsd :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> IO ()
smlsd bufref cond exchange rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((117440592 .|. cond) .|. (exchange << 5)) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smlsld :: IORef (Ptr ()) -> Condition -> bool -> IO ()
smlsld bufref cond exchange = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((121634896 .|. cond) .|. (exchange << 5))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smmla :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smmla bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((122683408 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smmls :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
smmls bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((122683600 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smmul :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smmul bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((122744848 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smuad :: IORef (Ptr ()) -> Condition -> bool -> Reg -> IO ()
smuad bufref cond exchange rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((117501968 .|. cond) .|. (exchange << 5)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smulbb :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smulbb bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((23068800 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smulbt :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smulbt bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((23068832 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smultb :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smultb bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((23068864 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smultt :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smultt bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((23068896 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smull :: IORef (Ptr ()) -> Condition -> bool -> bool -> IO ()
smull bufref cond update_cprs update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((12583056 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smulwb :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smulwb bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((18874528 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smulwt :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
smulwt bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((18874592 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


smusd :: IORef (Ptr ()) -> Condition -> bool -> Reg -> IO ()
smusd bufref cond exchange rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((117502032 .|. cond) .|. (exchange << 5)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


srs :: IORef (Ptr ()) -> bool -> Mode -> OffsetMode -> Addressing -> IO ()
srs bufref write mode offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((4165797120 .|. (write << 21)) .|. (mode << 0)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ssat :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
ssat bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((105906192 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ssat16 :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
ssat16 bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((111152944 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ssub16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
ssub16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((101715824 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ssub8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
ssub8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((101715952 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


ssubaddx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
ssubaddx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((101715792 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


stc :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Coprocessor -> OffsetMode -> Addressing -> IO ()
stc bufref cond write rn cpnum offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((201326592 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (cpnum << 8)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


stm :: IORef (Ptr ()) -> Condition -> Reg -> OffsetMode -> Addressing -> Reg -> bool -> bool -> IO ()
stm bufref cond rn offset_mode addressing_mode registers write user_mode = do
    assert ((user_mode == 0) || (write == 0))
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((((134217728 .|. cond) .|. (rn << 16)) .|. (addressing_mode << 23)) .|. (offset_mode << 11)) .|. (addressing_mode << 23)) .|. registers) .|. (user_mode << 21)) .|. (write << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


str :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
str bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((67108864 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


str#b :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
str#b bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((71303168 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


str#bt :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> OffsetMode -> IO ()
str#bt bufref cond rn rd offset_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((73400320 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


str#d :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
str#d bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((240 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


strex :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
strex bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((25169808 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


str#h :: IORef (Ptr ()) -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> IO ()
str#h bufref cond write rn rd offset_mode addressing_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((((176 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


str#t :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> OffsetMode -> IO ()
str#t bufref cond rn rd offset_mode = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((69206016 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


swi :: IORef (Ptr ()) -> Condition -> IO ()
swi bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (251658240 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


swp :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
swp bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((16777360 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


swpb :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
swpb bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((20971664 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sxtab :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Rotation -> IO ()
sxtab bufref cond rn rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((111149168 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sxtab16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Rotation -> IO ()
sxtab16 bufref cond rn rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((109052016 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sxtah :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Rotation -> IO ()
sxtah bufref cond rn rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((112197744 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sxtb :: IORef (Ptr ()) -> Condition -> Reg -> Rotation -> IO ()
sxtb bufref cond rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((112132208 .|. cond) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sxtb16 :: IORef (Ptr ()) -> Condition -> Reg -> Rotation -> IO ()
sxtb16 bufref cond rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((110035056 .|. cond) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


sxth :: IORef (Ptr ()) -> Condition -> Reg -> Rotation -> IO ()
sxth bufref cond rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((113180784 .|. cond) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


teq :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
teq bufref cond rn = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((19922944 .|. cond) .|. (rn << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


tst :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
tst bufref cond rn = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((17825792 .|. cond) .|. (rn << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uadd16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uadd16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((105910032 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uadd8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uadd8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((105910160 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uaddsubx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uaddsubx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((105910064 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uhadd16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uhadd16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((108007184 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uhadd8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uhadd8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((108007312 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uhaddsubx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uhaddsubx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((108007216 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uhsub16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uhsub16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((108007280 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uhsub8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uhsub8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((108007408 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uhsubaddx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uhsubaddx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((108007248 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


umaal :: IORef (Ptr ()) -> Condition -> IO ()
umaal bufref cond = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (4194448 .|. cond)
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


umlal :: IORef (Ptr ()) -> Condition -> bool -> bool -> IO ()
umlal bufref cond update_cprs update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((10485904 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


umull :: IORef (Ptr ()) -> Condition -> bool -> bool -> IO ()
umull bufref cond update_cprs update_condition = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((8388752 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uqadd16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uqadd16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((106958608 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uqadd8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uqadd8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((106958736 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uqaddsubx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uqaddsubx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((106958640 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uqsub16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uqsub16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((106958704 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uqsub8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uqsub8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((106958832 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uqsubaddx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
uqsubaddx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((106958672 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usad8 :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
usad8 bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((125890576 .|. cond) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usada8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
usada8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((125829136 .|. cond) .|. (rn << 12)) .|. (rd << 16))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usat :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
usat bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((115343376 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usat16 :: IORef (Ptr ()) -> Condition -> Reg -> IO ()
usat16 bufref cond rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((115347248 .|. cond) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usub16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
usub16 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((105910128 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usub8 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
usub8 bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((105910256 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


usubaddx :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> IO ()
usubaddx bufref cond rn rd = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((105910096 .|. cond) .|. (rn << 16)) .|. (rd << 12))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uxtab :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Rotation -> IO ()
uxtab bufref cond rn rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((115343472 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uxtab16 :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Rotation -> IO ()
uxtab16 bufref cond rn rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((113246320 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uxtah :: IORef (Ptr ()) -> Condition -> Reg -> Reg -> Rotation -> IO ()
uxtah bufref cond rn rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) ((((116392048 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uxtb :: IORef (Ptr ()) -> Condition -> Reg -> Rotation -> IO ()
uxtb bufref cond rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((116326512 .|. cond) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uxtb16 :: IORef (Ptr ()) -> Condition -> Reg -> Rotation -> IO ()
uxtb16 bufref cond rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((114229360 .|. cond) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


uxth :: IORef (Ptr ()) -> Condition -> Reg -> Rotation -> IO ()
uxth bufref cond rd rotate = do
    poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr uint32) (((117375088 .|. cond) .|. (rd << 12)) .|. (rotate << 10))
    writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) 4)


