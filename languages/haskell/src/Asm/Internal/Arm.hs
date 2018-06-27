module Asm.Internal.Arm where

    import Data.ByteString.Builder

    -- | An ARM register.
    newtype Register = Register Word8

    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, a1, a2, a3, a4, v1, v2, v3, v4, v5, v6, v7, v8, ip, sp, lr, pc, wr, sb, sl, fp :: Register
    r0 = Register 0
    r1 = Register 1
    r2 = Register 2
    r3 = Register 3
    r4 = Register 4
    r5 = Register 5
    r6 = Register 6
    r7 = Register 7
    r8 = Register 8
    r9 = Register 9
    r10 = Register 10
    r11 = Register 11
    r12 = Register 12
    r13 = Register 13
    r14 = Register 14
    r15 = Register 15
    a1 = Register 0
    a2 = Register 1
    a3 = Register 2
    a4 = Register 3
    v1 = Register 4
    v2 = Register 5
    v3 = Register 6
    v4 = Register 7
    v5 = Register 8
    v6 = Register 9
    v7 = Register 10
    v8 = Register 11
    ip = Register 12
    sp = Register 13
    lr = Register 14
    pc = Register 15
    wr = Register 7
    sb = Register 9
    sl = Register 10
    fp = Register 11


    -- | A list of ARM registers, where each register corresponds to a single bit.
    data RegList =
      RLR0 -- ^ Register #1.
    | RLR1 -- ^ Register #2.
    | RLR2 -- ^ Register #3.
    | RLR3 -- ^ Register #4.
    | RLR4 -- ^ Register #5.
    | RLR5 -- ^ Register #6.
    | RLR6 -- ^ Register #7.
    | RLR7 -- ^ Register #8.
    | RLR8 -- ^ Register #9.
    | RLR9 -- ^ Register #10.
    | RLR10 -- ^ Register #11.
    | RLR11 -- ^ Register #12.
    | RLR12 -- ^ Register #13.
    | RLR13 -- ^ Register #14.
    | RLR14 -- ^ Register #15.
    | RLR15 -- ^ Register #16.
    | RLA1 -- ^ Register A1.
    | RLA2 -- ^ Register A2.
    | RLA3 -- ^ Register A3.
    | RLA4 -- ^ Register A4.
    | RLV1 -- ^ Register V1.
    | RLV2 -- ^ Register V2.
    | RLV3 -- ^ Register V3.
    | RLV4 -- ^ Register V4.
    | RLV5 -- ^ Register V5.
    | RLV6 -- ^ Register V6.
    | RLV7 -- ^ Register V7.
    | RLV8 -- ^ Register V8.
    | RLIP -- ^ Register IP.
    | RLSP -- ^ Register SP.
    | RLLR -- ^ Register LR.
    | RLPC -- ^ Register PC.
    | RLWR -- ^ Register WR.
    | RLSB -- ^ Register SB.
    | RLSL -- ^ Register SL.
    | RLFP -- ^ Register FP.
      deriving (Eq, Show)

    instance Enum RegList where
      fromEnum RLR0 = 0
      fromEnum RLR1 = 1
      fromEnum RLR2 = 2
      fromEnum RLR3 = 3
      fromEnum RLR4 = 4
      fromEnum RLR5 = 5
      fromEnum RLR6 = 6
      fromEnum RLR7 = 7
      fromEnum RLR8 = 8
      fromEnum RLR9 = 9
      fromEnum RLR10 = 10
      fromEnum RLR11 = 11
      fromEnum RLR12 = 12
      fromEnum RLR13 = 13
      fromEnum RLR14 = 14
      fromEnum RLR15 = 15
      fromEnum RLA1 = 0
      fromEnum RLA2 = 1
      fromEnum RLA3 = 2
      fromEnum RLA4 = 3
      fromEnum RLV1 = 4
      fromEnum RLV2 = 5
      fromEnum RLV3 = 6
      fromEnum RLV4 = 7
      fromEnum RLV5 = 8
      fromEnum RLV6 = 9
      fromEnum RLV7 = 10
      fromEnum RLV8 = 11
      fromEnum RLIP = 12
      fromEnum RLSP = 13
      fromEnum RLLR = 14
      fromEnum RLPC = 15
      fromEnum RLWR = 7
      fromEnum RLSB = 9
      fromEnum RLSL = 10
      fromEnum RLFP = 11

      toEnum 0 = RLR0
      toEnum 1 = RLR1
      toEnum 2 = RLR2
      toEnum 3 = RLR3
      toEnum 4 = RLR4
      toEnum 5 = RLR5
      toEnum 6 = RLR6
      toEnum 7 = RLR7
      toEnum 8 = RLR8
      toEnum 9 = RLR9
      toEnum 10 = RLR10
      toEnum 11 = RLR11
      toEnum 12 = RLR12
      toEnum 13 = RLR13
      toEnum 14 = RLR14
      toEnum 15 = RLR15
      toEnum 0 = RLA1
      toEnum 1 = RLA2
      toEnum 2 = RLA3
      toEnum 3 = RLA4
      toEnum 4 = RLV1
      toEnum 5 = RLV2
      toEnum 6 = RLV3
      toEnum 7 = RLV4
      toEnum 8 = RLV5
      toEnum 9 = RLV6
      toEnum 10 = RLV7
      toEnum 11 = RLV8
      toEnum 12 = RLIP
      toEnum 13 = RLSP
      toEnum 14 = RLLR
      toEnum 15 = RLPC
      toEnum 7 = RLWR
      toEnum 9 = RLSB
      toEnum 10 = RLSL
      toEnum 11 = RLFP


    -- | An ARM coprocessor.
    newtype Coprocessor = Coprocessor Word8

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


    adc :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    adc cond update_cprs rn rd update_condition = do
        word16LE (((((10485760 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    add :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    add cond update_cprs rn rd update_condition = do
        word16LE (((((8388608 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    and :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    and cond update_cprs rn rd update_condition = do
        word16LE (((((0 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    eor :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    eor cond update_cprs rn rd update_condition = do
        word16LE (((((2097152 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    orr :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    orr cond update_cprs rn rd update_condition = do
        word16LE (((((25165824 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    rsb :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    rsb cond update_cprs rn rd update_condition = do
        word16LE (((((6291456 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    rsc :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    rsc cond update_cprs rn rd update_condition = do
        word16LE (((((14680064 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    sbc :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    sbc cond update_cprs rn rd update_condition = do
        word16LE (((((12582912 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    sub :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    sub cond update_cprs rn rd update_condition = do
        word16LE (((((4194304 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    bkpt :: Word16 -> Builder
    bkpt immed = do
        word16LE ((3776970864 .|. ((immed .&. 65520) << 8)) .|. ((immed .&. 15) << 0))


    b :: Condition -> Builder
    b cond = do
        word16LE (167772160 .|. cond)


    bic :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    bic cond update_cprs rn rd update_condition = do
        word16LE (((((29360128 .|. cond) .|. (update_cprs << 20)) .|. (rn << 16)) .|. (rd << 12)) .|. (update_condition << 20))


    blx :: Condition -> Builder
    blx cond = do
        word16LE (19922736 .|. cond)


    bx :: Condition -> Builder
    bx cond = do
        word16LE (19922704 .|. cond)


    bxj :: Condition -> Builder
    bxj cond = do
        word16LE (19922720 .|. cond)


    blxun :: Builder
    blxun  = do
        word16LE 4194304000


    clz :: Condition -> Register -> Builder
    clz cond rd = do
        word16LE ((24055568 .|. cond) .|. (rd << 12))


    cmn :: Condition -> Register -> Builder
    cmn cond rn = do
        word16LE ((24117248 .|. cond) .|. (rn << 16))


    cmp :: Condition -> Register -> Builder
    cmp cond rn = do
        word16LE ((22020096 .|. cond) .|. (rn << 16))


    cpy :: Condition -> Register -> Builder
    cpy cond rd = do
        word16LE ((27262976 .|. cond) .|. (rd << 12))


    cps :: Mode -> Builder
    cps mode = do
        word16LE (4043440128 .|. (mode << 0))


    cpsie :: InterruptFlags -> Builder
    cpsie iflags = do
        word16LE (4043833344 .|. (iflags << 6))


    cpsid :: InterruptFlags -> Builder
    cpsid iflags = do
        word16LE (4044095488 .|. (iflags << 6))


    cpsie_mode :: InterruptFlags -> Mode -> Builder
    cpsie_mode iflags mode = do
        word16LE ((4043964416 .|. (iflags << 6)) .|. (mode << 0))


    cpsid_mode :: InterruptFlags -> Mode -> Builder
    cpsid_mode iflags mode = do
        word16LE ((4044226560 .|. (iflags << 6)) .|. (mode << 0))


    ldc :: Condition -> Bool -> Register -> Coprocessor -> OffsetMode -> Addressing -> Builder
    ldc cond write rn cpnum offset_mode addressing_mode = do
        word16LE ((((((202375168 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (cpnum << 8)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldm :: Condition -> Register -> OffsetMode -> Addressing -> RegList -> Bool -> Bool -> Builder
    ldm cond rn offset_mode addressing_mode registers write copy_spsr = do
        assert ((copy_spsr == 1) `xor` (write == (registers .&. 32768)))
        word16LE ((((((((135266304 .|. cond) .|. (rn << 16)) .|. (addressing_mode << 23)) .|. (offset_mode << 11)) .|. (addressing_mode << 23)) .|. registers) .|. (copy_spsr << 21)) .|. (write << 10))


    ldr :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    ldr cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((68157440 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldrb :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    ldrb cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((72351744 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldrbt :: Condition -> Register -> Register -> OffsetMode -> Builder
    ldrbt cond rn rd offset_mode = do
        word16LE ((((74448896 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))


    ldrd :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    ldrd cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((208 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldrex :: Condition -> Register -> Register -> Builder
    ldrex cond rn rd = do
        word16LE (((26218399 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    ldrh :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    ldrh cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((1048752 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldrsb :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    ldrsb cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((1048784 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldrsh :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    ldrsh cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((1048816 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ldrt :: Condition -> Register -> Register -> OffsetMode -> Builder
    ldrt cond rn rd offset_mode = do
        word16LE ((((70254592 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))


    cdp :: Condition -> Coprocessor -> Builder
    cdp cond cpnum = do
        word16LE ((234881024 .|. cond) .|. (cpnum << 8))


    mcr :: Condition -> Register -> Coprocessor -> Builder
    mcr cond rd cpnum = do
        word16LE (((234881040 .|. cond) .|. (rd << 12)) .|. (cpnum << 8))


    mrc :: Condition -> Register -> Coprocessor -> Builder
    mrc cond rd cpnum = do
        word16LE (((235929616 .|. cond) .|. (rd << 12)) .|. (cpnum << 8))


    mcrr :: Condition -> Register -> Register -> Coprocessor -> Builder
    mcrr cond rn rd cpnum = do
        word16LE ((((205520896 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (cpnum << 8))


    mla :: Condition -> Bool -> Register -> Register -> Bool -> Builder
    mla cond update_cprs rn rd update_condition = do
        word16LE (((((2097296 .|. cond) .|. (update_cprs << 20)) .|. (rn << 12)) .|. (rd << 16)) .|. (update_condition << 20))


    mov :: Condition -> Bool -> Register -> Bool -> Builder
    mov cond update_cprs rd update_condition = do
        word16LE ((((27262976 .|. cond) .|. (update_cprs << 20)) .|. (rd << 12)) .|. (update_condition << 20))


    mrrc :: Condition -> Register -> Register -> Coprocessor -> Builder
    mrrc cond rn rd cpnum = do
        word16LE ((((206569472 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (cpnum << 8))


    mrs :: Condition -> Register -> Builder
    mrs cond rd = do
        word16LE ((17760256 .|. cond) .|. (rd << 12))


    mul :: Condition -> Bool -> Register -> Bool -> Builder
    mul cond update_cprs rd update_condition = do
        word16LE ((((144 .|. cond) .|. (update_cprs << 20)) .|. (rd << 16)) .|. (update_condition << 20))


    mvn :: Condition -> Bool -> Register -> Bool -> Builder
    mvn cond update_cprs rd update_condition = do
        word16LE ((((31457280 .|. cond) .|. (update_cprs << 20)) .|. (rd << 12)) .|. (update_condition << 20))


    msr_imm :: Condition -> FieldMask -> Builder
    msr_imm cond fieldmask = do
        word16LE ((52490240 .|. cond) .|. (fieldmask << 16))


    msr_reg :: Condition -> FieldMask -> Builder
    msr_reg cond fieldmask = do
        word16LE ((18935808 .|. cond) .|. (fieldmask << 16))


    pkhbt :: Condition -> Register -> Register -> Builder
    pkhbt cond rn rd = do
        word16LE (((109051920 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    pkhtb :: Condition -> Register -> Register -> Builder
    pkhtb cond rn rd = do
        word16LE (((109051984 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    pld :: Register -> OffsetMode -> Builder
    pld rn offset_mode = do
        word16LE ((4115722240 .|. (rn << 16)) .|. (offset_mode << 23))


    qadd :: Condition -> Register -> Register -> Builder
    qadd cond rn rd = do
        word16LE (((16777296 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qadd16 :: Condition -> Register -> Register -> Builder
    qadd16 cond rn rd = do
        word16LE (((102764304 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qadd8 :: Condition -> Register -> Register -> Builder
    qadd8 cond rn rd = do
        word16LE (((102764432 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qaddsubx :: Condition -> Register -> Register -> Builder
    qaddsubx cond rn rd = do
        word16LE (((102764336 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qdadd :: Condition -> Register -> Register -> Builder
    qdadd cond rn rd = do
        word16LE (((20971600 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qdsub :: Condition -> Register -> Register -> Builder
    qdsub cond rn rd = do
        word16LE (((23068752 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qsub :: Condition -> Register -> Register -> Builder
    qsub cond rn rd = do
        word16LE (((18874448 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qsub16 :: Condition -> Register -> Register -> Builder
    qsub16 cond rn rd = do
        word16LE (((102764400 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qsub8 :: Condition -> Register -> Register -> Builder
    qsub8 cond rn rd = do
        word16LE (((102764528 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    qsubaddx :: Condition -> Register -> Register -> Builder
    qsubaddx cond rn rd = do
        word16LE (((102764368 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    rev :: Condition -> Register -> Builder
    rev cond rd = do
        word16LE ((113184560 .|. cond) .|. (rd << 12))


    rev16 :: Condition -> Register -> Builder
    rev16 cond rd = do
        word16LE ((113184688 .|. cond) .|. (rd << 12))


    revsh :: Condition -> Register -> Builder
    revsh cond rd = do
        word16LE ((117378992 .|. cond) .|. (rd << 12))


    rfe :: Bool -> Register -> OffsetMode -> Addressing -> Builder
    rfe write rn offset_mode addressing_mode = do
        word16LE ((((4161800704 .|. (write << 21)) .|. (rn << 16)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    sadd16 :: Condition -> Register -> Register -> Builder
    sadd16 cond rn rd = do
        word16LE (((101715728 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    sadd8 :: Condition -> Register -> Register -> Builder
    sadd8 cond rn rd = do
        word16LE (((101715856 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    saddsubx :: Condition -> Register -> Register -> Builder
    saddsubx cond rn rd = do
        word16LE (((101715760 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    sel :: Condition -> Register -> Register -> Builder
    sel cond rn rd = do
        word16LE (((109055920 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    setendbe :: Builder
    setendbe  = do
        word16LE 4043375104


    setendle :: Builder
    setendle  = do
        word16LE 4043374592


    shadd16 :: Condition -> Register -> Register -> Builder
    shadd16 cond rn rd = do
        word16LE (((103812880 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    shadd8 :: Condition -> Register -> Register -> Builder
    shadd8 cond rn rd = do
        word16LE (((103813008 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    shaddsubx :: Condition -> Register -> Register -> Builder
    shaddsubx cond rn rd = do
        word16LE (((103812912 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    shsub16 :: Condition -> Register -> Register -> Builder
    shsub16 cond rn rd = do
        word16LE (((103812976 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    shsub8 :: Condition -> Register -> Register -> Builder
    shsub8 cond rn rd = do
        word16LE (((103813104 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    shsubaddx :: Condition -> Register -> Register -> Builder
    shsubaddx cond rn rd = do
        word16LE (((103812944 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    smlabb :: Condition -> Register -> Register -> Builder
    smlabb cond rn rd = do
        word16LE (((16777344 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smlabt :: Condition -> Register -> Register -> Builder
    smlabt cond rn rd = do
        word16LE (((16777376 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smlatb :: Condition -> Register -> Register -> Builder
    smlatb cond rn rd = do
        word16LE (((16777408 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smlatt :: Condition -> Register -> Register -> Builder
    smlatt cond rn rd = do
        word16LE (((16777440 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smlad :: Condition -> Bool -> Register -> Register -> Builder
    smlad cond exchange rn rd = do
        word16LE ((((117440528 .|. cond) .|. (exchange << 5)) .|. (rn << 12)) .|. (rd << 16))


    smlal :: Condition -> Bool -> Bool -> Builder
    smlal cond update_cprs update_condition = do
        word16LE (((14680208 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))


    smlalbb :: Condition -> Builder
    smlalbb cond = do
        word16LE (20971648 .|. cond)


    smlalbt :: Condition -> Builder
    smlalbt cond = do
        word16LE (20971680 .|. cond)


    smlaltb :: Condition -> Builder
    smlaltb cond = do
        word16LE (20971712 .|. cond)


    smlaltt :: Condition -> Builder
    smlaltt cond = do
        word16LE (20971744 .|. cond)


    smlald :: Condition -> Bool -> Builder
    smlald cond exchange = do
        word16LE ((121634832 .|. cond) .|. (exchange << 5))


    smlawb :: Condition -> Register -> Register -> Builder
    smlawb cond rn rd = do
        word16LE (((18874496 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smlawt :: Condition -> Register -> Register -> Builder
    smlawt cond rn rd = do
        word16LE (((18874560 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smlsd :: Condition -> Bool -> Register -> Register -> Builder
    smlsd cond exchange rn rd = do
        word16LE ((((117440592 .|. cond) .|. (exchange << 5)) .|. (rn << 12)) .|. (rd << 16))


    smlsld :: Condition -> Bool -> Builder
    smlsld cond exchange = do
        word16LE ((121634896 .|. cond) .|. (exchange << 5))


    smmla :: Condition -> Register -> Register -> Builder
    smmla cond rn rd = do
        word16LE (((122683408 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smmls :: Condition -> Register -> Register -> Builder
    smmls cond rn rd = do
        word16LE (((122683600 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    smmul :: Condition -> Register -> Builder
    smmul cond rd = do
        word16LE ((122744848 .|. cond) .|. (rd << 16))


    smuad :: Condition -> Bool -> Register -> Builder
    smuad cond exchange rd = do
        word16LE (((117501968 .|. cond) .|. (exchange << 5)) .|. (rd << 16))


    smulbb :: Condition -> Register -> Builder
    smulbb cond rd = do
        word16LE ((23068800 .|. cond) .|. (rd << 16))


    smulbt :: Condition -> Register -> Builder
    smulbt cond rd = do
        word16LE ((23068832 .|. cond) .|. (rd << 16))


    smultb :: Condition -> Register -> Builder
    smultb cond rd = do
        word16LE ((23068864 .|. cond) .|. (rd << 16))


    smultt :: Condition -> Register -> Builder
    smultt cond rd = do
        word16LE ((23068896 .|. cond) .|. (rd << 16))


    smull :: Condition -> Bool -> Bool -> Builder
    smull cond update_cprs update_condition = do
        word16LE (((12583056 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))


    smulwb :: Condition -> Register -> Builder
    smulwb cond rd = do
        word16LE ((18874528 .|. cond) .|. (rd << 16))


    smulwt :: Condition -> Register -> Builder
    smulwt cond rd = do
        word16LE ((18874592 .|. cond) .|. (rd << 16))


    smusd :: Condition -> Bool -> Register -> Builder
    smusd cond exchange rd = do
        word16LE (((117502032 .|. cond) .|. (exchange << 5)) .|. (rd << 16))


    srs :: Bool -> Mode -> OffsetMode -> Addressing -> Builder
    srs write mode offset_mode addressing_mode = do
        word16LE ((((4165797120 .|. (write << 21)) .|. (mode << 0)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    ssat :: Condition -> Register -> Builder
    ssat cond rd = do
        word16LE ((105906192 .|. cond) .|. (rd << 12))


    ssat16 :: Condition -> Register -> Builder
    ssat16 cond rd = do
        word16LE ((111152944 .|. cond) .|. (rd << 12))


    ssub16 :: Condition -> Register -> Register -> Builder
    ssub16 cond rn rd = do
        word16LE (((101715824 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    ssub8 :: Condition -> Register -> Register -> Builder
    ssub8 cond rn rd = do
        word16LE (((101715952 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    ssubaddx :: Condition -> Register -> Register -> Builder
    ssubaddx cond rn rd = do
        word16LE (((101715792 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    stc :: Condition -> Bool -> Register -> Coprocessor -> OffsetMode -> Addressing -> Builder
    stc cond write rn cpnum offset_mode addressing_mode = do
        word16LE ((((((201326592 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (cpnum << 8)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    stm :: Condition -> Register -> OffsetMode -> Addressing -> RegList -> Bool -> Bool -> Builder
    stm cond rn offset_mode addressing_mode registers write user_mode = do
        assert ((user_mode == 0) || (write == 0))
        word16LE ((((((((134217728 .|. cond) .|. (rn << 16)) .|. (addressing_mode << 23)) .|. (offset_mode << 11)) .|. (addressing_mode << 23)) .|. registers) .|. (user_mode << 21)) .|. (write << 10))


    str :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    str cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((67108864 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    strb :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    strb cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((71303168 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    strbt :: Condition -> Register -> Register -> OffsetMode -> Builder
    strbt cond rn rd offset_mode = do
        word16LE ((((73400320 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))


    strd :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    strd cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((240 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    strex :: Condition -> Register -> Register -> Builder
    strex cond rn rd = do
        word16LE (((25169808 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    strh :: Condition -> Bool -> Register -> Register -> OffsetMode -> Addressing -> Builder
    strh cond write rn rd offset_mode addressing_mode = do
        word16LE ((((((176 .|. cond) .|. (write << 21)) .|. (rn << 16)) .|. (rd << 12)) .|. (addressing_mode << 23)) .|. (offset_mode << 11))


    strt :: Condition -> Register -> Register -> OffsetMode -> Builder
    strt cond rn rd offset_mode = do
        word16LE ((((69206016 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (offset_mode << 23))


    swi :: Condition -> Builder
    swi cond = do
        word16LE (251658240 .|. cond)


    swp :: Condition -> Register -> Register -> Builder
    swp cond rn rd = do
        word16LE (((16777360 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    swpb :: Condition -> Register -> Register -> Builder
    swpb cond rn rd = do
        word16LE (((20971664 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    sxtab :: Condition -> Register -> Register -> Rotation -> Builder
    sxtab cond rn rd rotate = do
        word16LE ((((111149168 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))


    sxtab16 :: Condition -> Register -> Register -> Rotation -> Builder
    sxtab16 cond rn rd rotate = do
        word16LE ((((109052016 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))


    sxtah :: Condition -> Register -> Register -> Rotation -> Builder
    sxtah cond rn rd rotate = do
        word16LE ((((112197744 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))


    sxtb :: Condition -> Register -> Rotation -> Builder
    sxtb cond rd rotate = do
        word16LE (((112132208 .|. cond) .|. (rd << 12)) .|. (rotate << 10))


    sxtb16 :: Condition -> Register -> Rotation -> Builder
    sxtb16 cond rd rotate = do
        word16LE (((110035056 .|. cond) .|. (rd << 12)) .|. (rotate << 10))


    sxth :: Condition -> Register -> Rotation -> Builder
    sxth cond rd rotate = do
        word16LE (((113180784 .|. cond) .|. (rd << 12)) .|. (rotate << 10))


    teq :: Condition -> Register -> Builder
    teq cond rn = do
        word16LE ((19922944 .|. cond) .|. (rn << 16))


    tst :: Condition -> Register -> Builder
    tst cond rn = do
        word16LE ((17825792 .|. cond) .|. (rn << 16))


    uadd16 :: Condition -> Register -> Register -> Builder
    uadd16 cond rn rd = do
        word16LE (((105910032 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uadd8 :: Condition -> Register -> Register -> Builder
    uadd8 cond rn rd = do
        word16LE (((105910160 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uaddsubx :: Condition -> Register -> Register -> Builder
    uaddsubx cond rn rd = do
        word16LE (((105910064 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uhadd16 :: Condition -> Register -> Register -> Builder
    uhadd16 cond rn rd = do
        word16LE (((108007184 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uhadd8 :: Condition -> Register -> Register -> Builder
    uhadd8 cond rn rd = do
        word16LE (((108007312 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uhaddsubx :: Condition -> Register -> Register -> Builder
    uhaddsubx cond rn rd = do
        word16LE (((108007216 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uhsub16 :: Condition -> Register -> Register -> Builder
    uhsub16 cond rn rd = do
        word16LE (((108007280 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uhsub8 :: Condition -> Register -> Register -> Builder
    uhsub8 cond rn rd = do
        word16LE (((108007408 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uhsubaddx :: Condition -> Register -> Register -> Builder
    uhsubaddx cond rn rd = do
        word16LE (((108007248 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    umaal :: Condition -> Builder
    umaal cond = do
        word16LE (4194448 .|. cond)


    umlal :: Condition -> Bool -> Bool -> Builder
    umlal cond update_cprs update_condition = do
        word16LE (((10485904 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))


    umull :: Condition -> Bool -> Bool -> Builder
    umull cond update_cprs update_condition = do
        word16LE (((8388752 .|. cond) .|. (update_cprs << 20)) .|. (update_condition << 20))


    uqadd16 :: Condition -> Register -> Register -> Builder
    uqadd16 cond rn rd = do
        word16LE (((106958608 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uqadd8 :: Condition -> Register -> Register -> Builder
    uqadd8 cond rn rd = do
        word16LE (((106958736 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uqaddsubx :: Condition -> Register -> Register -> Builder
    uqaddsubx cond rn rd = do
        word16LE (((106958640 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uqsub16 :: Condition -> Register -> Register -> Builder
    uqsub16 cond rn rd = do
        word16LE (((106958704 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uqsub8 :: Condition -> Register -> Register -> Builder
    uqsub8 cond rn rd = do
        word16LE (((106958832 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uqsubaddx :: Condition -> Register -> Register -> Builder
    uqsubaddx cond rn rd = do
        word16LE (((106958672 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    usad8 :: Condition -> Register -> Builder
    usad8 cond rd = do
        word16LE ((125890576 .|. cond) .|. (rd << 16))


    usada8 :: Condition -> Register -> Register -> Builder
    usada8 cond rn rd = do
        word16LE (((125829136 .|. cond) .|. (rn << 12)) .|. (rd << 16))


    usat :: Condition -> Register -> Builder
    usat cond rd = do
        word16LE ((115343376 .|. cond) .|. (rd << 12))


    usat16 :: Condition -> Register -> Builder
    usat16 cond rd = do
        word16LE ((115347248 .|. cond) .|. (rd << 12))


    usub16 :: Condition -> Register -> Register -> Builder
    usub16 cond rn rd = do
        word16LE (((105910128 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    usub8 :: Condition -> Register -> Register -> Builder
    usub8 cond rn rd = do
        word16LE (((105910256 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    usubaddx :: Condition -> Register -> Register -> Builder
    usubaddx cond rn rd = do
        word16LE (((105910096 .|. cond) .|. (rn << 16)) .|. (rd << 12))


    uxtab :: Condition -> Register -> Register -> Rotation -> Builder
    uxtab cond rn rd rotate = do
        word16LE ((((115343472 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))


    uxtab16 :: Condition -> Register -> Register -> Rotation -> Builder
    uxtab16 cond rn rd rotate = do
        word16LE ((((113246320 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))


    uxtah :: Condition -> Register -> Register -> Rotation -> Builder
    uxtah cond rn rd rotate = do
        word16LE ((((116392048 .|. cond) .|. (rn << 16)) .|. (rd << 12)) .|. (rotate << 10))


    uxtb :: Condition -> Register -> Rotation -> Builder
    uxtb cond rd rotate = do
        word16LE (((116326512 .|. cond) .|. (rd << 12)) .|. (rotate << 10))


    uxtb16 :: Condition -> Register -> Rotation -> Builder
    uxtb16 cond rd rotate = do
        word16LE (((114229360 .|. cond) .|. (rd << 12)) .|. (rotate << 10))


    uxth :: Condition -> Register -> Rotation -> Builder
    uxth cond rd rotate = do
        word16LE (((117375088 .|. cond) .|. (rd << 12)) .|. (rotate << 10))


