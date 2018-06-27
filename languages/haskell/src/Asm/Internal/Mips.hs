module Asm.Internal.Mips where

    import Data.ByteString.Builder

    -- | A Mips register.
    newtype Register = Register Word8

    Zero, AT, V0, V1, A0, A1, A2, A3, T0, T1, T2, T3, T4, T5, T6, T7, S0, S1, S2, S3, S4, S5, S6, S7, T8, T9, K0, K1, GP, SP, FP, RA :: Register
    Zero = Register 0
    AT = Register 1
    V0 = Register 2
    V1 = Register 3
    A0 = Register 4
    A1 = Register 5
    A2 = Register 6
    A3 = Register 7
    T0 = Register 8
    T1 = Register 9
    T2 = Register 10
    T3 = Register 11
    T4 = Register 12
    T5 = Register 13
    T6 = Register 14
    T7 = Register 15
    S0 = Register 16
    S1 = Register 17
    S2 = Register 18
    S3 = Register 19
    S4 = Register 20
    S5 = Register 21
    S6 = Register 22
    S7 = Register 23
    T8 = Register 24
    T9 = Register 25
    K0 = Register 26
    K1 = Register 27
    GP = Register 28
    SP = Register 29
    FP = Register 30
    RA = Register 31


    sll :: Register -> Register -> Register -> Word8 -> Builder
    sll rd rs rt shift = do
        word16LE ((((0 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    movci :: Register -> Register -> Register -> Word8 -> Builder
    movci rd rs rt shift = do
        word16LE ((((1 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    srl :: Register -> Register -> Register -> Word8 -> Builder
    srl rd rs rt shift = do
        word16LE ((((2 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    sra :: Register -> Register -> Register -> Word8 -> Builder
    sra rd rs rt shift = do
        word16LE ((((3 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    sllv :: Register -> Register -> Register -> Word8 -> Builder
    sllv rd rs rt shift = do
        word16LE ((((4 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    srlv :: Register -> Register -> Register -> Word8 -> Builder
    srlv rd rs rt shift = do
        word16LE ((((6 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    srav :: Register -> Register -> Register -> Word8 -> Builder
    srav rd rs rt shift = do
        word16LE ((((7 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    jr :: Register -> Register -> Register -> Word8 -> Builder
    jr rd rs rt shift = do
        word16LE ((((8 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    jalr :: Register -> Register -> Register -> Word8 -> Builder
    jalr rd rs rt shift = do
        word16LE ((((9 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    movz :: Register -> Register -> Register -> Word8 -> Builder
    movz rd rs rt shift = do
        word16LE ((((10 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    movn :: Register -> Register -> Register -> Word8 -> Builder
    movn rd rs rt shift = do
        word16LE ((((11 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    syscall :: Register -> Register -> Register -> Word8 -> Builder
    syscall rd rs rt shift = do
        word16LE ((((12 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    breakpoint :: Register -> Register -> Register -> Word8 -> Builder
    breakpoint rd rs rt shift = do
        word16LE ((((13 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    sync :: Register -> Register -> Register -> Word8 -> Builder
    sync rd rs rt shift = do
        word16LE ((((15 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    mfhi :: Register -> Register -> Register -> Word8 -> Builder
    mfhi rd rs rt shift = do
        word16LE ((((16 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    mthi :: Register -> Register -> Register -> Word8 -> Builder
    mthi rd rs rt shift = do
        word16LE ((((17 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    mflo :: Register -> Register -> Register -> Word8 -> Builder
    mflo rd rs rt shift = do
        word16LE ((((18 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    mfhi :: Register -> Register -> Register -> Word8 -> Builder
    mfhi rd rs rt shift = do
        word16LE ((((19 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsllv :: Register -> Register -> Register -> Word8 -> Builder
    dsllv rd rs rt shift = do
        word16LE ((((20 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsrlv :: Register -> Register -> Register -> Word8 -> Builder
    dsrlv rd rs rt shift = do
        word16LE ((((22 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsrav :: Register -> Register -> Register -> Word8 -> Builder
    dsrav rd rs rt shift = do
        word16LE ((((23 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    mult :: Register -> Register -> Register -> Word8 -> Builder
    mult rd rs rt shift = do
        word16LE ((((24 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    multu :: Register -> Register -> Register -> Word8 -> Builder
    multu rd rs rt shift = do
        word16LE ((((25 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    div_ :: Register -> Register -> Register -> Word8 -> Builder
    div_ rd rs rt shift = do
        word16LE ((((26 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    divu :: Register -> Register -> Register -> Word8 -> Builder
    divu rd rs rt shift = do
        word16LE ((((27 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dmult :: Register -> Register -> Register -> Word8 -> Builder
    dmult rd rs rt shift = do
        word16LE ((((28 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dmultu :: Register -> Register -> Register -> Word8 -> Builder
    dmultu rd rs rt shift = do
        word16LE ((((29 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    ddiv :: Register -> Register -> Register -> Word8 -> Builder
    ddiv rd rs rt shift = do
        word16LE ((((30 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    ddivu :: Register -> Register -> Register -> Word8 -> Builder
    ddivu rd rs rt shift = do
        word16LE ((((31 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    add :: Register -> Register -> Register -> Word8 -> Builder
    add rd rs rt shift = do
        word16LE ((((32 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    addu :: Register -> Register -> Register -> Word8 -> Builder
    addu rd rs rt shift = do
        word16LE ((((33 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    sub :: Register -> Register -> Register -> Word8 -> Builder
    sub rd rs rt shift = do
        word16LE ((((34 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    subu :: Register -> Register -> Register -> Word8 -> Builder
    subu rd rs rt shift = do
        word16LE ((((35 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    and :: Register -> Register -> Register -> Word8 -> Builder
    and rd rs rt shift = do
        word16LE ((((36 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    or :: Register -> Register -> Register -> Word8 -> Builder
    or rd rs rt shift = do
        word16LE ((((37 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    xor :: Register -> Register -> Register -> Word8 -> Builder
    xor rd rs rt shift = do
        word16LE ((((38 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    nor :: Register -> Register -> Register -> Word8 -> Builder
    nor rd rs rt shift = do
        word16LE ((((39 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    slt :: Register -> Register -> Register -> Word8 -> Builder
    slt rd rs rt shift = do
        word16LE ((((42 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    sltu :: Register -> Register -> Register -> Word8 -> Builder
    sltu rd rs rt shift = do
        word16LE ((((43 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dadd :: Register -> Register -> Register -> Word8 -> Builder
    dadd rd rs rt shift = do
        word16LE ((((44 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    daddu :: Register -> Register -> Register -> Word8 -> Builder
    daddu rd rs rt shift = do
        word16LE ((((45 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsub :: Register -> Register -> Register -> Word8 -> Builder
    dsub rd rs rt shift = do
        word16LE ((((46 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsubu :: Register -> Register -> Register -> Word8 -> Builder
    dsubu rd rs rt shift = do
        word16LE ((((47 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    tge :: Register -> Register -> Register -> Word8 -> Builder
    tge rd rs rt shift = do
        word16LE ((((48 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    tgeu :: Register -> Register -> Register -> Word8 -> Builder
    tgeu rd rs rt shift = do
        word16LE ((((49 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    tlt :: Register -> Register -> Register -> Word8 -> Builder
    tlt rd rs rt shift = do
        word16LE ((((50 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    tltu :: Register -> Register -> Register -> Word8 -> Builder
    tltu rd rs rt shift = do
        word16LE ((((51 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    teq :: Register -> Register -> Register -> Word8 -> Builder
    teq rd rs rt shift = do
        word16LE ((((52 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    tne :: Register -> Register -> Register -> Word8 -> Builder
    tne rd rs rt shift = do
        word16LE ((((54 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsll :: Register -> Register -> Register -> Word8 -> Builder
    dsll rd rs rt shift = do
        word16LE ((((56 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dslr :: Register -> Register -> Register -> Word8 -> Builder
    dslr rd rs rt shift = do
        word16LE ((((58 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    dsra :: Register -> Register -> Register -> Word8 -> Builder
    dsra rd rs rt shift = do
        word16LE ((((59 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    mhc0 :: Register -> Register -> Register -> Word8 -> Builder
    mhc0 rd rs rt shift = do
        word16LE ((((1073741824 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((rd .&. 31) << 11)) .|. ((shift .&. 31) << 6))


    btlz :: Register -> Word16 -> Builder
    btlz rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bgez :: Register -> Word16 -> Builder
    bgez rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bltzl :: Register -> Word16 -> Builder
    bltzl rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bgezl :: Register -> Word16 -> Builder
    bgezl rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    sllv :: Register -> Word16 -> Builder
    sllv rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    tgei :: Register -> Word16 -> Builder
    tgei rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    jalr :: Register -> Word16 -> Builder
    jalr rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    tlti :: Register -> Word16 -> Builder
    tlti rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    tltiu :: Register -> Word16 -> Builder
    tltiu rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    teqi :: Register -> Word16 -> Builder
    teqi rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    tnei :: Register -> Word16 -> Builder
    tnei rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bltzal :: Register -> Word16 -> Builder
    bltzal rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bgezal :: Register -> Word16 -> Builder
    bgezal rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bltzall :: Register -> Word16 -> Builder
    bltzall rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    bgezall :: Register -> Word16 -> Builder
    bgezall rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    dsllv :: Register -> Word16 -> Builder
    dsllv rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    synci :: Register -> Word16 -> Builder
    synci rs target = do
        word16LE ((67108864 .|. ((rs .&. 31) << 16)) .|. ((target >> 2) .&. 65535))


    addi :: Register -> Register -> Word16 -> Builder
    addi rs rt imm = do
        word16LE (((536870912 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    addiu :: Register -> Register -> Word16 -> Builder
    addiu rs rt imm = do
        word16LE (((603979776 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    andi :: Register -> Register -> Word16 -> Builder
    andi rs rt imm = do
        word16LE (((805306368 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    beq :: Register -> Register -> Word16 -> Builder
    beq rs rt imm = do
        word16LE (((268435456 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((imm .&. 65535) >> 2))


    blez :: Register -> Register -> Word16 -> Builder
    blez rs rt imm = do
        word16LE (((402653184 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((imm .&. 65535) >> 2))


    bne :: Register -> Register -> Word16 -> Builder
    bne rs rt imm = do
        word16LE (((335544320 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. ((imm .&. 65535) >> 2))


    lw :: Register -> Register -> Word16 -> Builder
    lw rs rt imm = do
        word16LE (((2348810240 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    lbu :: Register -> Register -> Word16 -> Builder
    lbu rs rt imm = do
        word16LE (((2415919104 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    lhu :: Register -> Register -> Word16 -> Builder
    lhu rs rt imm = do
        word16LE (((2483027968 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    lui :: Register -> Register -> Word16 -> Builder
    lui rs rt imm = do
        word16LE (((1006632960 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    ori :: Register -> Register -> Word16 -> Builder
    ori rs rt imm = do
        word16LE (((872415232 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    sb :: Register -> Register -> Word16 -> Builder
    sb rs rt imm = do
        word16LE (((2684354560 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    sh :: Register -> Register -> Word16 -> Builder
    sh rs rt imm = do
        word16LE (((2751463424 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    slti :: Register -> Register -> Word16 -> Builder
    slti rs rt imm = do
        word16LE (((671088640 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    sltiu :: Register -> Register -> Word16 -> Builder
    sltiu rs rt imm = do
        word16LE (((738197504 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    sw :: Register -> Register -> Word16 -> Builder
    sw rs rt imm = do
        word16LE (((2885681152 .|. ((rs .&. 31) << 21)) .|. ((rt .&. 31) << 16)) .|. (imm .&. 65535))


    j :: Word32 -> Builder
    j address = do
        word16LE (134217728 .|. ((address >> 2) .&. 67108863))


    jal :: Word32 -> Builder
    jal address = do
        word16LE (201326592 .|. ((address >> 2) .&. 67108863))


