module Asm.Internal.Mips where

    import Control.Exception (assert)
    import Data.Bits
    import Data.ByteString.Builder
    import Data.Int
    import Data.Semigroup (Semigroup((<>)))
    import Data.Word

    -- | A Mips register.
    newtype Register = Register Word8

    zero, at, v0, v1, a0, a1, a2, a3, t0, t1, t2, t3, t4, t5, t6, t7, s0, s1, s2, s3, s4, s5, s6, s7, t8, t9, k0, k1, gp, sp, fp, ra :: Register
    zero = Register 0
    at = Register 1
    v0 = Register 2
    v1 = Register 3
    a0 = Register 4
    a1 = Register 5
    a2 = Register 6
    a3 = Register 7
    t0 = Register 8
    t1 = Register 9
    t2 = Register 10
    t3 = Register 11
    t4 = Register 12
    t5 = Register 13
    t6 = Register 14
    t7 = Register 15
    s0 = Register 16
    s1 = Register 17
    s2 = Register 18
    s3 = Register 19
    s4 = Register 20
    s5 = Register 21
    s6 = Register 22
    s7 = Register 23
    t8 = Register 24
    t9 = Register 25
    k0 = Register 26
    k1 = Register 27
    gp = Register 28
    sp = Register 29
    fp = Register 30
    ra = Register 31


    sll :: Register -> Register -> Register -> Word8 -> Builder
    sll rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((0 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    movci :: Register -> Register -> Register -> Word8 -> Builder
    movci rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((1 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    srl :: Register -> Register -> Register -> Word8 -> Builder
    srl rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((2 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    sra :: Register -> Register -> Register -> Word8 -> Builder
    sra rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((3 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    sllv_r :: Register -> Register -> Register -> Word8 -> Builder
    sllv_r rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((4 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    srlv :: Register -> Register -> Register -> Word8 -> Builder
    srlv rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((6 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    srav :: Register -> Register -> Register -> Word8 -> Builder
    srav rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((7 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    jr :: Register -> Register -> Register -> Word8 -> Builder
    jr rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((8 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    jalr_r :: Register -> Register -> Register -> Word8 -> Builder
    jalr_r rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((9 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    movz :: Register -> Register -> Register -> Word8 -> Builder
    movz rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((10 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    movn :: Register -> Register -> Register -> Word8 -> Builder
    movn rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((11 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    syscall :: Register -> Register -> Register -> Word8 -> Builder
    syscall rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((12 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    breakpoint :: Register -> Register -> Register -> Word8 -> Builder
    breakpoint rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((13 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    sync :: Register -> Register -> Register -> Word8 -> Builder
    sync rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((15 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    mfhi :: Register -> Register -> Register -> Word8 -> Builder
    mfhi rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((16 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    mthi :: Register -> Register -> Register -> Word8 -> Builder
    mthi rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((17 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    mflo :: Register -> Register -> Register -> Word8 -> Builder
    mflo rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((18 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsllv_r :: Register -> Register -> Register -> Word8 -> Builder
    dsllv_r rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((20 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsrlv :: Register -> Register -> Register -> Word8 -> Builder
    dsrlv rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((22 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsrav :: Register -> Register -> Register -> Word8 -> Builder
    dsrav rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((23 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    mult :: Register -> Register -> Register -> Word8 -> Builder
    mult rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((24 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    multu :: Register -> Register -> Register -> Word8 -> Builder
    multu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((25 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    div_ :: Register -> Register -> Register -> Word8 -> Builder
    div_ rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((26 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    divu :: Register -> Register -> Register -> Word8 -> Builder
    divu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((27 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dmult :: Register -> Register -> Register -> Word8 -> Builder
    dmult rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((28 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dmultu :: Register -> Register -> Register -> Word8 -> Builder
    dmultu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((29 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    ddiv :: Register -> Register -> Register -> Word8 -> Builder
    ddiv rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((30 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    ddivu :: Register -> Register -> Register -> Word8 -> Builder
    ddivu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((31 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    add :: Register -> Register -> Register -> Word8 -> Builder
    add rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((32 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    addu :: Register -> Register -> Register -> Word8 -> Builder
    addu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((33 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    sub :: Register -> Register -> Register -> Word8 -> Builder
    sub rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((34 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    subu :: Register -> Register -> Register -> Word8 -> Builder
    subu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((35 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    and :: Register -> Register -> Register -> Word8 -> Builder
    and rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((36 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    or :: Register -> Register -> Register -> Word8 -> Builder
    or rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((37 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    xor :: Register -> Register -> Register -> Word8 -> Builder
    xor rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((38 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    nor :: Register -> Register -> Register -> Word8 -> Builder
    nor rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((39 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    slt :: Register -> Register -> Register -> Word8 -> Builder
    slt rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((42 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    sltu :: Register -> Register -> Register -> Word8 -> Builder
    sltu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((43 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dadd :: Register -> Register -> Register -> Word8 -> Builder
    dadd rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((44 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    daddu :: Register -> Register -> Register -> Word8 -> Builder
    daddu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((45 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsub :: Register -> Register -> Register -> Word8 -> Builder
    dsub rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((46 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsubu :: Register -> Register -> Register -> Word8 -> Builder
    dsubu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((47 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    tge :: Register -> Register -> Register -> Word8 -> Builder
    tge rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((48 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    tgeu :: Register -> Register -> Register -> Word8 -> Builder
    tgeu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((49 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    tlt :: Register -> Register -> Register -> Word8 -> Builder
    tlt rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((50 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    tltu :: Register -> Register -> Register -> Word8 -> Builder
    tltu rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((51 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    teq :: Register -> Register -> Register -> Word8 -> Builder
    teq rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((52 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    tne :: Register -> Register -> Register -> Word8 -> Builder
    tne rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((54 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsll :: Register -> Register -> Register -> Word8 -> Builder
    dsll rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((56 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dslr :: Register -> Register -> Register -> Word8 -> Builder
    dslr rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((58 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    dsra :: Register -> Register -> Register -> Word8 -> Builder
    dsra rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((59 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    mhc0 :: Register -> Register -> Register -> Word8 -> Builder
    mhc0 rd rs rt shift =
        let rd = fromIntegral rd in
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let shift = fromIntegral shift in
        word32LE ((((1073741824 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((rd .&. 31) `shiftL` 11)) .|. ((shift .&. 31) `shiftL` 6))


    btlz :: Register -> Word16 -> Builder
    btlz rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bgez :: Register -> Word16 -> Builder
    bgez rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bltzl :: Register -> Word16 -> Builder
    bltzl rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bgezl :: Register -> Word16 -> Builder
    bgezl rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    sllv_ri :: Register -> Word16 -> Builder
    sllv_ri rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    tgei :: Register -> Word16 -> Builder
    tgei rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    jalr_ri :: Register -> Word16 -> Builder
    jalr_ri rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    tlti :: Register -> Word16 -> Builder
    tlti rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    tltiu :: Register -> Word16 -> Builder
    tltiu rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    teqi :: Register -> Word16 -> Builder
    teqi rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    tnei :: Register -> Word16 -> Builder
    tnei rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bltzal :: Register -> Word16 -> Builder
    bltzal rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bgezal :: Register -> Word16 -> Builder
    bgezal rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bltzall :: Register -> Word16 -> Builder
    bltzall rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    bgezall :: Register -> Word16 -> Builder
    bgezall rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    dsllv_ri :: Register -> Word16 -> Builder
    dsllv_ri rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    synci :: Register -> Word16 -> Builder
    synci rs target =
        let rs = fromIntegral rs in
        let target = fromIntegral target in
        word32LE ((67108864 .|. ((rs .&. 31) `shiftL` 16)) .|. ((target `shiftR` 2) .&. 65535))


    addi :: Register -> Register -> Word16 -> Builder
    addi rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((536870912 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    addiu :: Register -> Register -> Word16 -> Builder
    addiu rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((603979776 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    andi :: Register -> Register -> Word16 -> Builder
    andi rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((805306368 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    beq :: Register -> Register -> Word16 -> Builder
    beq rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((268435456 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((imm .&. 65535) `shiftR` 2))


    blez :: Register -> Register -> Word16 -> Builder
    blez rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((402653184 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((imm .&. 65535) `shiftR` 2))


    bne :: Register -> Register -> Word16 -> Builder
    bne rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((335544320 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. ((imm .&. 65535) `shiftR` 2))


    lw :: Register -> Register -> Word16 -> Builder
    lw rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((2348810240 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    lbu :: Register -> Register -> Word16 -> Builder
    lbu rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((2415919104 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    lhu :: Register -> Register -> Word16 -> Builder
    lhu rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((2483027968 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    lui :: Register -> Register -> Word16 -> Builder
    lui rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((1006632960 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    ori :: Register -> Register -> Word16 -> Builder
    ori rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((872415232 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    sb :: Register -> Register -> Word16 -> Builder
    sb rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((2684354560 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    sh :: Register -> Register -> Word16 -> Builder
    sh rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((2751463424 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    slti :: Register -> Register -> Word16 -> Builder
    slti rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((671088640 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    sltiu :: Register -> Register -> Word16 -> Builder
    sltiu rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((738197504 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    sw :: Register -> Register -> Word16 -> Builder
    sw rs rt imm =
        let rs = fromIntegral rs in
        let rt = fromIntegral rt in
        let imm = fromIntegral imm in
        word32LE (((2885681152 .|. ((rs .&. 31) `shiftL` 21)) .|. ((rt .&. 31) `shiftL` 16)) .|. (imm .&. 65535))


    j :: Word32 -> Builder
    j address =
        let address = fromIntegral address in
        word32LE (134217728 .|. ((address `shiftR` 2) .&. 67108863))


    jal :: Word32 -> Builder
    jal address =
        let address = fromIntegral address in
        word32LE (201326592 .|. ((address `shiftR` 2) .&. 67108863))


