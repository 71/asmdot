module Asm.Internal.X86 where

    import Data.ByteString.Builder

    -- | An x86 8-bits register.
    newtype Register8 = Register8 Word8

    al, cl, dl, bl, spl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b :: Register8
    al = Register8 0
    cl = Register8 1
    dl = Register8 2
    bl = Register8 3
    spl = Register8 4
    bpl = Register8 5
    sil = Register8 6
    dil = Register8 7
    r8b = Register8 8
    r9b = Register8 9
    r10b = Register8 10
    r11b = Register8 11
    r12b = Register8 12
    r13b = Register8 13
    r14b = Register8 14
    r15b = Register8 15


    -- | An x86 16-bits register.
    newtype Register16 = Register16 Word8

    ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w :: Register16
    ax = Register16 0
    cx = Register16 1
    dx = Register16 2
    bx = Register16 3
    sp = Register16 4
    bp = Register16 5
    si = Register16 6
    di = Register16 7
    r8w = Register16 8
    r9w = Register16 9
    r10w = Register16 10
    r11w = Register16 11
    r12w = Register16 12
    r13w = Register16 13
    r14w = Register16 14
    r15w = Register16 15


    -- | An x86 32-bits register.
    newtype Register32 = Register32 Word8

    eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d :: Register32
    eax = Register32 0
    ecx = Register32 1
    edx = Register32 2
    ebx = Register32 3
    esp = Register32 4
    ebp = Register32 5
    esi = Register32 6
    edi = Register32 7
    r8d = Register32 8
    r9d = Register32 9
    r10d = Register32 10
    r11d = Register32 11
    r12d = Register32 12
    r13d = Register32 13
    r14d = Register32 14
    r15d = Register32 15


    -- | An x86 64-bits register.
    newtype Register64 = Register64 Word8

    rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15 :: Register64
    rax = Register64 0
    rcx = Register64 1
    rdx = Register64 2
    rbx = Register64 3
    rsp = Register64 4
    rbp = Register64 5
    rsi = Register64 6
    rdi = Register64 7
    r8 = Register64 8
    r9 = Register64 9
    r10 = Register64 10
    r11 = Register64 11
    r12 = Register64 12
    r13 = Register64 13
    r14 = Register64 14
    r15 = Register64 15


    -- | An x86 128-bits register.
    newtype Register128 = Register128 Word8

    pushf :: Builder
    pushf  = do
        word8 156


    popf :: Builder
    popf  = do
        word8 157


    ret :: Builder
    ret  = do
        word8 195


    clc :: Builder
    clc  = do
        word8 248


    stc :: Builder
    stc  = do
        word8 249


    cli :: Builder
    cli  = do
        word8 250


    sti :: Builder
    sti  = do
        word8 251


    cld :: Builder
    cld  = do
        word8 252


    std :: Builder
    std  = do
        word8 253


    jo_imm8 :: Int8 -> Builder
    jo_imm8 operand = do
        word8 112
        int8 operand


    jno_imm8 :: Int8 -> Builder
    jno_imm8 operand = do
        word8 113
        int8 operand


    jb_imm8 :: Int8 -> Builder
    jb_imm8 operand = do
        word8 114
        int8 operand


    jnae_imm8 :: Int8 -> Builder
    jnae_imm8 operand = do
        word8 114
        int8 operand


    jc_imm8 :: Int8 -> Builder
    jc_imm8 operand = do
        word8 114
        int8 operand


    jnb_imm8 :: Int8 -> Builder
    jnb_imm8 operand = do
        word8 115
        int8 operand


    jae_imm8 :: Int8 -> Builder
    jae_imm8 operand = do
        word8 115
        int8 operand


    jnc_imm8 :: Int8 -> Builder
    jnc_imm8 operand = do
        word8 115
        int8 operand


    jz_imm8 :: Int8 -> Builder
    jz_imm8 operand = do
        word8 116
        int8 operand


    je_imm8 :: Int8 -> Builder
    je_imm8 operand = do
        word8 116
        int8 operand


    jnz_imm8 :: Int8 -> Builder
    jnz_imm8 operand = do
        word8 117
        int8 operand


    jne_imm8 :: Int8 -> Builder
    jne_imm8 operand = do
        word8 117
        int8 operand


    jbe_imm8 :: Int8 -> Builder
    jbe_imm8 operand = do
        word8 118
        int8 operand


    jna_imm8 :: Int8 -> Builder
    jna_imm8 operand = do
        word8 118
        int8 operand


    jnbe_imm8 :: Int8 -> Builder
    jnbe_imm8 operand = do
        word8 119
        int8 operand


    ja_imm8 :: Int8 -> Builder
    ja_imm8 operand = do
        word8 119
        int8 operand


    js_imm8 :: Int8 -> Builder
    js_imm8 operand = do
        word8 120
        int8 operand


    jns_imm8 :: Int8 -> Builder
    jns_imm8 operand = do
        word8 121
        int8 operand


    jp_imm8 :: Int8 -> Builder
    jp_imm8 operand = do
        word8 122
        int8 operand


    jpe_imm8 :: Int8 -> Builder
    jpe_imm8 operand = do
        word8 122
        int8 operand


    jnp_imm8 :: Int8 -> Builder
    jnp_imm8 operand = do
        word8 123
        int8 operand


    jpo_imm8 :: Int8 -> Builder
    jpo_imm8 operand = do
        word8 123
        int8 operand


    jl_imm8 :: Int8 -> Builder
    jl_imm8 operand = do
        word8 124
        int8 operand


    jnge_imm8 :: Int8 -> Builder
    jnge_imm8 operand = do
        word8 124
        int8 operand


    jnl_imm8 :: Int8 -> Builder
    jnl_imm8 operand = do
        word8 125
        int8 operand


    jge_imm8 :: Int8 -> Builder
    jge_imm8 operand = do
        word8 125
        int8 operand


    jle_imm8 :: Int8 -> Builder
    jle_imm8 operand = do
        word8 126
        int8 operand


    jng_imm8 :: Int8 -> Builder
    jng_imm8 operand = do
        word8 126
        int8 operand


    jnle_imm8 :: Int8 -> Builder
    jnle_imm8 operand = do
        word8 127
        int8 operand


    jg_imm8 :: Int8 -> Builder
    jg_imm8 operand = do
        word8 127
        int8 operand


    inc_r16 :: Register16 -> Builder
    inc_r16 operand = do
        word8 (102 + get_prefix operand)
        word8 (64 + operand)


    inc_r32 :: Register32 -> Builder
    inc_r32 operand = do
        if (operand > 7) then
            word8 65
        word8 (64 + operand)


    dec_r16 :: Register16 -> Builder
    dec_r16 operand = do
        word8 (102 + get_prefix operand)
        word8 (72 + operand)


    dec_r32 :: Register32 -> Builder
    dec_r32 operand = do
        if (operand > 7) then
            word8 65
        word8 (72 + operand)


    push_r16 :: Register16 -> Builder
    push_r16 operand = do
        word8 (102 + get_prefix operand)
        word8 (80 + operand)


    push_r32 :: Register32 -> Builder
    push_r32 operand = do
        if (operand > 7) then
            word8 65
        word8 (80 + operand)


    pop_r16 :: Register16 -> Builder
    pop_r16 operand = do
        word8 (102 + get_prefix operand)
        word8 (88 + operand)


    pop_r32 :: Register32 -> Builder
    pop_r32 operand = do
        if (operand > 7) then
            word8 65
        word8 (88 + operand)


    pop_r64 :: Register64 -> Builder
    pop_r64 operand = do
        word8 (72 + get_prefix operand)
        word8 (88 + operand)


    add_rm8_imm8 :: Register8 -> Int8 -> Builder
    add_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 0)
        int8 value


    or_rm8_imm8 :: Register8 -> Int8 -> Builder
    or_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 1)
        int8 value


    adc_rm8_imm8 :: Register8 -> Int8 -> Builder
    adc_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 2)
        int8 value


    sbb_rm8_imm8 :: Register8 -> Int8 -> Builder
    sbb_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 3)
        int8 value


    and_rm8_imm8 :: Register8 -> Int8 -> Builder
    and_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 4)
        int8 value


    sub_rm8_imm8 :: Register8 -> Int8 -> Builder
    sub_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 5)
        int8 value


    xor_rm8_imm8 :: Register8 -> Int8 -> Builder
    xor_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 6)
        int8 value


    cmp_rm8_imm8 :: Register8 -> Int8 -> Builder
    cmp_rm8_imm8 reg value = do
        word8 128
        word8 (reg + 7)
        int8 value


    add_rm16_imm16 :: Register16 -> Int16 -> Builder
    add_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 0)
        int8LE value


    add_rm16_imm32 :: Register16 -> Int32 -> Builder
    add_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 0)
        int16LE value


    add_rm32_imm16 :: Register32 -> Int16 -> Builder
    add_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 0)
        int8LE value


    add_rm32_imm32 :: Register32 -> Int32 -> Builder
    add_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 0)
        int16LE value


    or_rm16_imm16 :: Register16 -> Int16 -> Builder
    or_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 1)
        int8LE value


    or_rm16_imm32 :: Register16 -> Int32 -> Builder
    or_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 1)
        int16LE value


    or_rm32_imm16 :: Register32 -> Int16 -> Builder
    or_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 1)
        int8LE value


    or_rm32_imm32 :: Register32 -> Int32 -> Builder
    or_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 1)
        int16LE value


    adc_rm16_imm16 :: Register16 -> Int16 -> Builder
    adc_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 2)
        int8LE value


    adc_rm16_imm32 :: Register16 -> Int32 -> Builder
    adc_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 2)
        int16LE value


    adc_rm32_imm16 :: Register32 -> Int16 -> Builder
    adc_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 2)
        int8LE value


    adc_rm32_imm32 :: Register32 -> Int32 -> Builder
    adc_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 2)
        int16LE value


    sbb_rm16_imm16 :: Register16 -> Int16 -> Builder
    sbb_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 3)
        int8LE value


    sbb_rm16_imm32 :: Register16 -> Int32 -> Builder
    sbb_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 3)
        int16LE value


    sbb_rm32_imm16 :: Register32 -> Int16 -> Builder
    sbb_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 3)
        int8LE value


    sbb_rm32_imm32 :: Register32 -> Int32 -> Builder
    sbb_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 3)
        int16LE value


    and_rm16_imm16 :: Register16 -> Int16 -> Builder
    and_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 4)
        int8LE value


    and_rm16_imm32 :: Register16 -> Int32 -> Builder
    and_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 4)
        int16LE value


    and_rm32_imm16 :: Register32 -> Int16 -> Builder
    and_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 4)
        int8LE value


    and_rm32_imm32 :: Register32 -> Int32 -> Builder
    and_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 4)
        int16LE value


    sub_rm16_imm16 :: Register16 -> Int16 -> Builder
    sub_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 5)
        int8LE value


    sub_rm16_imm32 :: Register16 -> Int32 -> Builder
    sub_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 5)
        int16LE value


    sub_rm32_imm16 :: Register32 -> Int16 -> Builder
    sub_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 5)
        int8LE value


    sub_rm32_imm32 :: Register32 -> Int32 -> Builder
    sub_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 5)
        int16LE value


    xor_rm16_imm16 :: Register16 -> Int16 -> Builder
    xor_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 6)
        int8LE value


    xor_rm16_imm32 :: Register16 -> Int32 -> Builder
    xor_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 6)
        int16LE value


    xor_rm32_imm16 :: Register32 -> Int16 -> Builder
    xor_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 6)
        int8LE value


    xor_rm32_imm32 :: Register32 -> Int32 -> Builder
    xor_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 6)
        int16LE value


    cmp_rm16_imm16 :: Register16 -> Int16 -> Builder
    cmp_rm16_imm16 reg value = do
        word8 102
        word8 129
        word8 (reg + 7)
        int8LE value


    cmp_rm16_imm32 :: Register16 -> Int32 -> Builder
    cmp_rm16_imm32 reg value = do
        word8 102
        word8 129
        word8 (reg + 7)
        int16LE value


    cmp_rm32_imm16 :: Register32 -> Int16 -> Builder
    cmp_rm32_imm16 reg value = do
        word8 129
        word8 (reg + 7)
        int8LE value


    cmp_rm32_imm32 :: Register32 -> Int32 -> Builder
    cmp_rm32_imm32 reg value = do
        word8 129
        word8 (reg + 7)
        int16LE value


    add_rm16_imm8 :: Register16 -> Int8 -> Builder
    add_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 0)
        int8 value


    add_rm32_imm8 :: Register32 -> Int8 -> Builder
    add_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 0)
        int8 value


    or_rm16_imm8 :: Register16 -> Int8 -> Builder
    or_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 1)
        int8 value


    or_rm32_imm8 :: Register32 -> Int8 -> Builder
    or_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 1)
        int8 value


    adc_rm16_imm8 :: Register16 -> Int8 -> Builder
    adc_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 2)
        int8 value


    adc_rm32_imm8 :: Register32 -> Int8 -> Builder
    adc_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 2)
        int8 value


    sbb_rm16_imm8 :: Register16 -> Int8 -> Builder
    sbb_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 3)
        int8 value


    sbb_rm32_imm8 :: Register32 -> Int8 -> Builder
    sbb_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 3)
        int8 value


    and_rm16_imm8 :: Register16 -> Int8 -> Builder
    and_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 4)
        int8 value


    and_rm32_imm8 :: Register32 -> Int8 -> Builder
    and_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 4)
        int8 value


    sub_rm16_imm8 :: Register16 -> Int8 -> Builder
    sub_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 5)
        int8 value


    sub_rm32_imm8 :: Register32 -> Int8 -> Builder
    sub_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 5)
        int8 value


    xor_rm16_imm8 :: Register16 -> Int8 -> Builder
    xor_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 6)
        int8 value


    xor_rm32_imm8 :: Register32 -> Int8 -> Builder
    xor_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 6)
        int8 value


    cmp_rm16_imm8 :: Register16 -> Int8 -> Builder
    cmp_rm16_imm8 reg value = do
        word8 102
        word8 131
        word8 (reg + 7)
        int8 value


    cmp_rm32_imm8 :: Register32 -> Int8 -> Builder
    cmp_rm32_imm8 reg value = do
        word8 131
        word8 (reg + 7)
        int8 value


