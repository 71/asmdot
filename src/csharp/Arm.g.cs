using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{
    /// <summary>An ARM register.</summary>
    public struct Register
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register(byte value) => new Register { Value = value };
    }

    /// <summary>
    /// Condition for an ARM instruction to be executed.
    /// </summary>
    public enum Condition
    {
        /// <summary>
        /// Equal.
        /// </summary>
        EQ = 0,
        /// <summary>
        /// Not equal.
        /// </summary>
        NE = 1,
        /// <summary>
        /// Unsigned higher or same.
        /// </summary>
        HS = 2,
        /// <summary>
        /// Unsigned lower.
        /// </summary>
        LO = 3,
        /// <summary>
        /// Minus / negative.
        /// </summary>
        MI = 4,
        /// <summary>
        /// Plus / positive or zero.
        /// </summary>
        PL = 5,
        /// <summary>
        /// Overflow.
        /// </summary>
        VS = 6,
        /// <summary>
        /// No overflow.
        /// </summary>
        VC = 7,
        /// <summary>
        /// Unsigned higher.
        /// </summary>
        HI = 8,
        /// <summary>
        /// Unsigned lower or same.
        /// </summary>
        LS = 9,
        /// <summary>
        /// Signed greater than or equal.
        /// </summary>
        GE = 10,
        /// <summary>
        /// Signed less than.
        /// </summary>
        LT = 11,
        /// <summary>
        /// Signed greater than.
        /// </summary>
        GT = 12,
        /// <summary>
        /// Signed less than or equal.
        /// </summary>
        LE = 13,
        /// <summary>
        /// Always (unconditional).
        /// </summary>
        AL = 14,
        /// <summary>
        /// Unpredictable (ARMv4 or lower).
        /// </summary>
        UN = 15,
        /// <summary>
        /// Carry set.
        /// </summary>
        CS = 2,
        /// <summary>
        /// Carry clear.
        /// </summary>
        CC = 3,
    }

    /// <summary>
    /// Processor mode.
    /// </summary>
    public enum Mode
    {
        /// <summary>
        /// User mode.
        /// </summary>
        USR = 16,
        /// <summary>
        /// FIQ (high-speed data transfer) mode.
        /// </summary>
        FIQ = 17,
        /// <summary>
        /// IRQ (general-purpose interrupt handling) mode.
        /// </summary>
        IRQ = 18,
        /// <summary>
        /// Supervisor mode.
        /// </summary>
        SVC = 19,
        /// <summary>
        /// Abort mode.
        /// </summary>
        ABT = 23,
        /// <summary>
        /// Undefined mode.
        /// </summary>
        UND = 27,
        /// <summary>
        /// System (privileged) mode.
        /// </summary>
        SYS = 31,
    }

    /// <summary>
    /// Kind of a shift.
    /// </summary>
    public enum Shift
    {
        /// <summary>
        /// Logical shift left.
        /// </summary>
        LSL = 0,
        /// <summary>
        /// Logical shift right.
        /// </summary>
        LSR = 1,
        /// <summary>
        /// Arithmetic shift right.
        /// </summary>
        ASR = 2,
        /// <summary>
        /// Rotate right.
        /// </summary>
        ROR = 3,
        /// <summary>
        /// Shifted right by one bit.
        /// </summary>
        RRX = 3,
    }

    /// <summary>
    /// Kind of a right rotation.
    /// </summary>
    public enum Rotation
    {
        /// <summary>
        /// Do not rotate.
        /// </summary>
        NOP = 0,
        /// <summary>
        /// Rotate 8 bits to the right.
        /// </summary>
        ROR8 = 1,
        /// <summary>
        /// Rotate 16 bits to the right.
        /// </summary>
        ROR16 = 2,
        /// <summary>
        /// Rotate 24 bits to the right.
        /// </summary>
        ROR24 = 3,
    }

    /// <summary>
    /// Field mask bits.
    /// </summary>
    [Flags]
    public enum FieldMask
    {
        /// <summary>
        /// Control field mask bit.
        /// </summary>
        C = 1,
        /// <summary>
        /// Extension field mask bit.
        /// </summary>
        X = 2,
        /// <summary>
        /// Status field mask bit.
        /// </summary>
        S = 4,
        /// <summary>
        /// Flags field mask bit.
        /// </summary>
        F = 8,
    }

    /// <summary>
    /// Interrupt flags.
    /// </summary>
    [Flags]
    public enum InterruptFlags
    {
        /// <summary>
        /// FIQ interrupt bit.
        /// </summary>
        F = 1,
        /// <summary>
        /// IRQ interrupt bit.
        /// </summary>
        I = 2,
        /// <summary>
        /// Imprecise data abort bit.
        /// </summary>
        A = 4,
    }

    partial class Arm
    {
        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((1280 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((256 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((0 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'eor' instruction.</summary>
        public static void eor(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((1024 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'orr' instruction.</summary>
        public static void orr(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((384 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rsb' instruction.</summary>
        public static void rsb(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((1536 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rsc' instruction.</summary>
        public static void rsc(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((1792 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sbc' instruction.</summary>
        public static void sbc(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((768 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((512 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bkpt' instruction.</summary>
        public static void bkpt(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 234882183;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'b' instruction.</summary>
        public static void b(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (80 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bic' instruction.</summary>
        public static void bic(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((896 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'blx' instruction.</summary>
        public static void blx(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (218100864 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bx' instruction.</summary>
        public static void bx(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (150992000 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bxj' instruction.</summary>
        public static void bxj(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (83883136 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'blxun' instruction.</summary>
        public static void blxun(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 95;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cdp' instruction.</summary>
        public static void cdp(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (112 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'clz' instruction.</summary>
        public static void clz(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((150009472 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cmn' instruction.</summary>
        public static void cmn(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((3712 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((2688 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpy' instruction.</summary>
        public static void cpy(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((1408 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cps' instruction.</summary>
        public static void cps(ref IntPtr buffer, Mode mode)
        {
            *(uint*)(*buf) = (16527 | (mode << 24));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsie' instruction.</summary>
        public static void cpsie(ref IntPtr buffer, InterruptFlags iflags)
        {
            *(uint*)(*buf) = (4239 | (iflags << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsid' instruction.</summary>
        public static void cpsid(ref IntPtr buffer, InterruptFlags iflags)
        {
            *(uint*)(*buf) = (12431 | (iflags << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsie_mode' instruction.</summary>
        public static void cpsie_mode(ref IntPtr buffer, InterruptFlags iflags, Mode mode)
        {
            *(uint*)(*buf) = ((20623 | (iflags << 20)) | (mode << 24));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsid_mode' instruction.</summary>
        public static void cpsid_mode(ref IntPtr buffer, InterruptFlags iflags, Mode mode)
        {
            *(uint*)(*buf) = ((28815 | (iflags << 20)) | (mode << 24));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldc' instruction.</summary>
        public static void ldc(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((560 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldm1' instruction.</summary>
        public static void ldm1(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((528 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldm2' instruction.</summary>
        public static void ldm2(ref IntPtr buffer, Condition cond, Register rn)
        {
            *(uint*)(*buf) = ((656 | cond) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldm3' instruction.</summary>
        public static void ldm3(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((17040 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldr' instruction.</summary>
        public static void ldr(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((544 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrb' instruction.</summary>
        public static void ldrb(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((672 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrbt' instruction.</summary>
        public static void ldrbt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((1824 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrd' instruction.</summary>
        public static void ldrd(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((2883584 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrex' instruction.</summary>
        public static void ldrex(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((4193257856 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrh' instruction.</summary>
        public static void ldrh(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((3408384 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrsb' instruction.</summary>
        public static void ldrsb(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((2884096 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrsh' instruction.</summary>
        public static void ldrsh(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((3932672 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrt' instruction.</summary>
        public static void ldrt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((1568 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mcr' instruction.</summary>
        public static void mcr(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((131184 | cond) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mcrr' instruction.</summary>
        public static void mcrr(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mla' instruction.</summary>
        public static void mla(ref IntPtr buffer, Condition cond, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((150995968 | cond) | (s << 11)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mov' instruction.</summary>
        public static void mov(ref IntPtr buffer, Condition cond, bool i, bool s, Register rd)
        {
            *(uint*)(*buf) = ((((1408 | cond) | (i << 6)) | (s << 11)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mrc' instruction.</summary>
        public static void mrc(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((131440 | cond) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mrrc' instruction.</summary>
        public static void mrrc(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((2608 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mrs' instruction.</summary>
        public static void mrs(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((61568 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mul' instruction.</summary>
        public static void mul(ref IntPtr buffer, Condition cond, bool s, Register rd)
        {
            *(uint*)(*buf) = (((150994944 | cond) | (s << 11)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mvn' instruction.</summary>
        public static void mvn(ref IntPtr buffer, Condition cond, bool i, bool s, Register rd)
        {
            *(uint*)(*buf) = ((((1920 | cond) | (i << 6)) | (s << 11)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'msr_imm' instruction.</summary>
        public static void msr_imm(ref IntPtr buffer, Condition cond, FieldMask fieldmask)
        {
            *(uint*)(*buf) = ((984256 | cond) | (fieldmask << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'msr_reg' instruction.</summary>
        public static void msr_reg(ref IntPtr buffer, Condition cond, FieldMask fieldmask)
        {
            *(uint*)(*buf) = ((984192 | cond) | (fieldmask << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'pkhbt' instruction.</summary>
        public static void pkhbt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((134218080 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'pkhtb' instruction.</summary>
        public static void pkhtb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((167772512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'pld' instruction.</summary>
        public static void pld(ref IntPtr buffer, bool i, Register rn)
        {
            *(uint*)(*buf) = ((492975 | (i << 6)) | (rn << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qadd' instruction.</summary>
        public static void qadd(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((167772288 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qadd16' instruction.</summary>
        public static void qadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((149947488 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qadd8' instruction.</summary>
        public static void qadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((166724704 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qaddsubx' instruction.</summary>
        public static void qaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((217056352 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qdadd' instruction.</summary>
        public static void qdadd(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((167772800 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qdsub' instruction.</summary>
        public static void qdsub(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((167773824 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsub' instruction.</summary>
        public static void qsub(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((167773312 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsub16' instruction.</summary>
        public static void qsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((250610784 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsub8' instruction.</summary>
        public static void qsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((267388000 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsubaddx' instruction.</summary>
        public static void qsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((183501920 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rev' instruction.</summary>
        public static void rev(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((217120096 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rev16' instruction.</summary>
        public static void rev16(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((233897312 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'revsh' instruction.</summary>
        public static void revsh(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((233897824 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rfe' instruction.</summary>
        public static void rfe(ref IntPtr buffer, bool write, Register rn)
        {
            *(uint*)(*buf) = ((1311263 | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sadd16' instruction.</summary>
        public static void sadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((149948512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sadd8' instruction.</summary>
        public static void sadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((166725728 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'saddsubx' instruction.</summary>
        public static void saddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((217057376 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sel' instruction.</summary>
        public static void sel(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((233832800 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'setendbe' instruction.</summary>
        public static void setendbe(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 4227215;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'setendle' instruction.</summary>
        public static void setendle(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 32911;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shadd16' instruction.</summary>
        public static void shadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((149949536 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shadd8' instruction.</summary>
        public static void shadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((166726752 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shaddsubx' instruction.</summary>
        public static void shaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((217058400 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shsub16' instruction.</summary>
        public static void shsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((250612832 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shsub8' instruction.</summary>
        public static void shsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((267390048 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shsubaddx' instruction.</summary>
        public static void shsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((183503968 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlabb' instruction.</summary>
        public static void smlabb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777344 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlabt' instruction.</summary>
        public static void smlabt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((83886208 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlatb' instruction.</summary>
        public static void smlatb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((50331776 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlatt' instruction.</summary>
        public static void smlatt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((117440640 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlad' instruction.</summary>
        public static void smlad(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((67109088 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlal' instruction.</summary>
        public static void smlal(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((150996736 | cond) | (s << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlalbb' instruction.</summary>
        public static void smlalbb(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (16777856 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlalbt' instruction.</summary>
        public static void smlalbt(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (83886720 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlaltb' instruction.</summary>
        public static void smlaltb(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (50332288 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlaltt' instruction.</summary>
        public static void smlaltt(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (117441152 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlald' instruction.</summary>
        public static void smlald(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (67109600 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlawb' instruction.</summary>
        public static void smlawb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16778368 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlawt' instruction.</summary>
        public static void smlawt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((50332800 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlsd' instruction.</summary>
        public static void smlsd(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((100663520 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlsld' instruction.</summary>
        public static void smlsld(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (100664032 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smmla' instruction.</summary>
        public static void smmla(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((134220512 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smmls' instruction.</summary>
        public static void smmls(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((184552160 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smmul' instruction.</summary>
        public static void smmul(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((135203552 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smuad' instruction.</summary>
        public static void smuad(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((68092128 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulbb' instruction.</summary>
        public static void smulbb(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((16778880 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulbt' instruction.</summary>
        public static void smulbt(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((83887744 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smultb' instruction.</summary>
        public static void smultb(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((50333312 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smultt' instruction.</summary>
        public static void smultt(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((117442176 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smull' instruction.</summary>
        public static void smull(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((301991424 | cond) | (s << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulwb' instruction.</summary>
        public static void smulwb(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((83887232 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulwt' instruction.</summary>
        public static void smulwt(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((117441664 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smusd' instruction.</summary>
        public static void smusd(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((101646560 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'srs' instruction.</summary>
        public static void srs(ref IntPtr buffer, bool write, Mode mode)
        {
            *(uint*)(*buf) = ((2632863 | (write << 8)) | (mode << 26));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssat' instruction.</summary>
        public static void ssat(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((133728 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssat16' instruction.</summary>
        public static void ssat16(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((13567328 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssub16' instruction.</summary>
        public static void ssub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((250611808 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssub8' instruction.</summary>
        public static void ssub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((267389024 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssubaddx' instruction.</summary>
        public static void ssubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((183502944 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void stc(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((48 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'stm1' instruction.</summary>
        public static void stm1(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((16 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'stm2' instruction.</summary>
        public static void stm2(ref IntPtr buffer, Condition cond, Register rn)
        {
            *(uint*)(*buf) = ((144 | cond) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'str' instruction.</summary>
        public static void str(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((32 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strb' instruction.</summary>
        public static void strb(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((160 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strbt' instruction.</summary>
        public static void strbt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((800 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strd' instruction.</summary>
        public static void strd(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((3932160 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strex' instruction.</summary>
        public static void strex(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((83362176 | cond) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strh' instruction.</summary>
        public static void strh(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((3407872 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strt' instruction.</summary>
        public static void strt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((544 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'swi' instruction.</summary>
        public static void swi(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (240 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'swp' instruction.</summary>
        public static void swp(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((150995072 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'swpb' instruction.</summary>
        public static void swpb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((150995584 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtab' instruction.</summary>
        public static void sxtab(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234882400 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtab16' instruction.</summary>
        public static void sxtab16(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234881376 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtah' instruction.</summary>
        public static void sxtah(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234884448 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtb' instruction.</summary>
        public static void sxtb(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234943840 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtb16' instruction.</summary>
        public static void sxtb16(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234942816 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxth' instruction.</summary>
        public static void sxth(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234945888 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'teq' instruction.</summary>
        public static void teq(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((3200 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'tst' instruction.</summary>
        public static void tst(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((2176 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uadd16' instruction.</summary>
        public static void uadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((149949024 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uadd8' instruction.</summary>
        public static void uadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((166726240 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uaddsubx' instruction.</summary>
        public static void uaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((217057888 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhadd16' instruction.</summary>
        public static void uhadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((149950048 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhadd8' instruction.</summary>
        public static void uhadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((166727264 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhaddsubx' instruction.</summary>
        public static void uhaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((217058912 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhsub16' instruction.</summary>
        public static void uhsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((250613344 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhsub8' instruction.</summary>
        public static void uhsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((267390560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhsubaddx' instruction.</summary>
        public static void uhsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((183504480 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'umaal' instruction.</summary>
        public static void umaal(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (150995456 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'umlal' instruction.</summary>
        public static void umlal(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((150996224 | cond) | (s << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'umull' instruction.</summary>
        public static void umull(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((150995200 | cond) | (s << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqadd16' instruction.</summary>
        public static void uqadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((149948000 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqadd8' instruction.</summary>
        public static void uqadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((166725216 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqaddsubx' instruction.</summary>
        public static void uqaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((217056864 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqsub16' instruction.</summary>
        public static void uqsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((250611296 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqsub8' instruction.</summary>
        public static void uqsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((267388512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqsubaddx' instruction.</summary>
        public static void uqsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((183502432 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usad8' instruction.</summary>
        public static void usad8(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((135201248 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usada8' instruction.</summary>
        public static void usada8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((134218208 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usat' instruction.</summary>
        public static void usat(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((67424 | cond) | (rd << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usat16' instruction.</summary>
        public static void usat16(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((13567840 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usub16' instruction.</summary>
        public static void usub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((250612320 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usub8' instruction.</summary>
        public static void usub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((267389536 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usubaddx' instruction.</summary>
        public static void usubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((183503456 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtab' instruction.</summary>
        public static void uxtab(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234882912 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtab16' instruction.</summary>
        public static void uxtab16(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234881888 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtah' instruction.</summary>
        public static void uxtah(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234884960 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtb' instruction.</summary>
        public static void uxtb(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234944352 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtb16' instruction.</summary>
        public static void uxtb16(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234943328 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxth' instruction.</summary>
        public static void uxth(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234946400 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }


    }
}
