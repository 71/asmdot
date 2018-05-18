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
            *(uint*)(*buf) = (((((10485760 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((8388608 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((0 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'eor' instruction.</summary>
        public static void eor(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((2097152 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'orr' instruction.</summary>
        public static void orr(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((25165824 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rsb' instruction.</summary>
        public static void rsb(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((6291456 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rsc' instruction.</summary>
        public static void rsc(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((14680064 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sbc' instruction.</summary>
        public static void sbc(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((12582912 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((4194304 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bkpt' instruction.</summary>
        public static void bkpt(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 3776970864;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'b' instruction.</summary>
        public static void b(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (167772160 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bic' instruction.</summary>
        public static void bic(ref IntPtr buffer, Condition cond, bool i, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((29360128 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'blx' instruction.</summary>
        public static void blx(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (19922736 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bx' instruction.</summary>
        public static void bx(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (19922704 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'bxj' instruction.</summary>
        public static void bxj(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (19922720 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'blxun' instruction.</summary>
        public static void blxun(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 4194304000;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cdp' instruction.</summary>
        public static void cdp(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (234881024 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'clz' instruction.</summary>
        public static void clz(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((24055568 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cmn' instruction.</summary>
        public static void cmn(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((24117248 | cond) | (i << 25)) | (rn << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((22020096 | cond) | (i << 25)) | (rn << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpy' instruction.</summary>
        public static void cpy(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((27262976 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cps' instruction.</summary>
        public static void cps(ref IntPtr buffer, Mode mode)
        {
            *(uint*)(*buf) = (4043440128 | (mode << 0));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsie' instruction.</summary>
        public static void cpsie(ref IntPtr buffer, InterruptFlags iflags)
        {
            *(uint*)(*buf) = (4043833344 | (iflags << 9));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsid' instruction.</summary>
        public static void cpsid(ref IntPtr buffer, InterruptFlags iflags)
        {
            *(uint*)(*buf) = (4044095488 | (iflags << 9));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsie_mode' instruction.</summary>
        public static void cpsie_mode(ref IntPtr buffer, InterruptFlags iflags, Mode mode)
        {
            *(uint*)(*buf) = ((4043964416 | (iflags << 9)) | (mode << 3));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'cpsid_mode' instruction.</summary>
        public static void cpsid_mode(ref IntPtr buffer, InterruptFlags iflags, Mode mode)
        {
            *(uint*)(*buf) = ((4044226560 | (iflags << 9)) | (mode << 3));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldc' instruction.</summary>
        public static void ldc(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((205520896 | cond) | (write << 23)) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldm1' instruction.</summary>
        public static void ldm1(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((138412032 | cond) | (write << 23)) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldm2' instruction.</summary>
        public static void ldm2(ref IntPtr buffer, Condition cond, Register rn)
        {
            *(uint*)(*buf) = ((155189248 | cond) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldm3' instruction.</summary>
        public static void ldm3(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((155320320 | cond) | (write << 23)) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldr' instruction.</summary>
        public static void ldr(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((71303168 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrb' instruction.</summary>
        public static void ldrb(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((88080384 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrbt' instruction.</summary>
        public static void ldrbt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((81788928 | cond) | (i << 25)) | (rn << 17)) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrd' instruction.</summary>
        public static void ldrd(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((13312 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrex' instruction.</summary>
        public static void ldrex(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((26218399 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrh' instruction.</summary>
        public static void ldrh(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((4205568 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrsb' instruction.</summary>
        public static void ldrsb(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((4207616 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrsh' instruction.</summary>
        public static void ldrsh(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((4209664 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ldrt' instruction.</summary>
        public static void ldrt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((73400320 | cond) | (i << 25)) | (rn << 17)) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mcr' instruction.</summary>
        public static void mcr(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((234897408 | cond) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mcrr' instruction.</summary>
        public static void mcrr(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((205520896 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mla' instruction.</summary>
        public static void mla(ref IntPtr buffer, Condition cond, bool s, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((2097296 | cond) | (s << 20)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mov' instruction.</summary>
        public static void mov(ref IntPtr buffer, Condition cond, bool i, bool s, Register rd)
        {
            *(uint*)(*buf) = ((((27262976 | cond) | (i << 25)) | (s << 20)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mrc' instruction.</summary>
        public static void mrc(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((243286016 | cond) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mrrc' instruction.</summary>
        public static void mrrc(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((206569472 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mrs' instruction.</summary>
        public static void mrs(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((17760256 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mul' instruction.</summary>
        public static void mul(ref IntPtr buffer, Condition cond, bool s, Register rd)
        {
            *(uint*)(*buf) = (((144 | cond) | (s << 20)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'mvn' instruction.</summary>
        public static void mvn(ref IntPtr buffer, Condition cond, bool i, bool s, Register rd)
        {
            *(uint*)(*buf) = ((((31457280 | cond) | (i << 25)) | (s << 20)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'msr_imm' instruction.</summary>
        public static void msr_imm(ref IntPtr buffer, Condition cond, FieldMask fieldmask)
        {
            *(uint*)(*buf) = ((52490240 | cond) | (fieldmask << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'msr_reg' instruction.</summary>
        public static void msr_reg(ref IntPtr buffer, Condition cond, FieldMask fieldmask)
        {
            *(uint*)(*buf) = ((18935808 | cond) | (fieldmask << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'pkhbt' instruction.</summary>
        public static void pkhbt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((109051920 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'pkhtb' instruction.</summary>
        public static void pkhtb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((109051984 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'pld' instruction.</summary>
        public static void pld(ref IntPtr buffer, bool i, Register rn)
        {
            *(uint*)(*buf) = ((4121026560 | (i << 25)) | (rn << 17));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qadd' instruction.</summary>
        public static void qadd(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777296 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qadd16' instruction.</summary>
        public static void qadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((102764304 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qadd8' instruction.</summary>
        public static void qadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((102764432 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qaddsubx' instruction.</summary>
        public static void qaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((102764336 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qdadd' instruction.</summary>
        public static void qdadd(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((20971600 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qdsub' instruction.</summary>
        public static void qdsub(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((23068752 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsub' instruction.</summary>
        public static void qsub(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((18874448 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsub16' instruction.</summary>
        public static void qsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((102764400 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsub8' instruction.</summary>
        public static void qsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((102764528 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'qsubaddx' instruction.</summary>
        public static void qsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((102764368 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rev' instruction.</summary>
        public static void rev(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((113184560 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rev16' instruction.</summary>
        public static void rev16(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((113184688 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'revsh' instruction.</summary>
        public static void revsh(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((117378992 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'rfe' instruction.</summary>
        public static void rfe(ref IntPtr buffer, bool write, Register rn)
        {
            *(uint*)(*buf) = ((4164954112 | (write << 23)) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sadd16' instruction.</summary>
        public static void sadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((101715728 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sadd8' instruction.</summary>
        public static void sadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((101715856 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'saddsubx' instruction.</summary>
        public static void saddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((101715760 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sel' instruction.</summary>
        public static void sel(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((109055920 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'setendbe' instruction.</summary>
        public static void setendbe(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 4043375104;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'setendle' instruction.</summary>
        public static void setendle(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 4043374592;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shadd16' instruction.</summary>
        public static void shadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((103812880 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shadd8' instruction.</summary>
        public static void shadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((103813008 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shaddsubx' instruction.</summary>
        public static void shaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((103812912 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shsub16' instruction.</summary>
        public static void shsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((103812976 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shsub8' instruction.</summary>
        public static void shsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((103813104 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'shsubaddx' instruction.</summary>
        public static void shsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((103812944 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlabb' instruction.</summary>
        public static void smlabb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777344 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlabt' instruction.</summary>
        public static void smlabt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777376 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlatb' instruction.</summary>
        public static void smlatb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777408 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlatt' instruction.</summary>
        public static void smlatt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777440 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlad' instruction.</summary>
        public static void smlad(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((117440544 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlal' instruction.</summary>
        public static void smlal(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((14680208 | cond) | (s << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlalbb' instruction.</summary>
        public static void smlalbb(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (20971648 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlalbt' instruction.</summary>
        public static void smlalbt(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (20971680 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlaltb' instruction.</summary>
        public static void smlaltb(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (20971712 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlaltt' instruction.</summary>
        public static void smlaltt(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (20971744 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlald' instruction.</summary>
        public static void smlald(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (121634848 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlawb' instruction.</summary>
        public static void smlawb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((18874496 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlawt' instruction.</summary>
        public static void smlawt(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((18874560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlsd' instruction.</summary>
        public static void smlsd(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((117440608 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smlsld' instruction.</summary>
        public static void smlsld(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (121634912 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smmla' instruction.</summary>
        public static void smmla(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((122683408 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smmls' instruction.</summary>
        public static void smmls(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((122683600 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smmul' instruction.</summary>
        public static void smmul(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((122744848 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smuad' instruction.</summary>
        public static void smuad(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((117501984 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulbb' instruction.</summary>
        public static void smulbb(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((23068800 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulbt' instruction.</summary>
        public static void smulbt(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((23068832 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smultb' instruction.</summary>
        public static void smultb(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((23068864 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smultt' instruction.</summary>
        public static void smultt(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((23068896 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smull' instruction.</summary>
        public static void smull(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((6291528 | cond) | (s << 19));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulwb' instruction.</summary>
        public static void smulwb(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((18874528 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smulwt' instruction.</summary>
        public static void smulwt(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((18874592 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'smusd' instruction.</summary>
        public static void smusd(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((117502048 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'srs' instruction.</summary>
        public static void srs(ref IntPtr buffer, bool write, Mode mode)
        {
            *(uint*)(*buf) = ((4180939776 | (write << 23)) | (mode << 1));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssat' instruction.</summary>
        public static void ssat(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((105922560 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssat16' instruction.</summary>
        public static void ssat16(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((111211264 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssub16' instruction.</summary>
        public static void ssub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((101715824 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssub8' instruction.</summary>
        public static void ssub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((101715952 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'ssubaddx' instruction.</summary>
        public static void ssubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((101715792 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void stc(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((201326592 | cond) | (write << 23)) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'stm1' instruction.</summary>
        public static void stm1(ref IntPtr buffer, Condition cond, bool write, Register rn)
        {
            *(uint*)(*buf) = (((134217728 | cond) | (write << 23)) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'stm2' instruction.</summary>
        public static void stm2(ref IntPtr buffer, Condition cond, Register rn)
        {
            *(uint*)(*buf) = ((150994944 | cond) | (rn << 18));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'str' instruction.</summary>
        public static void str(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((67108864 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strb' instruction.</summary>
        public static void strb(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((83886080 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strbt' instruction.</summary>
        public static void strbt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((79691776 | cond) | (i << 25)) | (rn << 17)) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strd' instruction.</summary>
        public static void strd(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((15360 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strex' instruction.</summary>
        public static void strex(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((25173792 | cond) | (rn << 17)) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strh' instruction.</summary>
        public static void strh(ref IntPtr buffer, Condition cond, bool write, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((((11264 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'strt' instruction.</summary>
        public static void strt(ref IntPtr buffer, Condition cond, bool i, Register rn, Register rd)
        {
            *(uint*)(*buf) = ((((71303168 | cond) | (i << 25)) | (rn << 17)) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'swi' instruction.</summary>
        public static void swi(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (251658240 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'swp' instruction.</summary>
        public static void swp(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((16777360 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'swpb' instruction.</summary>
        public static void swpb(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((20971664 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtab' instruction.</summary>
        public static void sxtab(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtab16' instruction.</summary>
        public static void sxtab16(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtah' instruction.</summary>
        public static void sxtah(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtb' instruction.</summary>
        public static void sxtb(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((112132208 | cond) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxtb16' instruction.</summary>
        public static void sxtb16(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((110035056 | cond) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'sxth' instruction.</summary>
        public static void sxth(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((113180784 | cond) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'teq' instruction.</summary>
        public static void teq(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((19922944 | cond) | (i << 25)) | (rn << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a 'tst' instruction.</summary>
        public static void tst(ref IntPtr buffer, Condition cond, bool i, Register rn)
        {
            *(uint*)(*buf) = (((17825792 | cond) | (i << 25)) | (rn << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uadd16' instruction.</summary>
        public static void uadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((105910032 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uadd8' instruction.</summary>
        public static void uadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((105910160 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uaddsubx' instruction.</summary>
        public static void uaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((105910064 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhadd16' instruction.</summary>
        public static void uhadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((108007184 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhadd8' instruction.</summary>
        public static void uhadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((108007312 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhaddsubx' instruction.</summary>
        public static void uhaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((108007216 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhsub16' instruction.</summary>
        public static void uhsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((108007280 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhsub8' instruction.</summary>
        public static void uhsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((108007408 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uhsubaddx' instruction.</summary>
        public static void uhsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((108007248 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'umaal' instruction.</summary>
        public static void umaal(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (4194448 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'umlal' instruction.</summary>
        public static void umlal(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((10485904 | cond) | (s << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'umull' instruction.</summary>
        public static void umull(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((8388752 | cond) | (s << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqadd16' instruction.</summary>
        public static void uqadd16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((106958608 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqadd8' instruction.</summary>
        public static void uqadd8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((106958736 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqaddsubx' instruction.</summary>
        public static void uqaddsubx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((106958640 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqsub16' instruction.</summary>
        public static void uqsub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((106958704 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqsub8' instruction.</summary>
        public static void uqsub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((106958832 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uqsubaddx' instruction.</summary>
        public static void uqsubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((106958672 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usad8' instruction.</summary>
        public static void usad8(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((125890576 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usada8' instruction.</summary>
        public static void usada8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((125829136 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usat' instruction.</summary>
        public static void usat(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((115376128 | cond) | (rd << 17));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usat16' instruction.</summary>
        public static void usat16(ref IntPtr buffer, Condition cond, Register rd)
        {
            *(uint*)(*buf) = ((115405568 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usub16' instruction.</summary>
        public static void usub16(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((105910128 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usub8' instruction.</summary>
        public static void usub8(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((105910256 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'usubaddx' instruction.</summary>
        public static void usubaddx(ref IntPtr buffer, Condition cond, Register rn, Register rd)
        {
            *(uint*)(*buf) = (((105910096 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtab' instruction.</summary>
        public static void uxtab(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtab16' instruction.</summary>
        public static void uxtab16(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtah' instruction.</summary>
        public static void uxtah(ref IntPtr buffer, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtb' instruction.</summary>
        public static void uxtb(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((116326512 | cond) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxtb16' instruction.</summary>
        public static void uxtb16(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((114229360 | cond) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an 'uxth' instruction.</summary>
        public static void uxth(ref IntPtr buffer, Condition cond, Register rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((117375088 | cond) | (rd << 12)) | (rotate << 10));
            *(byte*)buf += 4;
        }


    }
}
