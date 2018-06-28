using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net.Arm
{
    /// <summary>An ARM register.</summary>
    public struct Register
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register(byte value) => new Register(value);

        /// <summary>Creates a new Register, given its underlying value.</summary>
        public Register(byte underlyingValue) { Value = underlyingValue; }

        public static readonly Register R0 = new Register(0);
        public static readonly Register R1 = new Register(1);
        public static readonly Register R2 = new Register(2);
        public static readonly Register R3 = new Register(3);
        public static readonly Register R4 = new Register(4);
        public static readonly Register R5 = new Register(5);
        public static readonly Register R6 = new Register(6);
        public static readonly Register R7 = new Register(7);
        public static readonly Register R8 = new Register(8);
        public static readonly Register R9 = new Register(9);
        public static readonly Register R10 = new Register(10);
        public static readonly Register R11 = new Register(11);
        public static readonly Register R12 = new Register(12);
        public static readonly Register R13 = new Register(13);
        public static readonly Register R14 = new Register(14);
        public static readonly Register R15 = new Register(15);
        public static readonly Register A1 = new Register(0);
        public static readonly Register A2 = new Register(1);
        public static readonly Register A3 = new Register(2);
        public static readonly Register A4 = new Register(3);
        public static readonly Register V1 = new Register(4);
        public static readonly Register V2 = new Register(5);
        public static readonly Register V3 = new Register(6);
        public static readonly Register V4 = new Register(7);
        public static readonly Register V5 = new Register(8);
        public static readonly Register V6 = new Register(9);
        public static readonly Register V7 = new Register(10);
        public static readonly Register V8 = new Register(11);
        public static readonly Register IP = new Register(12);
        public static readonly Register SP = new Register(13);
        public static readonly Register LR = new Register(14);
        public static readonly Register PC = new Register(15);
        public static readonly Register WR = new Register(7);
        public static readonly Register SB = new Register(9);
        public static readonly Register SL = new Register(10);
        public static readonly Register FP = new Register(11);
    }

    /// <summary>
    ///   A list of ARM registers, where each register corresponds to a single bit.
    /// </summary>
    [Flags]
    public enum RegList
    {
        /// <summary>
        ///   Register #1.
        /// </summary>
        R0 = 0,
        /// <summary>
        ///   Register #2.
        /// </summary>
        R1 = 1,
        /// <summary>
        ///   Register #3.
        /// </summary>
        R2 = 2,
        /// <summary>
        ///   Register #4.
        /// </summary>
        R3 = 3,
        /// <summary>
        ///   Register #5.
        /// </summary>
        R4 = 4,
        /// <summary>
        ///   Register #6.
        /// </summary>
        R5 = 5,
        /// <summary>
        ///   Register #7.
        /// </summary>
        R6 = 6,
        /// <summary>
        ///   Register #8.
        /// </summary>
        R7 = 7,
        /// <summary>
        ///   Register #9.
        /// </summary>
        R8 = 8,
        /// <summary>
        ///   Register #10.
        /// </summary>
        R9 = 9,
        /// <summary>
        ///   Register #11.
        /// </summary>
        R10 = 10,
        /// <summary>
        ///   Register #12.
        /// </summary>
        R11 = 11,
        /// <summary>
        ///   Register #13.
        /// </summary>
        R12 = 12,
        /// <summary>
        ///   Register #14.
        /// </summary>
        R13 = 13,
        /// <summary>
        ///   Register #15.
        /// </summary>
        R14 = 14,
        /// <summary>
        ///   Register #16.
        /// </summary>
        R15 = 15,
        /// <summary>
        ///   Register A1.
        /// </summary>
        A1 = 0,
        /// <summary>
        ///   Register A2.
        /// </summary>
        A2 = 1,
        /// <summary>
        ///   Register A3.
        /// </summary>
        A3 = 2,
        /// <summary>
        ///   Register A4.
        /// </summary>
        A4 = 3,
        /// <summary>
        ///   Register V1.
        /// </summary>
        V1 = 4,
        /// <summary>
        ///   Register V2.
        /// </summary>
        V2 = 5,
        /// <summary>
        ///   Register V3.
        /// </summary>
        V3 = 6,
        /// <summary>
        ///   Register V4.
        /// </summary>
        V4 = 7,
        /// <summary>
        ///   Register V5.
        /// </summary>
        V5 = 8,
        /// <summary>
        ///   Register V6.
        /// </summary>
        V6 = 9,
        /// <summary>
        ///   Register V7.
        /// </summary>
        V7 = 10,
        /// <summary>
        ///   Register V8.
        /// </summary>
        V8 = 11,
        /// <summary>
        ///   Register IP.
        /// </summary>
        IP = 12,
        /// <summary>
        ///   Register SP.
        /// </summary>
        SP = 13,
        /// <summary>
        ///   Register LR.
        /// </summary>
        LR = 14,
        /// <summary>
        ///   Register PC.
        /// </summary>
        PC = 15,
        /// <summary>
        ///   Register WR.
        /// </summary>
        WR = 7,
        /// <summary>
        ///   Register SB.
        /// </summary>
        SB = 9,
        /// <summary>
        ///   Register SL.
        /// </summary>
        SL = 10,
        /// <summary>
        ///   Register FP.
        /// </summary>
        FP = 11,
    }

    /// <summary>An ARM coprocessor.</summary>
    public struct Coprocessor
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Coprocessor wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Coprocessor(byte value) => new Coprocessor(value);

        /// <summary>Creates a new Coprocessor, given its underlying value.</summary>
        public Coprocessor(byte underlyingValue) { Value = underlyingValue; }

        public static readonly Coprocessor CP0 = new Coprocessor(0);
        public static readonly Coprocessor CP1 = new Coprocessor(1);
        public static readonly Coprocessor CP2 = new Coprocessor(2);
        public static readonly Coprocessor CP3 = new Coprocessor(3);
        public static readonly Coprocessor CP4 = new Coprocessor(4);
        public static readonly Coprocessor CP5 = new Coprocessor(5);
        public static readonly Coprocessor CP6 = new Coprocessor(6);
        public static readonly Coprocessor CP7 = new Coprocessor(7);
        public static readonly Coprocessor CP8 = new Coprocessor(8);
        public static readonly Coprocessor CP9 = new Coprocessor(9);
        public static readonly Coprocessor CP10 = new Coprocessor(10);
        public static readonly Coprocessor CP11 = new Coprocessor(11);
        public static readonly Coprocessor CP12 = new Coprocessor(12);
        public static readonly Coprocessor CP13 = new Coprocessor(13);
        public static readonly Coprocessor CP14 = new Coprocessor(14);
        public static readonly Coprocessor CP15 = new Coprocessor(15);
    }

    /// <summary>
    ///   Condition for an ARM instruction to be executed.
    /// </summary>
    public enum Condition
    {
        /// <summary>
        ///   Equal.
        /// </summary>
        EQ = 0,
        /// <summary>
        ///   Not equal.
        /// </summary>
        NE = 1,
        /// <summary>
        ///   Unsigned higher or same.
        /// </summary>
        HS = 2,
        /// <summary>
        ///   Unsigned lower.
        /// </summary>
        LO = 3,
        /// <summary>
        ///   Minus / negative.
        /// </summary>
        MI = 4,
        /// <summary>
        ///   Plus / positive or zero.
        /// </summary>
        PL = 5,
        /// <summary>
        ///   Overflow.
        /// </summary>
        VS = 6,
        /// <summary>
        ///   No overflow.
        /// </summary>
        VC = 7,
        /// <summary>
        ///   Unsigned higher.
        /// </summary>
        HI = 8,
        /// <summary>
        ///   Unsigned lower or same.
        /// </summary>
        LS = 9,
        /// <summary>
        ///   Signed greater than or equal.
        /// </summary>
        GE = 10,
        /// <summary>
        ///   Signed less than.
        /// </summary>
        LT = 11,
        /// <summary>
        ///   Signed greater than.
        /// </summary>
        GT = 12,
        /// <summary>
        ///   Signed less than or equal.
        /// </summary>
        LE = 13,
        /// <summary>
        ///   Always (unconditional).
        /// </summary>
        AL = 14,
        /// <summary>
        ///   Unpredictable (ARMv4 or lower).
        /// </summary>
        UN = 15,
        /// <summary>
        ///   Carry set.
        /// </summary>
        CS = 2,
        /// <summary>
        ///   Carry clear.
        /// </summary>
        CC = 3,
    }

    /// <summary>
    ///   Processor mode.
    /// </summary>
    public enum Mode
    {
        /// <summary>
        ///   User mode.
        /// </summary>
        USR = 16,
        /// <summary>
        ///   FIQ (high-speed data transfer) mode.
        /// </summary>
        FIQ = 17,
        /// <summary>
        ///   IRQ (general-purpose interrupt handling) mode.
        /// </summary>
        IRQ = 18,
        /// <summary>
        ///   Supervisor mode.
        /// </summary>
        SVC = 19,
        /// <summary>
        ///   Abort mode.
        /// </summary>
        ABT = 23,
        /// <summary>
        ///   Undefined mode.
        /// </summary>
        UND = 27,
        /// <summary>
        ///   System (privileged) mode.
        /// </summary>
        SYS = 31,
    }

    /// <summary>
    ///   Kind of a shift.
    /// </summary>
    public enum Shift
    {
        /// <summary>
        ///   Logical shift left.
        /// </summary>
        LSL = 0,
        /// <summary>
        ///   Logical shift right.
        /// </summary>
        LSR = 1,
        /// <summary>
        ///   Arithmetic shift right.
        /// </summary>
        ASR = 2,
        /// <summary>
        ///   Rotate right.
        /// </summary>
        ROR = 3,
        /// <summary>
        ///   Shifted right by one bit.
        /// </summary>
        RRX = 3,
    }

    /// <summary>
    ///   Kind of a right rotation.
    /// </summary>
    public enum Rotation
    {
        /// <summary>
        ///   Do not rotate.
        /// </summary>
        NOP = 0,
        /// <summary>
        ///   Rotate 8 bits to the right.
        /// </summary>
        ROR8 = 1,
        /// <summary>
        ///   Rotate 16 bits to the right.
        /// </summary>
        ROR16 = 2,
        /// <summary>
        ///   Rotate 24 bits to the right.
        /// </summary>
        ROR24 = 3,
    }

    /// <summary>
    ///   Field mask bits.
    /// </summary>
    [Flags]
    public enum FieldMask
    {
        /// <summary>
        ///   Control field mask bit.
        /// </summary>
        C = 1,
        /// <summary>
        ///   Extension field mask bit.
        /// </summary>
        X = 2,
        /// <summary>
        ///   Status field mask bit.
        /// </summary>
        S = 4,
        /// <summary>
        ///   Flags field mask bit.
        /// </summary>
        F = 8,
    }

    /// <summary>
    ///   Interrupt flags.
    /// </summary>
    [Flags]
    public enum InterruptFlags
    {
        /// <summary>
        ///   FIQ interrupt bit.
        /// </summary>
        F = 1,
        /// <summary>
        ///   IRQ interrupt bit.
        /// </summary>
        I = 2,
        /// <summary>
        ///   Imprecise data abort bit.
        /// </summary>
        A = 4,
    }

    /// <summary>
    ///   Addressing type.
    /// </summary>
    public enum Addressing
    {
        /// <summary>
        ///   Post-indexed addressing.
        /// </summary>
        PostIndexed = 0,
        /// <summary>
        ///   Pre-indexed addressing (or offset addressing if `write` is false).
        /// </summary>
        PreIndexed = 1,
        /// <summary>
        ///   Offset addressing (or pre-indexed addressing if `write` is true).
        /// </summary>
        Offset = 1,
    }

    /// <summary>
    ///   Offset adding or subtracting mode.
    /// </summary>
    public enum OffsetMode
    {
        /// <summary>
        ///   Subtract offset from the base.
        /// </summary>
        Subtract = 0,
        /// <summary>
        ///   Add offset to the base.
        /// </summary>
        Add = 1,
    }

    partial class Arm
    {
        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)10485760 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)8388608 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)0 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits an 'eor' instruction.</summary>
        public static void Eor(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)2097152 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits an 'orr' instruction.</summary>
        public static void Orr(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)25165824 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'rsb' instruction.</summary>
        public static void Rsb(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)6291456 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'rsc' instruction.</summary>
        public static void Rsc(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)14680064 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'sbc' instruction.</summary>
        public static void Sbc(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)12582912 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)4194304 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'bkpt' instruction.</summary>
        public static void Bkpt(this Stream stream, ushort immed)
        {
            stream.WriteLE((uint)(((uint)3776970864 | (((uint)immed & (ushort)65520) << (uint)8)) | (((uint)immed & (ushort)15) << (uint)0))));
        }

        /// <summary>Emits a 'b' instruction.</summary>
        public static void B(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)167772160 | (uint)cond)));
        }

        /// <summary>Emits a 'bic' instruction.</summary>
        public static void Bic(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)29360128 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'blx' instruction.</summary>
        public static void Blx(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)19922736 | (uint)cond)));
        }

        /// <summary>Emits a 'bx' instruction.</summary>
        public static void Bx(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)19922704 | (uint)cond)));
        }

        /// <summary>Emits a 'bxj' instruction.</summary>
        public static void Bxj(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)19922720 | (uint)cond)));
        }

        /// <summary>Emits a 'blxun' instruction.</summary>
        public static void Blxun(this Stream stream)
        {
            stream.WriteLE((uint)(uint)4194304000));
        }

        /// <summary>Emits a 'clz' instruction.</summary>
        public static void Clz(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)24055568 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'cmn' instruction.</summary>
        public static void Cmn(this Stream stream, Condition cond, Register rn)
        {
            stream.WriteLE((uint)(((uint)24117248 | (uint)cond) | ((uint)rn << (uint)16))));
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Condition cond, Register rn)
        {
            stream.WriteLE((uint)(((uint)22020096 | (uint)cond) | ((uint)rn << (uint)16))));
        }

        /// <summary>Emits a 'cpy' instruction.</summary>
        public static void Cpy(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)27262976 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'cps' instruction.</summary>
        public static void Cps(this Stream stream, Mode mode)
        {
            stream.WriteLE((uint)((uint)4043440128 | ((uint)mode << (uint)0))));
        }

        /// <summary>Emits a 'cpsie' instruction.</summary>
        public static void Cpsie(this Stream stream, InterruptFlags iflags)
        {
            stream.WriteLE((uint)((uint)4043833344 | ((uint)iflags << (uint)6))));
        }

        /// <summary>Emits a 'cpsid' instruction.</summary>
        public static void Cpsid(this Stream stream, InterruptFlags iflags)
        {
            stream.WriteLE((uint)((uint)4044095488 | ((uint)iflags << (uint)6))));
        }

        /// <summary>Emits a 'cpsie_mode' instruction.</summary>
        public static void Cpsie_mode(this Stream stream, InterruptFlags iflags, Mode mode)
        {
            stream.WriteLE((uint)(((uint)4043964416 | ((uint)iflags << (uint)6)) | ((uint)mode << (uint)0))));
        }

        /// <summary>Emits a 'cpsid_mode' instruction.</summary>
        public static void Cpsid_mode(this Stream stream, InterruptFlags iflags, Mode mode)
        {
            stream.WriteLE((uint)(((uint)4044226560 | ((uint)iflags << (uint)6)) | ((uint)mode << (uint)0))));
        }

        /// <summary>Emits a 'ldc' instruction.</summary>
        public static void Ldc(this Stream stream, Condition cond, bool write, Register rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)202375168 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)cpnum << (uint)8)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldm' instruction.</summary>
        public static void Ldm(this Stream stream, Condition cond, Register rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool copy_spsr)
        {
            Debug.Assert((((uint)copy_spsr == (uint)1) ^ ((uint)write == ((uint)registers & (ushort)32768))), "(((uint)copy_spsr == (uint)1) ^ ((uint)write == ((uint)registers & (ushort)32768)))");
            stream.WriteLE((uint)(((((((((uint)135266304 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11)) | ((uint)addressing_mode << (uint)23)) | (uint)registers) | ((uint)copy_spsr << (uint)21)) | ((uint)write << (uint)10))));
        }

        /// <summary>Emits a 'ldr' instruction.</summary>
        public static void Ldr(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)68157440 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldrb' instruction.</summary>
        public static void Ldrb(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)72351744 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldrbt' instruction.</summary>
        public static void Ldrbt(this Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.WriteLE((uint)(((((uint)74448896 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)offset_mode << (uint)23))));
        }

        /// <summary>Emits a 'ldrd' instruction.</summary>
        public static void Ldrd(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)208 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldrex' instruction.</summary>
        public static void Ldrex(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)26218399 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'ldrh' instruction.</summary>
        public static void Ldrh(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)1048752 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldrsb' instruction.</summary>
        public static void Ldrsb(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)1048784 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldrsh' instruction.</summary>
        public static void Ldrsh(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)1048816 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ldrt' instruction.</summary>
        public static void Ldrt(this Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.WriteLE((uint)(((((uint)70254592 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)offset_mode << (uint)23))));
        }

        /// <summary>Emits a 'cdp' instruction.</summary>
        public static void Cdp(this Stream stream, Condition cond, Coprocessor cpnum)
        {
            stream.WriteLE((uint)(((uint)234881024 | (uint)cond) | ((uint)cpnum << (uint)8))));
        }

        /// <summary>Emits a 'mcr' instruction.</summary>
        public static void Mcr(this Stream stream, Condition cond, Register rd, Coprocessor cpnum)
        {
            stream.WriteLE((uint)((((uint)234881040 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)cpnum << (uint)8))));
        }

        /// <summary>Emits a 'mrc' instruction.</summary>
        public static void Mrc(this Stream stream, Condition cond, Register rd, Coprocessor cpnum)
        {
            stream.WriteLE((uint)((((uint)235929616 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)cpnum << (uint)8))));
        }

        /// <summary>Emits a 'mcrr' instruction.</summary>
        public static void Mcrr(this Stream stream, Condition cond, Register rn, Register rd, Coprocessor cpnum)
        {
            stream.WriteLE((uint)(((((uint)205520896 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)cpnum << (uint)8))));
        }

        /// <summary>Emits a 'mla' instruction.</summary>
        public static void Mla(this Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)((((((uint)2097296 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'mov' instruction.</summary>
        public static void Mov(this Stream stream, Condition cond, bool update_cprs, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)(((((uint)27262976 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'mrrc' instruction.</summary>
        public static void Mrrc(this Stream stream, Condition cond, Register rn, Register rd, Coprocessor cpnum)
        {
            stream.WriteLE((uint)(((((uint)206569472 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)cpnum << (uint)8))));
        }

        /// <summary>Emits a 'mrs' instruction.</summary>
        public static void Mrs(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)17760256 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'mul' instruction.</summary>
        public static void Mul(this Stream stream, Condition cond, bool update_cprs, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)(((((uint)144 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rd << (uint)16)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'mvn' instruction.</summary>
        public static void Mvn(this Stream stream, Condition cond, bool update_cprs, Register rd, bool update_condition)
        {
            stream.WriteLE((uint)(((((uint)31457280 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)rd << (uint)12)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'msr_imm' instruction.</summary>
        public static void Msr_imm(this Stream stream, Condition cond, FieldMask fieldmask)
        {
            stream.WriteLE((uint)(((uint)52490240 | (uint)cond) | ((uint)fieldmask << (uint)16))));
        }

        /// <summary>Emits a 'msr_reg' instruction.</summary>
        public static void Msr_reg(this Stream stream, Condition cond, FieldMask fieldmask)
        {
            stream.WriteLE((uint)(((uint)18935808 | (uint)cond) | ((uint)fieldmask << (uint)16))));
        }

        /// <summary>Emits a 'pkhbt' instruction.</summary>
        public static void Pkhbt(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)109051920 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'pkhtb' instruction.</summary>
        public static void Pkhtb(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)109051984 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'pld' instruction.</summary>
        public static void Pld(this Stream stream, Register rn, OffsetMode offset_mode)
        {
            stream.WriteLE((uint)(((uint)4115722240 | ((uint)rn << (uint)16)) | ((uint)offset_mode << (uint)23))));
        }

        /// <summary>Emits a 'qadd' instruction.</summary>
        public static void Qadd(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)16777296 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qadd16' instruction.</summary>
        public static void Qadd16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)102764304 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qadd8' instruction.</summary>
        public static void Qadd8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)102764432 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qaddsubx' instruction.</summary>
        public static void Qaddsubx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)102764336 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qdadd' instruction.</summary>
        public static void Qdadd(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)20971600 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qdsub' instruction.</summary>
        public static void Qdsub(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)23068752 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qsub' instruction.</summary>
        public static void Qsub(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)18874448 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qsub16' instruction.</summary>
        public static void Qsub16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)102764400 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qsub8' instruction.</summary>
        public static void Qsub8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)102764528 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'qsubaddx' instruction.</summary>
        public static void Qsubaddx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)102764368 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'rev' instruction.</summary>
        public static void Rev(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)113184560 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'rev16' instruction.</summary>
        public static void Rev16(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)113184688 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'revsh' instruction.</summary>
        public static void Revsh(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)117378992 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'rfe' instruction.</summary>
        public static void Rfe(this Stream stream, bool write, Register rn, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((uint)4161800704 | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'sadd16' instruction.</summary>
        public static void Sadd16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)101715728 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'sadd8' instruction.</summary>
        public static void Sadd8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)101715856 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'saddsubx' instruction.</summary>
        public static void Saddsubx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)101715760 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'sel' instruction.</summary>
        public static void Sel(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)109055920 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'setendbe' instruction.</summary>
        public static void Setendbe(this Stream stream)
        {
            stream.WriteLE((uint)(uint)4043375104));
        }

        /// <summary>Emits a 'setendle' instruction.</summary>
        public static void Setendle(this Stream stream)
        {
            stream.WriteLE((uint)(uint)4043374592));
        }

        /// <summary>Emits a 'shadd16' instruction.</summary>
        public static void Shadd16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)103812880 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'shadd8' instruction.</summary>
        public static void Shadd8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)103813008 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'shaddsubx' instruction.</summary>
        public static void Shaddsubx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)103812912 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'shsub16' instruction.</summary>
        public static void Shsub16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)103812976 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'shsub8' instruction.</summary>
        public static void Shsub8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)103813104 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'shsubaddx' instruction.</summary>
        public static void Shsubaddx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)103812944 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'smlabb' instruction.</summary>
        public static void Smlabb(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)16777344 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlabt' instruction.</summary>
        public static void Smlabt(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)16777376 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlatb' instruction.</summary>
        public static void Smlatb(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)16777408 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlatt' instruction.</summary>
        public static void Smlatt(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)16777440 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlad' instruction.</summary>
        public static void Smlad(this Stream stream, Condition cond, bool exchange, Register rn, Register rd)
        {
            stream.WriteLE((uint)(((((uint)117440528 | (uint)cond) | ((uint)exchange << (byte)5)) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlal' instruction.</summary>
        public static void Smlal(this Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.WriteLE((uint)((((uint)14680208 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'smlalbb' instruction.</summary>
        public static void Smlalbb(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)20971648 | (uint)cond)));
        }

        /// <summary>Emits a 'smlalbt' instruction.</summary>
        public static void Smlalbt(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)20971680 | (uint)cond)));
        }

        /// <summary>Emits a 'smlaltb' instruction.</summary>
        public static void Smlaltb(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)20971712 | (uint)cond)));
        }

        /// <summary>Emits a 'smlaltt' instruction.</summary>
        public static void Smlaltt(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)20971744 | (uint)cond)));
        }

        /// <summary>Emits a 'smlald' instruction.</summary>
        public static void Smlald(this Stream stream, Condition cond, bool exchange)
        {
            stream.WriteLE((uint)(((uint)121634832 | (uint)cond) | ((uint)exchange << (byte)5))));
        }

        /// <summary>Emits a 'smlawb' instruction.</summary>
        public static void Smlawb(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)18874496 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlawt' instruction.</summary>
        public static void Smlawt(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)18874560 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlsd' instruction.</summary>
        public static void Smlsd(this Stream stream, Condition cond, bool exchange, Register rn, Register rd)
        {
            stream.WriteLE((uint)(((((uint)117440592 | (uint)cond) | ((uint)exchange << (byte)5)) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smlsld' instruction.</summary>
        public static void Smlsld(this Stream stream, Condition cond, bool exchange)
        {
            stream.WriteLE((uint)(((uint)121634896 | (uint)cond) | ((uint)exchange << (byte)5))));
        }

        /// <summary>Emits a 'smmla' instruction.</summary>
        public static void Smmla(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)122683408 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smmls' instruction.</summary>
        public static void Smmls(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)122683600 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smmul' instruction.</summary>
        public static void Smmul(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)122744848 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smuad' instruction.</summary>
        public static void Smuad(this Stream stream, Condition cond, bool exchange, Register rd)
        {
            stream.WriteLE((uint)((((uint)117501968 | (uint)cond) | ((uint)exchange << (byte)5)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smulbb' instruction.</summary>
        public static void Smulbb(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)23068800 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smulbt' instruction.</summary>
        public static void Smulbt(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)23068832 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smultb' instruction.</summary>
        public static void Smultb(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)23068864 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smultt' instruction.</summary>
        public static void Smultt(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)23068896 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smull' instruction.</summary>
        public static void Smull(this Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.WriteLE((uint)((((uint)12583056 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits a 'smulwb' instruction.</summary>
        public static void Smulwb(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)18874528 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smulwt' instruction.</summary>
        public static void Smulwt(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)18874592 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'smusd' instruction.</summary>
        public static void Smusd(this Stream stream, Condition cond, bool exchange, Register rd)
        {
            stream.WriteLE((uint)((((uint)117502032 | (uint)cond) | ((uint)exchange << (byte)5)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits a 'srs' instruction.</summary>
        public static void Srs(this Stream stream, bool write, Mode mode, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((uint)4165797120 | ((uint)write << (byte)21)) | ((uint)mode << (uint)0)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'ssat' instruction.</summary>
        public static void Ssat(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)105906192 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'ssat16' instruction.</summary>
        public static void Ssat16(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)111152944 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'ssub16' instruction.</summary>
        public static void Ssub16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)101715824 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'ssub8' instruction.</summary>
        public static void Ssub8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)101715952 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'ssubaddx' instruction.</summary>
        public static void Ssubaddx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)101715792 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void Stc(this Stream stream, Condition cond, bool write, Register rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)201326592 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)cpnum << (uint)8)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'stm' instruction.</summary>
        public static void Stm(this Stream stream, Condition cond, Register rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool user_mode)
        {
            Debug.Assert((((uint)user_mode == (bool)0) || ((uint)write == (bool)0)), "(((uint)user_mode == (bool)0) || ((uint)write == (bool)0))");
            stream.WriteLE((uint)(((((((((uint)134217728 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11)) | ((uint)addressing_mode << (uint)23)) | (uint)registers) | ((uint)user_mode << (uint)21)) | ((uint)write << (uint)10))));
        }

        /// <summary>Emits a 'str' instruction.</summary>
        public static void Str(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)67108864 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'strb' instruction.</summary>
        public static void Strb(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)71303168 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'strbt' instruction.</summary>
        public static void Strbt(this Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.WriteLE((uint)(((((uint)73400320 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)offset_mode << (uint)23))));
        }

        /// <summary>Emits a 'strd' instruction.</summary>
        public static void Strd(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)240 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'strex' instruction.</summary>
        public static void Strex(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)25169808 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'strh' instruction.</summary>
        public static void Strh(this Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.WriteLE((uint)(((((((uint)176 | (uint)cond) | ((uint)write << (byte)21)) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)addressing_mode << (uint)23)) | ((uint)offset_mode << (uint)11))));
        }

        /// <summary>Emits a 'strt' instruction.</summary>
        public static void Strt(this Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.WriteLE((uint)(((((uint)69206016 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)offset_mode << (uint)23))));
        }

        /// <summary>Emits a 'swi' instruction.</summary>
        public static void Swi(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)251658240 | (uint)cond)));
        }

        /// <summary>Emits a 'swp' instruction.</summary>
        public static void Swp(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)16777360 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'swpb' instruction.</summary>
        public static void Swpb(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)20971664 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits a 'sxtab' instruction.</summary>
        public static void Sxtab(this Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)(((((uint)111149168 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits a 'sxtab16' instruction.</summary>
        public static void Sxtab16(this Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)(((((uint)109052016 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits a 'sxtah' instruction.</summary>
        public static void Sxtah(this Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)(((((uint)112197744 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits a 'sxtb' instruction.</summary>
        public static void Sxtb(this Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)((((uint)112132208 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits a 'sxtb16' instruction.</summary>
        public static void Sxtb16(this Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)((((uint)110035056 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits a 'sxth' instruction.</summary>
        public static void Sxth(this Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)((((uint)113180784 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits a 'teq' instruction.</summary>
        public static void Teq(this Stream stream, Condition cond, Register rn)
        {
            stream.WriteLE((uint)(((uint)19922944 | (uint)cond) | ((uint)rn << (uint)16))));
        }

        /// <summary>Emits a 'tst' instruction.</summary>
        public static void Tst(this Stream stream, Condition cond, Register rn)
        {
            stream.WriteLE((uint)(((uint)17825792 | (uint)cond) | ((uint)rn << (uint)16))));
        }

        /// <summary>Emits an 'uadd16' instruction.</summary>
        public static void Uadd16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)105910032 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uadd8' instruction.</summary>
        public static void Uadd8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)105910160 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uaddsubx' instruction.</summary>
        public static void Uaddsubx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)105910064 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uhadd16' instruction.</summary>
        public static void Uhadd16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)108007184 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uhadd8' instruction.</summary>
        public static void Uhadd8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)108007312 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uhaddsubx' instruction.</summary>
        public static void Uhaddsubx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)108007216 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uhsub16' instruction.</summary>
        public static void Uhsub16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)108007280 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uhsub8' instruction.</summary>
        public static void Uhsub8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)108007408 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uhsubaddx' instruction.</summary>
        public static void Uhsubaddx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)108007248 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'umaal' instruction.</summary>
        public static void Umaal(this Stream stream, Condition cond)
        {
            stream.WriteLE((uint)((uint)4194448 | (uint)cond)));
        }

        /// <summary>Emits an 'umlal' instruction.</summary>
        public static void Umlal(this Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.WriteLE((uint)((((uint)10485904 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits an 'umull' instruction.</summary>
        public static void Umull(this Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.WriteLE((uint)((((uint)8388752 | (uint)cond) | ((uint)update_cprs << (byte)20)) | ((uint)update_condition << (uint)20))));
        }

        /// <summary>Emits an 'uqadd16' instruction.</summary>
        public static void Uqadd16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)106958608 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uqadd8' instruction.</summary>
        public static void Uqadd8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)106958736 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uqaddsubx' instruction.</summary>
        public static void Uqaddsubx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)106958640 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uqsub16' instruction.</summary>
        public static void Uqsub16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)106958704 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uqsub8' instruction.</summary>
        public static void Uqsub8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)106958832 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uqsubaddx' instruction.</summary>
        public static void Uqsubaddx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)106958672 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'usad8' instruction.</summary>
        public static void Usad8(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)125890576 | (uint)cond) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits an 'usada8' instruction.</summary>
        public static void Usada8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)125829136 | (uint)cond) | ((uint)rn << (uint)12)) | ((uint)rd << (uint)16))));
        }

        /// <summary>Emits an 'usat' instruction.</summary>
        public static void Usat(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)115343376 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'usat16' instruction.</summary>
        public static void Usat16(this Stream stream, Condition cond, Register rd)
        {
            stream.WriteLE((uint)(((uint)115347248 | (uint)cond) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'usub16' instruction.</summary>
        public static void Usub16(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)105910128 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'usub8' instruction.</summary>
        public static void Usub8(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)105910256 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'usubaddx' instruction.</summary>
        public static void Usubaddx(this Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.WriteLE((uint)((((uint)105910096 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12))));
        }

        /// <summary>Emits an 'uxtab' instruction.</summary>
        public static void Uxtab(this Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)(((((uint)115343472 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits an 'uxtab16' instruction.</summary>
        public static void Uxtab16(this Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)(((((uint)113246320 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits an 'uxtah' instruction.</summary>
        public static void Uxtah(this Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)(((((uint)116392048 | (uint)cond) | ((uint)rn << (uint)16)) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits an 'uxtb' instruction.</summary>
        public static void Uxtb(this Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)((((uint)116326512 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits an 'uxtb16' instruction.</summary>
        public static void Uxtb16(this Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)((((uint)114229360 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

        /// <summary>Emits an 'uxth' instruction.</summary>
        public static void Uxth(this Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.WriteLE((uint)((((uint)117375088 | (uint)cond) | ((uint)rd << (uint)12)) | ((uint)rotate << (uint)10))));
        }

    }
}
