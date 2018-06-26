using System;
using System.Diagnostics;
using System.IO;

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
    /// A list of ARM registers, where each register corresponds to a single bit.
    /// </summary>
    [Flags]
    public enum RegList
    {
        /// <summary>
        /// Register #1.
        /// </summary>
        R0 = 0,
        /// <summary>
        /// Register #2.
        /// </summary>
        R1 = 1,
        /// <summary>
        /// Register #3.
        /// </summary>
        R2 = 2,
        /// <summary>
        /// Register #4.
        /// </summary>
        R3 = 3,
        /// <summary>
        /// Register #5.
        /// </summary>
        R4 = 4,
        /// <summary>
        /// Register #6.
        /// </summary>
        R5 = 5,
        /// <summary>
        /// Register #7.
        /// </summary>
        R6 = 6,
        /// <summary>
        /// Register #8.
        /// </summary>
        R7 = 7,
        /// <summary>
        /// Register #9.
        /// </summary>
        R8 = 8,
        /// <summary>
        /// Register #10.
        /// </summary>
        R9 = 9,
        /// <summary>
        /// Register #11.
        /// </summary>
        R10 = 10,
        /// <summary>
        /// Register #12.
        /// </summary>
        R11 = 11,
        /// <summary>
        /// Register #13.
        /// </summary>
        R12 = 12,
        /// <summary>
        /// Register #14.
        /// </summary>
        R13 = 13,
        /// <summary>
        /// Register #15.
        /// </summary>
        R14 = 14,
        /// <summary>
        /// Register #16.
        /// </summary>
        R15 = 15,
        /// <summary>
        /// Register A1.
        /// </summary>
        A1 = 0,
        /// <summary>
        /// Register A2.
        /// </summary>
        A2 = 1,
        /// <summary>
        /// Register A3.
        /// </summary>
        A3 = 2,
        /// <summary>
        /// Register A4.
        /// </summary>
        A4 = 3,
        /// <summary>
        /// Register V1.
        /// </summary>
        V1 = 4,
        /// <summary>
        /// Register V2.
        /// </summary>
        V2 = 5,
        /// <summary>
        /// Register V3.
        /// </summary>
        V3 = 6,
        /// <summary>
        /// Register V4.
        /// </summary>
        V4 = 7,
        /// <summary>
        /// Register V5.
        /// </summary>
        V5 = 8,
        /// <summary>
        /// Register V6.
        /// </summary>
        V6 = 9,
        /// <summary>
        /// Register V7.
        /// </summary>
        V7 = 10,
        /// <summary>
        /// Register V8.
        /// </summary>
        V8 = 11,
        /// <summary>
        /// Register IP.
        /// </summary>
        IP = 12,
        /// <summary>
        /// Register SP.
        /// </summary>
        SP = 13,
        /// <summary>
        /// Register LR.
        /// </summary>
        LR = 14,
        /// <summary>
        /// Register PC.
        /// </summary>
        PC = 15,
        /// <summary>
        /// Register WR.
        /// </summary>
        WR = 7,
        /// <summary>
        /// Register SB.
        /// </summary>
        SB = 9,
        /// <summary>
        /// Register SL.
        /// </summary>
        SL = 10,
        /// <summary>
        /// Register FP.
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

    /// <summary>
    /// Addressing type.
    /// </summary>
    public enum Addressing
    {
        /// <summary>
        /// Post-indexed addressing.
        /// </summary>
        PostIndexed = 0,
        /// <summary>
        /// Pre-indexed addressing (or offset addressing if `write` is false).
        /// </summary>
        PreIndexed = 1,
        /// <summary>
        /// Offset addressing (or pre-indexed addressing if `write` is true).
        /// </summary>
        Offset = 1,
    }

    /// <summary>
    /// Offset adding or subtracting mode.
    /// </summary>
    public enum OffsetMode
    {
        /// <summary>
        /// Subtract offset from the base.
        /// </summary>
        Subtract = 0,
        /// <summary>
        /// Add offset to the base.
        /// </summary>
        Add = 1,
    }

    partial class Arm
    {
        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)10485760 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)8388608 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)0 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits an 'eor' instruction.</summary>
        public static void eor(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)2097152 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits an 'orr' instruction.</summary>
        public static void orr(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)25165824 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'rsb' instruction.</summary>
        public static void rsb(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)6291456 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'rsc' instruction.</summary>
        public static void rsc(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)14680064 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'sbc' instruction.</summary>
        public static void sbc(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)12582912 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)4194304 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'bkpt' instruction.</summary>
        public static void bkpt(Stream stream, ushort immed)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)3776970864 | (((ushort)immed & (ushort)65520) << (uint)8)) | (((ushort)immed & (ushort)15) << (uint)0))), 0, 4);
        }

        /// <summary>Emits a 'b' instruction.</summary>
        public static void b(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)167772160 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'bic' instruction.</summary>
        public static void bic(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)29360128 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'blx' instruction.</summary>
        public static void blx(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)19922736 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'bx' instruction.</summary>
        public static void bx(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)19922704 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'bxj' instruction.</summary>
        public static void bxj(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)19922720 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'blxun' instruction.</summary>
        public static void blxun(Stream stream)
        {
            stream.Write(BitConverter.GetBytes((uint)(uint)4194304000), 0, 4);
        }

        /// <summary>Emits a 'clz' instruction.</summary>
        public static void clz(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)24055568 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'cmn' instruction.</summary>
        public static void cmn(Stream stream, Condition cond, Register rn)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)24117248 | (byte)cond) | ((byte)rn << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Condition cond, Register rn)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)22020096 | (byte)cond) | ((byte)rn << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'cpy' instruction.</summary>
        public static void cpy(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)27262976 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'cps' instruction.</summary>
        public static void cps(Stream stream, Mode mode)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)4043440128 | ((byte)mode << (uint)0))), 0, 4);
        }

        /// <summary>Emits a 'cpsie' instruction.</summary>
        public static void cpsie(Stream stream, InterruptFlags iflags)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)4043833344 | ((byte)iflags << (uint)6))), 0, 4);
        }

        /// <summary>Emits a 'cpsid' instruction.</summary>
        public static void cpsid(Stream stream, InterruptFlags iflags)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)4044095488 | ((byte)iflags << (uint)6))), 0, 4);
        }

        /// <summary>Emits a 'cpsie_mode' instruction.</summary>
        public static void cpsie_mode(Stream stream, InterruptFlags iflags, Mode mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)4043964416 | ((byte)iflags << (uint)6)) | ((byte)mode << (uint)0))), 0, 4);
        }

        /// <summary>Emits a 'cpsid_mode' instruction.</summary>
        public static void cpsid_mode(Stream stream, InterruptFlags iflags, Mode mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)4044226560 | ((byte)iflags << (uint)6)) | ((byte)mode << (uint)0))), 0, 4);
        }

        /// <summary>Emits a 'ldc' instruction.</summary>
        public static void ldc(Stream stream, Condition cond, bool write, Register rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)202375168 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)cpnum << (uint)8)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldm' instruction.</summary>
        public static void ldm(Stream stream, Condition cond, Register rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool copy_spsr)
        {
            Debug.Assert((((bool)copy_spsr == (uint)1) ^ ((bool)write == ((ushort)registers & (ushort)32768))), "(((bool)copy_spsr == (uint)1) ^ ((bool)write == ((ushort)registers & (ushort)32768)))");
            stream.Write(BitConverter.GetBytes((uint)(((((((((uint)135266304 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11)) | ((byte)addressing_mode << (uint)23)) | (ushort)registers) | ((bool)copy_spsr << (uint)21)) | ((bool)write << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'ldr' instruction.</summary>
        public static void ldr(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)68157440 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldrb' instruction.</summary>
        public static void ldrb(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)72351744 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldrbt' instruction.</summary>
        public static void ldrbt(Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)74448896 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)offset_mode << (uint)23))), 0, 4);
        }

        /// <summary>Emits a 'ldrd' instruction.</summary>
        public static void ldrd(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)208 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldrex' instruction.</summary>
        public static void ldrex(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)26218399 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'ldrh' instruction.</summary>
        public static void ldrh(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)1048752 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldrsb' instruction.</summary>
        public static void ldrsb(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)1048784 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldrsh' instruction.</summary>
        public static void ldrsh(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)1048816 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ldrt' instruction.</summary>
        public static void ldrt(Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)70254592 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)offset_mode << (uint)23))), 0, 4);
        }

        /// <summary>Emits a 'cdp' instruction.</summary>
        public static void cdp(Stream stream, Condition cond, Coprocessor cpnum)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)234881024 | (byte)cond) | ((byte)cpnum << (uint)8))), 0, 4);
        }

        /// <summary>Emits a 'mcr' instruction.</summary>
        public static void mcr(Stream stream, Condition cond, Register rd, Coprocessor cpnum)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)234881040 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)cpnum << (uint)8))), 0, 4);
        }

        /// <summary>Emits a 'mrc' instruction.</summary>
        public static void mrc(Stream stream, Condition cond, Register rd, Coprocessor cpnum)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)235929616 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)cpnum << (uint)8))), 0, 4);
        }

        /// <summary>Emits a 'mcrr' instruction.</summary>
        public static void mcrr(Stream stream, Condition cond, Register rn, Register rd, Coprocessor cpnum)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)205520896 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)cpnum << (uint)8))), 0, 4);
        }

        /// <summary>Emits a 'mla' instruction.</summary>
        public static void mla(Stream stream, Condition cond, bool update_cprs, Register rn, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((((uint)2097296 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'mov' instruction.</summary>
        public static void mov(Stream stream, Condition cond, bool update_cprs, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)27262976 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'mrrc' instruction.</summary>
        public static void mrrc(Stream stream, Condition cond, Register rn, Register rd, Coprocessor cpnum)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)206569472 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)cpnum << (uint)8))), 0, 4);
        }

        /// <summary>Emits a 'mrs' instruction.</summary>
        public static void mrs(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)17760256 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'mul' instruction.</summary>
        public static void mul(Stream stream, Condition cond, bool update_cprs, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)144 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rd << (uint)16)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'mvn' instruction.</summary>
        public static void mvn(Stream stream, Condition cond, bool update_cprs, Register rd, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)31457280 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((byte)rd << (uint)12)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'msr_imm' instruction.</summary>
        public static void msr_imm(Stream stream, Condition cond, FieldMask fieldmask)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)52490240 | (byte)cond) | ((byte)fieldmask << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'msr_reg' instruction.</summary>
        public static void msr_reg(Stream stream, Condition cond, FieldMask fieldmask)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)18935808 | (byte)cond) | ((byte)fieldmask << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'pkhbt' instruction.</summary>
        public static void pkhbt(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)109051920 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'pkhtb' instruction.</summary>
        public static void pkhtb(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)109051984 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'pld' instruction.</summary>
        public static void pld(Stream stream, Register rn, OffsetMode offset_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)4115722240 | ((byte)rn << (uint)16)) | ((byte)offset_mode << (uint)23))), 0, 4);
        }

        /// <summary>Emits a 'qadd' instruction.</summary>
        public static void qadd(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)16777296 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qadd16' instruction.</summary>
        public static void qadd16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)102764304 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qadd8' instruction.</summary>
        public static void qadd8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)102764432 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qaddsubx' instruction.</summary>
        public static void qaddsubx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)102764336 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qdadd' instruction.</summary>
        public static void qdadd(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)20971600 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qdsub' instruction.</summary>
        public static void qdsub(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)23068752 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qsub' instruction.</summary>
        public static void qsub(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)18874448 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qsub16' instruction.</summary>
        public static void qsub16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)102764400 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qsub8' instruction.</summary>
        public static void qsub8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)102764528 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'qsubaddx' instruction.</summary>
        public static void qsubaddx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)102764368 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'rev' instruction.</summary>
        public static void rev(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)113184560 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'rev16' instruction.</summary>
        public static void rev16(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)113184688 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'revsh' instruction.</summary>
        public static void revsh(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)117378992 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'rfe' instruction.</summary>
        public static void rfe(Stream stream, bool write, Register rn, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)4161800704 | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'sadd16' instruction.</summary>
        public static void sadd16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)101715728 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'sadd8' instruction.</summary>
        public static void sadd8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)101715856 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'saddsubx' instruction.</summary>
        public static void saddsubx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)101715760 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'sel' instruction.</summary>
        public static void sel(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)109055920 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'setendbe' instruction.</summary>
        public static void setendbe(Stream stream)
        {
            stream.Write(BitConverter.GetBytes((uint)(uint)4043375104), 0, 4);
        }

        /// <summary>Emits a 'setendle' instruction.</summary>
        public static void setendle(Stream stream)
        {
            stream.Write(BitConverter.GetBytes((uint)(uint)4043374592), 0, 4);
        }

        /// <summary>Emits a 'shadd16' instruction.</summary>
        public static void shadd16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)103812880 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'shadd8' instruction.</summary>
        public static void shadd8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)103813008 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'shaddsubx' instruction.</summary>
        public static void shaddsubx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)103812912 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'shsub16' instruction.</summary>
        public static void shsub16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)103812976 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'shsub8' instruction.</summary>
        public static void shsub8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)103813104 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'shsubaddx' instruction.</summary>
        public static void shsubaddx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)103812944 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'smlabb' instruction.</summary>
        public static void smlabb(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)16777344 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlabt' instruction.</summary>
        public static void smlabt(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)16777376 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlatb' instruction.</summary>
        public static void smlatb(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)16777408 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlatt' instruction.</summary>
        public static void smlatt(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)16777440 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlad' instruction.</summary>
        public static void smlad(Stream stream, Condition cond, bool exchange, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)117440528 | (byte)cond) | ((bool)exchange << (byte)5)) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlal' instruction.</summary>
        public static void smlal(Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)14680208 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'smlalbb' instruction.</summary>
        public static void smlalbb(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)20971648 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'smlalbt' instruction.</summary>
        public static void smlalbt(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)20971680 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'smlaltb' instruction.</summary>
        public static void smlaltb(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)20971712 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'smlaltt' instruction.</summary>
        public static void smlaltt(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)20971744 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'smlald' instruction.</summary>
        public static void smlald(Stream stream, Condition cond, bool exchange)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)121634832 | (byte)cond) | ((bool)exchange << (byte)5))), 0, 4);
        }

        /// <summary>Emits a 'smlawb' instruction.</summary>
        public static void smlawb(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)18874496 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlawt' instruction.</summary>
        public static void smlawt(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)18874560 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlsd' instruction.</summary>
        public static void smlsd(Stream stream, Condition cond, bool exchange, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)117440592 | (byte)cond) | ((bool)exchange << (byte)5)) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smlsld' instruction.</summary>
        public static void smlsld(Stream stream, Condition cond, bool exchange)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)121634896 | (byte)cond) | ((bool)exchange << (byte)5))), 0, 4);
        }

        /// <summary>Emits a 'smmla' instruction.</summary>
        public static void smmla(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)122683408 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smmls' instruction.</summary>
        public static void smmls(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)122683600 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smmul' instruction.</summary>
        public static void smmul(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)122744848 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smuad' instruction.</summary>
        public static void smuad(Stream stream, Condition cond, bool exchange, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)117501968 | (byte)cond) | ((bool)exchange << (byte)5)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smulbb' instruction.</summary>
        public static void smulbb(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)23068800 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smulbt' instruction.</summary>
        public static void smulbt(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)23068832 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smultb' instruction.</summary>
        public static void smultb(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)23068864 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smultt' instruction.</summary>
        public static void smultt(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)23068896 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smull' instruction.</summary>
        public static void smull(Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)12583056 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits a 'smulwb' instruction.</summary>
        public static void smulwb(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)18874528 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smulwt' instruction.</summary>
        public static void smulwt(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)18874592 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'smusd' instruction.</summary>
        public static void smusd(Stream stream, Condition cond, bool exchange, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)117502032 | (byte)cond) | ((bool)exchange << (byte)5)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'srs' instruction.</summary>
        public static void srs(Stream stream, bool write, Mode mode, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)4165797120 | ((bool)write << (byte)21)) | ((byte)mode << (uint)0)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'ssat' instruction.</summary>
        public static void ssat(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)105906192 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'ssat16' instruction.</summary>
        public static void ssat16(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)111152944 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'ssub16' instruction.</summary>
        public static void ssub16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)101715824 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'ssub8' instruction.</summary>
        public static void ssub8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)101715952 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'ssubaddx' instruction.</summary>
        public static void ssubaddx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)101715792 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void stc(Stream stream, Condition cond, bool write, Register rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)201326592 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)cpnum << (uint)8)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'stm' instruction.</summary>
        public static void stm(Stream stream, Condition cond, Register rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool user_mode)
        {
            Debug.Assert((((bool)user_mode == (bool)0) || ((bool)write == (bool)0)), "(((bool)user_mode == (bool)0) || ((bool)write == (bool)0))");
            stream.Write(BitConverter.GetBytes((uint)(((((((((uint)134217728 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11)) | ((byte)addressing_mode << (uint)23)) | (ushort)registers) | ((bool)user_mode << (uint)21)) | ((bool)write << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'str' instruction.</summary>
        public static void str(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)67108864 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'strb' instruction.</summary>
        public static void strb(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)71303168 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'strbt' instruction.</summary>
        public static void strbt(Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)73400320 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)offset_mode << (uint)23))), 0, 4);
        }

        /// <summary>Emits a 'strd' instruction.</summary>
        public static void strd(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)240 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'strex' instruction.</summary>
        public static void strex(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)25169808 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'strh' instruction.</summary>
        public static void strh(Stream stream, Condition cond, bool write, Register rn, Register rd, OffsetMode offset_mode, Addressing addressing_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((((uint)176 | (byte)cond) | ((bool)write << (byte)21)) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)addressing_mode << (uint)23)) | ((byte)offset_mode << (uint)11))), 0, 4);
        }

        /// <summary>Emits a 'strt' instruction.</summary>
        public static void strt(Stream stream, Condition cond, Register rn, Register rd, OffsetMode offset_mode)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)69206016 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)offset_mode << (uint)23))), 0, 4);
        }

        /// <summary>Emits a 'swi' instruction.</summary>
        public static void swi(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)251658240 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits a 'swp' instruction.</summary>
        public static void swp(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)16777360 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'swpb' instruction.</summary>
        public static void swpb(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)20971664 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits a 'sxtab' instruction.</summary>
        public static void sxtab(Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)111149168 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'sxtab16' instruction.</summary>
        public static void sxtab16(Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)109052016 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'sxtah' instruction.</summary>
        public static void sxtah(Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)112197744 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'sxtb' instruction.</summary>
        public static void sxtb(Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)112132208 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'sxtb16' instruction.</summary>
        public static void sxtb16(Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)110035056 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'sxth' instruction.</summary>
        public static void sxth(Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)113180784 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits a 'teq' instruction.</summary>
        public static void teq(Stream stream, Condition cond, Register rn)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)19922944 | (byte)cond) | ((byte)rn << (uint)16))), 0, 4);
        }

        /// <summary>Emits a 'tst' instruction.</summary>
        public static void tst(Stream stream, Condition cond, Register rn)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)17825792 | (byte)cond) | ((byte)rn << (uint)16))), 0, 4);
        }

        /// <summary>Emits an 'uadd16' instruction.</summary>
        public static void uadd16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)105910032 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uadd8' instruction.</summary>
        public static void uadd8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)105910160 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uaddsubx' instruction.</summary>
        public static void uaddsubx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)105910064 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uhadd16' instruction.</summary>
        public static void uhadd16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)108007184 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uhadd8' instruction.</summary>
        public static void uhadd8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)108007312 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uhaddsubx' instruction.</summary>
        public static void uhaddsubx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)108007216 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uhsub16' instruction.</summary>
        public static void uhsub16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)108007280 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uhsub8' instruction.</summary>
        public static void uhsub8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)108007408 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uhsubaddx' instruction.</summary>
        public static void uhsubaddx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)108007248 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'umaal' instruction.</summary>
        public static void umaal(Stream stream, Condition cond)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)4194448 | (byte)cond)), 0, 4);
        }

        /// <summary>Emits an 'umlal' instruction.</summary>
        public static void umlal(Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)10485904 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits an 'umull' instruction.</summary>
        public static void umull(Stream stream, Condition cond, bool update_cprs, bool update_condition)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)8388752 | (byte)cond) | ((bool)update_cprs << (byte)20)) | ((bool)update_condition << (uint)20))), 0, 4);
        }

        /// <summary>Emits an 'uqadd16' instruction.</summary>
        public static void uqadd16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)106958608 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uqadd8' instruction.</summary>
        public static void uqadd8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)106958736 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uqaddsubx' instruction.</summary>
        public static void uqaddsubx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)106958640 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uqsub16' instruction.</summary>
        public static void uqsub16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)106958704 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uqsub8' instruction.</summary>
        public static void uqsub8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)106958832 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uqsubaddx' instruction.</summary>
        public static void uqsubaddx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)106958672 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'usad8' instruction.</summary>
        public static void usad8(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)125890576 | (byte)cond) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits an 'usada8' instruction.</summary>
        public static void usada8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)125829136 | (byte)cond) | ((byte)rn << (uint)12)) | ((byte)rd << (uint)16))), 0, 4);
        }

        /// <summary>Emits an 'usat' instruction.</summary>
        public static void usat(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)115343376 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'usat16' instruction.</summary>
        public static void usat16(Stream stream, Condition cond, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)(((uint)115347248 | (byte)cond) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'usub16' instruction.</summary>
        public static void usub16(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)105910128 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'usub8' instruction.</summary>
        public static void usub8(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)105910256 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'usubaddx' instruction.</summary>
        public static void usubaddx(Stream stream, Condition cond, Register rn, Register rd)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)105910096 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12))), 0, 4);
        }

        /// <summary>Emits an 'uxtab' instruction.</summary>
        public static void uxtab(Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)115343472 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits an 'uxtab16' instruction.</summary>
        public static void uxtab16(Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)113246320 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits an 'uxtah' instruction.</summary>
        public static void uxtah(Stream stream, Condition cond, Register rn, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)116392048 | (byte)cond) | ((byte)rn << (uint)16)) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits an 'uxtb' instruction.</summary>
        public static void uxtb(Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)116326512 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits an 'uxtb16' instruction.</summary>
        public static void uxtb16(Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)114229360 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

        /// <summary>Emits an 'uxth' instruction.</summary>
        public static void uxth(Stream stream, Condition cond, Register rd, Rotation rotate)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)117375088 | (byte)cond) | ((byte)rd << (uint)12)) | ((byte)rotate << (uint)10))), 0, 4);
        }

    }
}
