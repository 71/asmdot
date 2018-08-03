using System;
using System.Diagnostics;

#if USE_BUFFERS
using OutputBuffer = System.Buffers.IBufferWriter<byte>;
#else
using OutputBuffer = System.IO.Stream;
#endif

namespace Asm.Net.Mips
{
    /// <summary>A Mips register.</summary>
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

        public static readonly Register ZERO = new Register(0);
        public static readonly Register AT = new Register(1);
        public static readonly Register V0 = new Register(2);
        public static readonly Register V1 = new Register(3);
        public static readonly Register A0 = new Register(4);
        public static readonly Register A1 = new Register(5);
        public static readonly Register A2 = new Register(6);
        public static readonly Register A3 = new Register(7);
        public static readonly Register T0 = new Register(8);
        public static readonly Register T1 = new Register(9);
        public static readonly Register T2 = new Register(10);
        public static readonly Register T3 = new Register(11);
        public static readonly Register T4 = new Register(12);
        public static readonly Register T5 = new Register(13);
        public static readonly Register T6 = new Register(14);
        public static readonly Register T7 = new Register(15);
        public static readonly Register S0 = new Register(16);
        public static readonly Register S1 = new Register(17);
        public static readonly Register S2 = new Register(18);
        public static readonly Register S3 = new Register(19);
        public static readonly Register S4 = new Register(20);
        public static readonly Register S5 = new Register(21);
        public static readonly Register S6 = new Register(22);
        public static readonly Register S7 = new Register(23);
        public static readonly Register T8 = new Register(24);
        public static readonly Register T9 = new Register(25);
        public static readonly Register K0 = new Register(26);
        public static readonly Register K1 = new Register(27);
        public static readonly Register GP = new Register(28);
        public static readonly Register SP = new Register(29);
        public static readonly Register FP = new Register(30);
        public static readonly Register RA = new Register(31);
    }

    partial class Mips
    {
        /// <summary>Emits a 'sll' instruction.</summary>
        public static void Sll(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)0 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'movci' instruction.</summary>
        public static void Movci(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)1 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'srl' instruction.</summary>
        public static void Srl(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)2 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sra' instruction.</summary>
        public static void Sra(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)3 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sllv' instruction.</summary>
        public static void Sllv(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)4 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'srlv' instruction.</summary>
        public static void Srlv(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)6 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'srav' instruction.</summary>
        public static void Srav(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)7 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'jr' instruction.</summary>
        public static void Jr(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)8 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'jalr' instruction.</summary>
        public static void Jalr(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)9 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'movz' instruction.</summary>
        public static void Movz(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)10 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'movn' instruction.</summary>
        public static void Movn(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)11 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'syscall' instruction.</summary>
        public static void Syscall(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)12 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'breakpoint' instruction.</summary>
        public static void Breakpoint(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)13 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sync' instruction.</summary>
        public static void Sync(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)15 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mfhi' instruction.</summary>
        public static void Mfhi(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)16 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mthi' instruction.</summary>
        public static void Mthi(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)17 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mflo' instruction.</summary>
        public static void Mflo(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)18 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsllv' instruction.</summary>
        public static void Dsllv(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)20 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsrlv' instruction.</summary>
        public static void Dsrlv(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)22 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsrav' instruction.</summary>
        public static void Dsrav(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)23 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mult' instruction.</summary>
        public static void Mult(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)24 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'multu' instruction.</summary>
        public static void Multu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)25 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'div' instruction.</summary>
        public static void Div(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)26 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'divu' instruction.</summary>
        public static void Divu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)27 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dmult' instruction.</summary>
        public static void Dmult(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)28 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dmultu' instruction.</summary>
        public static void Dmultu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)29 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'ddiv' instruction.</summary>
        public static void Ddiv(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)30 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'ddivu' instruction.</summary>
        public static void Ddivu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)31 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)32 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'addu' instruction.</summary>
        public static void Addu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)33 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)34 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'subu' instruction.</summary>
        public static void Subu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)35 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)36 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)37 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)38 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'nor' instruction.</summary>
        public static void Nor(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)39 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'slt' instruction.</summary>
        public static void Slt(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)42 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sltu' instruction.</summary>
        public static void Sltu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)43 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dadd' instruction.</summary>
        public static void Dadd(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)44 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'daddu' instruction.</summary>
        public static void Daddu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)45 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsub' instruction.</summary>
        public static void Dsub(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)46 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsubu' instruction.</summary>
        public static void Dsubu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)47 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tge' instruction.</summary>
        public static void Tge(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)48 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tgeu' instruction.</summary>
        public static void Tgeu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)49 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tlt' instruction.</summary>
        public static void Tlt(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)50 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tltu' instruction.</summary>
        public static void Tltu(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)51 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'teq' instruction.</summary>
        public static void Teq(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)52 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tne' instruction.</summary>
        public static void Tne(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)54 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsll' instruction.</summary>
        public static void Dsll(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)56 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dslr' instruction.</summary>
        public static void Dslr(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)58 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsra' instruction.</summary>
        public static void Dsra(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)59 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mhc0' instruction.</summary>
        public static void Mhc0(this OutputBuffer buffer, Register rd, Register rs, Register rt, byte shift)
        {
            buffer.WriteLE((uint)(((((uint)1073741824 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'btlz' instruction.</summary>
        public static void Btlz(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgez' instruction.</summary>
        public static void Bgez(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bltzl' instruction.</summary>
        public static void Bltzl(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgezl' instruction.</summary>
        public static void Bgezl(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'sllv' instruction.</summary>
        public static void Sllv(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tgei' instruction.</summary>
        public static void Tgei(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'jalr' instruction.</summary>
        public static void Jalr(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tlti' instruction.</summary>
        public static void Tlti(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tltiu' instruction.</summary>
        public static void Tltiu(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'teqi' instruction.</summary>
        public static void Teqi(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tnei' instruction.</summary>
        public static void Tnei(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bltzal' instruction.</summary>
        public static void Bltzal(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgezal' instruction.</summary>
        public static void Bgezal(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bltzall' instruction.</summary>
        public static void Bltzall(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgezall' instruction.</summary>
        public static void Bgezall(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'dsllv' instruction.</summary>
        public static void Dsllv(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'synci' instruction.</summary>
        public static void Synci(this OutputBuffer buffer, Register rs, ushort target)
        {
            buffer.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits an 'addi' instruction.</summary>
        public static void Addi(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)536870912 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits an 'addiu' instruction.</summary>
        public static void Addiu(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)603979776 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits an 'andi' instruction.</summary>
        public static void Andi(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)805306368 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'beq' instruction.</summary>
        public static void Beq(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)268435456 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)imm & (uint)65535) >> (int)2)));
        }

        /// <summary>Emits a 'blez' instruction.</summary>
        public static void Blez(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)402653184 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)imm & (uint)65535) >> (int)2)));
        }

        /// <summary>Emits a 'bne' instruction.</summary>
        public static void Bne(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)335544320 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)imm & (uint)65535) >> (int)2)));
        }

        /// <summary>Emits a 'lw' instruction.</summary>
        public static void Lw(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)2348810240 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'lbu' instruction.</summary>
        public static void Lbu(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)2415919104 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'lhu' instruction.</summary>
        public static void Lhu(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)2483027968 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'lui' instruction.</summary>
        public static void Lui(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)1006632960 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits an 'ori' instruction.</summary>
        public static void Ori(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)872415232 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sb' instruction.</summary>
        public static void Sb(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)2684354560 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sh' instruction.</summary>
        public static void Sh(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)2751463424 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'slti' instruction.</summary>
        public static void Slti(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)671088640 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sltiu' instruction.</summary>
        public static void Sltiu(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)738197504 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sw' instruction.</summary>
        public static void Sw(this OutputBuffer buffer, Register rs, Register rt, ushort imm)
        {
            buffer.WriteLE((uint)((((uint)2885681152 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'j' instruction.</summary>
        public static void J(this OutputBuffer buffer, uint address)
        {
            buffer.WriteLE((uint)((uint)134217728 | (((uint)address >> (int)(uint)2) & (uint)67108863)));
        }

        /// <summary>Emits a 'jal' instruction.</summary>
        public static void Jal(this OutputBuffer buffer, uint address)
        {
            buffer.WriteLE((uint)((uint)201326592 | (((uint)address >> (int)(uint)2) & (uint)67108863)));
        }

        /// <summary>Assembles an instruction, given its opcode and operands.</summary>
        public static bool Assemble(this OutputBuffer buffer, string opcode, params object[] operands)
        {
            switch (opcode)
            {
                case "add":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Add(rd, rs, rt, shift); return true; }
                }

                return false;
                case "addi":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Addi(rs, rt, imm); return true; }
                }

                return false;
                case "addiu":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Addiu(rs, rt, imm); return true; }
                }

                return false;
                case "addu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Addu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "and":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.And(rd, rs, rt, shift); return true; }
                }

                return false;
                case "andi":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Andi(rs, rt, imm); return true; }
                }

                return false;
                case "beq":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Beq(rs, rt, imm); return true; }
                }

                return false;
                case "bgez":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bgez(rs, target); return true; }
                }

                return false;
                case "bgezal":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bgezal(rs, target); return true; }
                }

                return false;
                case "bgezall":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bgezall(rs, target); return true; }
                }

                return false;
                case "bgezl":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bgezl(rs, target); return true; }
                }

                return false;
                case "blez":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Blez(rs, rt, imm); return true; }
                }

                return false;
                case "bltzal":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bltzal(rs, target); return true; }
                }

                return false;
                case "bltzall":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bltzall(rs, target); return true; }
                }

                return false;
                case "bltzl":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Bltzl(rs, target); return true; }
                }

                return false;
                case "bne":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Bne(rs, rt, imm); return true; }
                }

                return false;
                case "breakpoint":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Breakpoint(rd, rs, rt, shift); return true; }
                }

                return false;
                case "btlz":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Btlz(rs, target); return true; }
                }

                return false;
                case "dadd":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dadd(rd, rs, rt, shift); return true; }
                }

                return false;
                case "daddu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Daddu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "ddiv":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Ddiv(rd, rs, rt, shift); return true; }
                }

                return false;
                case "ddivu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Ddivu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "div":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Div(rd, rs, rt, shift); return true; }
                }

                return false;
                case "divu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Divu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dmult":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dmult(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dmultu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dmultu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsll":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsll(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsllv":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsllv(rd, rs, rt, shift); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Dsllv(rs, target); return true; }
                }

                return false;
                case "dslr":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dslr(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsra":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsra(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsrav":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsrav(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsrlv":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsrlv(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsub":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsub(rd, rs, rt, shift); return true; }
                }

                return false;
                case "dsubu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Dsubu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "j":
                {
                    if (operands.Length == 1 && operands[0] is uint address) { buffer.J(address); return true; }
                }

                return false;
                case "jal":
                {
                    if (operands.Length == 1 && operands[0] is uint address) { buffer.Jal(address); return true; }
                }

                return false;
                case "jalr":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Jalr(rd, rs, rt, shift); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Jalr(rs, target); return true; }
                }

                return false;
                case "jr":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Jr(rd, rs, rt, shift); return true; }
                }

                return false;
                case "lbu":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Lbu(rs, rt, imm); return true; }
                }

                return false;
                case "lhu":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Lhu(rs, rt, imm); return true; }
                }

                return false;
                case "lui":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Lui(rs, rt, imm); return true; }
                }

                return false;
                case "lw":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Lw(rs, rt, imm); return true; }
                }

                return false;
                case "mfhi":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Mfhi(rd, rs, rt, shift); return true; }
                }

                return false;
                case "mflo":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Mflo(rd, rs, rt, shift); return true; }
                }

                return false;
                case "mhc0":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Mhc0(rd, rs, rt, shift); return true; }
                }

                return false;
                case "movci":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Movci(rd, rs, rt, shift); return true; }
                }

                return false;
                case "movn":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Movn(rd, rs, rt, shift); return true; }
                }

                return false;
                case "movz":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Movz(rd, rs, rt, shift); return true; }
                }

                return false;
                case "mthi":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Mthi(rd, rs, rt, shift); return true; }
                }

                return false;
                case "mult":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Mult(rd, rs, rt, shift); return true; }
                }

                return false;
                case "multu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Multu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "nor":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Nor(rd, rs, rt, shift); return true; }
                }

                return false;
                case "or":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Or(rd, rs, rt, shift); return true; }
                }

                return false;
                case "ori":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Ori(rs, rt, imm); return true; }
                }

                return false;
                case "sb":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Sb(rs, rt, imm); return true; }
                }

                return false;
                case "sh":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Sh(rs, rt, imm); return true; }
                }

                return false;
                case "sll":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Sll(rd, rs, rt, shift); return true; }
                }

                return false;
                case "sllv":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Sllv(rd, rs, rt, shift); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Sllv(rs, target); return true; }
                }

                return false;
                case "slt":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Slt(rd, rs, rt, shift); return true; }
                }

                return false;
                case "slti":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Slti(rs, rt, imm); return true; }
                }

                return false;
                case "sltiu":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Sltiu(rs, rt, imm); return true; }
                }

                return false;
                case "sltu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Sltu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "sra":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Sra(rd, rs, rt, shift); return true; }
                }

                return false;
                case "srav":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Srav(rd, rs, rt, shift); return true; }
                }

                return false;
                case "srl":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Srl(rd, rs, rt, shift); return true; }
                }

                return false;
                case "srlv":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Srlv(rd, rs, rt, shift); return true; }
                }

                return false;
                case "sub":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Sub(rd, rs, rt, shift); return true; }
                }

                return false;
                case "subu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Subu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "sw":
                {
                    if (operands.Length == 3 && operands[0] is Register rs && operands[1] is Register rt && operands[2] is ushort imm) { buffer.Sw(rs, rt, imm); return true; }
                }

                return false;
                case "sync":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Sync(rd, rs, rt, shift); return true; }
                }

                return false;
                case "synci":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Synci(rs, target); return true; }
                }

                return false;
                case "syscall":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Syscall(rd, rs, rt, shift); return true; }
                }

                return false;
                case "teq":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Teq(rd, rs, rt, shift); return true; }
                }

                return false;
                case "teqi":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Teqi(rs, target); return true; }
                }

                return false;
                case "tge":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Tge(rd, rs, rt, shift); return true; }
                }

                return false;
                case "tgei":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Tgei(rs, target); return true; }
                }

                return false;
                case "tgeu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Tgeu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "tlt":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Tlt(rd, rs, rt, shift); return true; }
                }

                return false;
                case "tlti":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Tlti(rs, target); return true; }
                }

                return false;
                case "tltiu":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Tltiu(rs, target); return true; }
                }

                return false;
                case "tltu":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Tltu(rd, rs, rt, shift); return true; }
                }

                return false;
                case "tne":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Tne(rd, rs, rt, shift); return true; }
                }

                return false;
                case "tnei":
                {
                    if (operands.Length == 2 && operands[0] is Register rs && operands[1] is ushort target) { buffer.Tnei(rs, target); return true; }
                }

                return false;
                case "xor":
                {
                    if (operands.Length == 4 && operands[0] is Register rd && operands[1] is Register rs && operands[2] is Register rt && operands[3] is byte shift) { buffer.Xor(rd, rs, rt, shift); return true; }
                }

                return false;
            }
            return false;
        }
    }
}
