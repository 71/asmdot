using System;
using System.Diagnostics;
using System.IO;

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
        public static void Sll(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)0 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'movci' instruction.</summary>
        public static void Movci(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)1 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'srl' instruction.</summary>
        public static void Srl(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)2 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sra' instruction.</summary>
        public static void Sra(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)3 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sllv' instruction.</summary>
        public static void Sllv(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)4 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'srlv' instruction.</summary>
        public static void Srlv(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)6 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'srav' instruction.</summary>
        public static void Srav(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)7 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'jr' instruction.</summary>
        public static void Jr(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)8 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'jalr' instruction.</summary>
        public static void Jalr(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)9 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'movz' instruction.</summary>
        public static void Movz(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)10 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'movn' instruction.</summary>
        public static void Movn(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)11 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'syscall' instruction.</summary>
        public static void Syscall(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)12 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'breakpoint' instruction.</summary>
        public static void Breakpoint(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)13 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sync' instruction.</summary>
        public static void Sync(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)15 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mfhi' instruction.</summary>
        public static void Mfhi(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)16 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mthi' instruction.</summary>
        public static void Mthi(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)17 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mflo' instruction.</summary>
        public static void Mflo(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)18 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsllv' instruction.</summary>
        public static void Dsllv(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)20 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsrlv' instruction.</summary>
        public static void Dsrlv(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)22 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsrav' instruction.</summary>
        public static void Dsrav(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)23 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mult' instruction.</summary>
        public static void Mult(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)24 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'multu' instruction.</summary>
        public static void Multu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)25 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'div' instruction.</summary>
        public static void Div(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)26 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'divu' instruction.</summary>
        public static void Divu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)27 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dmult' instruction.</summary>
        public static void Dmult(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)28 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dmultu' instruction.</summary>
        public static void Dmultu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)29 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'ddiv' instruction.</summary>
        public static void Ddiv(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)30 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'ddivu' instruction.</summary>
        public static void Ddivu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)31 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)32 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'addu' instruction.</summary>
        public static void Addu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)33 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)34 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'subu' instruction.</summary>
        public static void Subu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)35 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)36 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)37 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)38 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'nor' instruction.</summary>
        public static void Nor(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)39 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'slt' instruction.</summary>
        public static void Slt(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)42 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'sltu' instruction.</summary>
        public static void Sltu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)43 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dadd' instruction.</summary>
        public static void Dadd(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)44 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'daddu' instruction.</summary>
        public static void Daddu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)45 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsub' instruction.</summary>
        public static void Dsub(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)46 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsubu' instruction.</summary>
        public static void Dsubu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)47 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tge' instruction.</summary>
        public static void Tge(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)48 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tgeu' instruction.</summary>
        public static void Tgeu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)49 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tlt' instruction.</summary>
        public static void Tlt(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)50 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tltu' instruction.</summary>
        public static void Tltu(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)51 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'teq' instruction.</summary>
        public static void Teq(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)52 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'tne' instruction.</summary>
        public static void Tne(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)54 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsll' instruction.</summary>
        public static void Dsll(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)56 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dslr' instruction.</summary>
        public static void Dslr(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)58 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'dsra' instruction.</summary>
        public static void Dsra(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)59 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'mhc0' instruction.</summary>
        public static void Mhc0(this Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.WriteLE((uint)(((((uint)1073741824 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)rd & (uint)31) << (int)(uint)11)) | (((uint)shift & (uint)31) << (int)(uint)6)));
        }

        /// <summary>Emits a 'btlz' instruction.</summary>
        public static void Btlz(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgez' instruction.</summary>
        public static void Bgez(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bltzl' instruction.</summary>
        public static void Bltzl(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgezl' instruction.</summary>
        public static void Bgezl(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'sllv' instruction.</summary>
        public static void Sllv(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tgei' instruction.</summary>
        public static void Tgei(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'jalr' instruction.</summary>
        public static void Jalr(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tlti' instruction.</summary>
        public static void Tlti(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tltiu' instruction.</summary>
        public static void Tltiu(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'teqi' instruction.</summary>
        public static void Teqi(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'tnei' instruction.</summary>
        public static void Tnei(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bltzal' instruction.</summary>
        public static void Bltzal(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgezal' instruction.</summary>
        public static void Bgezal(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bltzall' instruction.</summary>
        public static void Bltzall(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'bgezall' instruction.</summary>
        public static void Bgezall(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'dsllv' instruction.</summary>
        public static void Dsllv(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits a 'synci' instruction.</summary>
        public static void Synci(this Stream stream, Register rs, ushort target)
        {
            stream.WriteLE((uint)(((uint)67108864 | (((uint)rs & (uint)31) << (int)(uint)16)) | (((uint)target >> (int)(uint)2) & (uint)65535)));
        }

        /// <summary>Emits an 'addi' instruction.</summary>
        public static void Addi(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)536870912 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits an 'addiu' instruction.</summary>
        public static void Addiu(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)603979776 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits an 'andi' instruction.</summary>
        public static void Andi(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)805306368 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'beq' instruction.</summary>
        public static void Beq(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)268435456 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)imm & (uint)65535) >> (int)2)));
        }

        /// <summary>Emits a 'blez' instruction.</summary>
        public static void Blez(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)402653184 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)imm & (uint)65535) >> (int)2)));
        }

        /// <summary>Emits a 'bne' instruction.</summary>
        public static void Bne(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)335544320 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | (((uint)imm & (uint)65535) >> (int)2)));
        }

        /// <summary>Emits a 'lw' instruction.</summary>
        public static void Lw(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)2348810240 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'lbu' instruction.</summary>
        public static void Lbu(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)2415919104 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'lhu' instruction.</summary>
        public static void Lhu(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)2483027968 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'lui' instruction.</summary>
        public static void Lui(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)1006632960 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits an 'ori' instruction.</summary>
        public static void Ori(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)872415232 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sb' instruction.</summary>
        public static void Sb(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)2684354560 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sh' instruction.</summary>
        public static void Sh(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)2751463424 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'slti' instruction.</summary>
        public static void Slti(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)671088640 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sltiu' instruction.</summary>
        public static void Sltiu(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)738197504 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'sw' instruction.</summary>
        public static void Sw(this Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.WriteLE((uint)((((uint)2885681152 | (((uint)rs & (uint)31) << (int)(uint)21)) | (((uint)rt & (uint)31) << (int)(uint)16)) | ((uint)imm & (uint)65535)));
        }

        /// <summary>Emits a 'j' instruction.</summary>
        public static void J(this Stream stream, uint address)
        {
            stream.WriteLE((uint)((uint)134217728 | (((uint)address >> (int)(uint)2) & (uint)67108863)));
        }

        /// <summary>Emits a 'jal' instruction.</summary>
        public static void Jal(this Stream stream, uint address)
        {
            stream.WriteLE((uint)((uint)201326592 | (((uint)address >> (int)(uint)2) & (uint)67108863)));
        }

        /// <summary>Assembles an instruction, given its opcode and operands.</summary>
        public static bool Assemble(this Stream stream, string opcode, params object[] operands)
        {
            switch (opcode)
            {
                case "sll":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Sll(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "movci":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Movci(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "srl":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Srl(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "sra":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Sra(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "sllv":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Sllv(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "srlv":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Srlv(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "srav":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Srav(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "jr":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Jr(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "jalr":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Jalr(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "movz":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Movz(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "movn":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Movn(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "syscall":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Syscall(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "breakpoint":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Breakpoint(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "sync":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Sync(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "mfhi":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Mfhi(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "mthi":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Mthi(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "mflo":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Mflo(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsllv":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsllv(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsrlv":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsrlv(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsrav":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsrav(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "mult":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Mult(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "multu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Multu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "div":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Div(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "divu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Divu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dmult":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dmult(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dmultu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dmultu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "ddiv":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Ddiv(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "ddivu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Ddivu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "add":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Add(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "addu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Addu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "sub":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Sub(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "subu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Subu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "and":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { And(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "or":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Or(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "xor":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Xor(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "nor":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Nor(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "slt":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Slt(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "sltu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Sltu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dadd":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dadd(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "daddu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Daddu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsub":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsub(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsubu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsubu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "tge":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Tge(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "tgeu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Tgeu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "tlt":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Tlt(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "tltu":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Tltu(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "teq":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Teq(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "tne":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Tne(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsll":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsll(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dslr":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dslr(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "dsra":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Dsra(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "mhc0":
                    if (true && rd is Register rd_ && rs is Register rs_ && rt is Register rt_ && shift is byte shift_) { Mhc0(stream, rd_, rs_, rt_, shift_); return true; }
                    return false;
                case "btlz":
                    if (true && rs is Register rs_ && target is ushort target_) { Btlz(stream, rs_, target_); return true; }
                    return false;
                case "bgez":
                    if (true && rs is Register rs_ && target is ushort target_) { Bgez(stream, rs_, target_); return true; }
                    return false;
                case "bltzl":
                    if (true && rs is Register rs_ && target is ushort target_) { Bltzl(stream, rs_, target_); return true; }
                    return false;
                case "bgezl":
                    if (true && rs is Register rs_ && target is ushort target_) { Bgezl(stream, rs_, target_); return true; }
                    return false;
                case "sllv":
                    if (true && rs is Register rs_ && target is ushort target_) { Sllv(stream, rs_, target_); return true; }
                    return false;
                case "tgei":
                    if (true && rs is Register rs_ && target is ushort target_) { Tgei(stream, rs_, target_); return true; }
                    return false;
                case "jalr":
                    if (true && rs is Register rs_ && target is ushort target_) { Jalr(stream, rs_, target_); return true; }
                    return false;
                case "tlti":
                    if (true && rs is Register rs_ && target is ushort target_) { Tlti(stream, rs_, target_); return true; }
                    return false;
                case "tltiu":
                    if (true && rs is Register rs_ && target is ushort target_) { Tltiu(stream, rs_, target_); return true; }
                    return false;
                case "teqi":
                    if (true && rs is Register rs_ && target is ushort target_) { Teqi(stream, rs_, target_); return true; }
                    return false;
                case "tnei":
                    if (true && rs is Register rs_ && target is ushort target_) { Tnei(stream, rs_, target_); return true; }
                    return false;
                case "bltzal":
                    if (true && rs is Register rs_ && target is ushort target_) { Bltzal(stream, rs_, target_); return true; }
                    return false;
                case "bgezal":
                    if (true && rs is Register rs_ && target is ushort target_) { Bgezal(stream, rs_, target_); return true; }
                    return false;
                case "bltzall":
                    if (true && rs is Register rs_ && target is ushort target_) { Bltzall(stream, rs_, target_); return true; }
                    return false;
                case "bgezall":
                    if (true && rs is Register rs_ && target is ushort target_) { Bgezall(stream, rs_, target_); return true; }
                    return false;
                case "dsllv":
                    if (true && rs is Register rs_ && target is ushort target_) { Dsllv(stream, rs_, target_); return true; }
                    return false;
                case "synci":
                    if (true && rs is Register rs_ && target is ushort target_) { Synci(stream, rs_, target_); return true; }
                    return false;
                case "addi":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Addi(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "addiu":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Addiu(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "andi":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Andi(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "beq":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Beq(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "blez":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Blez(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "bne":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Bne(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "lw":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Lw(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "lbu":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Lbu(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "lhu":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Lhu(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "lui":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Lui(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "ori":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Ori(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "sb":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Sb(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "sh":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Sh(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "slti":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Slti(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "sltiu":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Sltiu(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "sw":
                    if (true && rs is Register rs_ && rt is Register rt_ && imm is ushort imm_) { Sw(stream, rs_, rt_, imm_); return true; }
                    return false;
                case "j":
                    if (true && address is uint address_) { J(stream, address_); return true; }
                    return false;
                case "jal":
                    if (true && address is uint address_) { Jal(stream, address_); return true; }
                    return false;
            }
            return false;
        }
    }
}
