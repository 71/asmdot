using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net
{
    /// <summary>Mips register</summary>
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
        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)32 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits an 'addu' instruction.</summary>
        public static void addu(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)33 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)36 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'div' instruction.</summary>
        public static void div(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)26 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'divu' instruction.</summary>
        public static void divu(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)27 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'jr' instruction.</summary>
        public static void jr(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)8 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'mfhi' instruction.</summary>
        public static void mfhi(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)16 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'mflo' instruction.</summary>
        public static void mflo(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)18 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'mhc0' instruction.</summary>
        public static void mhc0(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)1073741824 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'mult' instruction.</summary>
        public static void mult(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)24 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'multu' instruction.</summary>
        public static void multu(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)25 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'nor' instruction.</summary>
        public static void nor(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)39 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)38 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)37 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'slt' instruction.</summary>
        public static void slt(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)42 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'sltu' instruction.</summary>
        public static void sltu(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)43 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'sll' instruction.</summary>
        public static void sll(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)0 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'srl' instruction.</summary>
        public static void srl(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)2 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'sra' instruction.</summary>
        public static void sra(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)3 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)34 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits a 'subu' instruction.</summary>
        public static void subu(Stream stream, Register rd, Register rs, Register rt, byte shift)
        {
            stream.Write(BitConverter.GetBytes((uint)(((((uint)35 | ((byte)rs << 21)) | ((byte)rt << 16)) | ((byte)rd << 11)) | ((byte)shift << 6))), 0, 4);
        }

        /// <summary>Emits an 'addi' instruction.</summary>
        public static void addi(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)536870912 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits an 'addiu' instruction.</summary>
        public static void addiu(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)603979776 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits an 'andi' instruction.</summary>
        public static void andi(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)805306368 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'beq' instruction.</summary>
        public static void beq(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)268435456 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'blez' instruction.</summary>
        public static void blez(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)402653184 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'bne' instruction.</summary>
        public static void bne(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)335544320 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'lbu' instruction.</summary>
        public static void lbu(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)2415919104 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'lhu' instruction.</summary>
        public static void lhu(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)2483027968 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'lui' instruction.</summary>
        public static void lui(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)1006632960 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits an 'ori' instruction.</summary>
        public static void ori(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)872415232 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'sb' instruction.</summary>
        public static void sb(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)2684354560 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'sh' instruction.</summary>
        public static void sh(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)2751463424 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'slti' instruction.</summary>
        public static void slti(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)671088640 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'sltiu' instruction.</summary>
        public static void sltiu(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)738197504 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'sw' instruction.</summary>
        public static void sw(Stream stream, Register rs, Register rt, ushort imm)
        {
            stream.Write(BitConverter.GetBytes((uint)((((uint)2885681152 | ((byte)rs << 21)) | ((byte)rt << 16)) | (ushort)imm)), 0, 4);
        }

        /// <summary>Emits a 'j' instruction.</summary>
        public static void j(Stream stream, uint addr)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)2885681152 | (67108863 & ((uint)addr << 2)))), 0, 4);
        }

        /// <summary>Emits a 'jal' instruction.</summary>
        public static void jal(Stream stream, uint addr)
        {
            stream.Write(BitConverter.GetBytes((uint)((uint)2885681152 | (67108863 & ((uint)addr << 2)))), 0, 4);
        }

    }
}
