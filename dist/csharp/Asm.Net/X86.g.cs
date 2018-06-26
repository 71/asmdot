using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net
{
    /// <summary>An x86 8-bits register.</summary>
    public struct Register8
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register8 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register8(byte value) => new Register8(value);

        /// <summary>Creates a new Register8, given its underlying value.</summary>
        public Register8(byte underlyingValue) { Value = underlyingValue; }

        public static readonly Register8 AL = new Register8(0);
        public static readonly Register8 CL = new Register8(1);
        public static readonly Register8 DL = new Register8(2);
        public static readonly Register8 BL = new Register8(3);
        public static readonly Register8 SPL = new Register8(4);
        public static readonly Register8 BPL = new Register8(5);
        public static readonly Register8 SIL = new Register8(6);
        public static readonly Register8 DIL = new Register8(7);
        public static readonly Register8 R8B = new Register8(8);
        public static readonly Register8 R9B = new Register8(9);
        public static readonly Register8 R10B = new Register8(10);
        public static readonly Register8 R11B = new Register8(11);
        public static readonly Register8 R12B = new Register8(12);
        public static readonly Register8 R13B = new Register8(13);
        public static readonly Register8 R14B = new Register8(14);
        public static readonly Register8 R15B = new Register8(15);
    }

    /// <summary>An x86 16-bits register.</summary>
    public struct Register16
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register16 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register16(byte value) => new Register16(value);

        /// <summary>Creates a new Register16, given its underlying value.</summary>
        public Register16(byte underlyingValue) { Value = underlyingValue; }

        public static readonly Register16 AX = new Register16(0);
        public static readonly Register16 CX = new Register16(1);
        public static readonly Register16 DX = new Register16(2);
        public static readonly Register16 BX = new Register16(3);
        public static readonly Register16 SP = new Register16(4);
        public static readonly Register16 BP = new Register16(5);
        public static readonly Register16 SI = new Register16(6);
        public static readonly Register16 DI = new Register16(7);
        public static readonly Register16 R8W = new Register16(8);
        public static readonly Register16 R9W = new Register16(9);
        public static readonly Register16 R10W = new Register16(10);
        public static readonly Register16 R11W = new Register16(11);
        public static readonly Register16 R12W = new Register16(12);
        public static readonly Register16 R13W = new Register16(13);
        public static readonly Register16 R14W = new Register16(14);
        public static readonly Register16 R15W = new Register16(15);
    }

    /// <summary>An x86 32-bits register.</summary>
    public struct Register32
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register32 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register32(byte value) => new Register32(value);

        /// <summary>Creates a new Register32, given its underlying value.</summary>
        public Register32(byte underlyingValue) { Value = underlyingValue; }

        public static readonly Register32 EAX = new Register32(0);
        public static readonly Register32 ECX = new Register32(1);
        public static readonly Register32 EDX = new Register32(2);
        public static readonly Register32 EBX = new Register32(3);
        public static readonly Register32 ESP = new Register32(4);
        public static readonly Register32 EBP = new Register32(5);
        public static readonly Register32 ESI = new Register32(6);
        public static readonly Register32 EDI = new Register32(7);
        public static readonly Register32 R8D = new Register32(8);
        public static readonly Register32 R9D = new Register32(9);
        public static readonly Register32 R10D = new Register32(10);
        public static readonly Register32 R11D = new Register32(11);
        public static readonly Register32 R12D = new Register32(12);
        public static readonly Register32 R13D = new Register32(13);
        public static readonly Register32 R14D = new Register32(14);
        public static readonly Register32 R15D = new Register32(15);
    }

    /// <summary>An x86 64-bits register.</summary>
    public struct Register64
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register64 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register64(byte value) => new Register64(value);

        /// <summary>Creates a new Register64, given its underlying value.</summary>
        public Register64(byte underlyingValue) { Value = underlyingValue; }

        public static readonly Register64 RAX = new Register64(0);
        public static readonly Register64 RCX = new Register64(1);
        public static readonly Register64 RDX = new Register64(2);
        public static readonly Register64 RBX = new Register64(3);
        public static readonly Register64 RSP = new Register64(4);
        public static readonly Register64 RBP = new Register64(5);
        public static readonly Register64 RSI = new Register64(6);
        public static readonly Register64 RDI = new Register64(7);
        public static readonly Register64 R8 = new Register64(8);
        public static readonly Register64 R9 = new Register64(9);
        public static readonly Register64 R10 = new Register64(10);
        public static readonly Register64 R11 = new Register64(11);
        public static readonly Register64 R12 = new Register64(12);
        public static readonly Register64 R13 = new Register64(13);
        public static readonly Register64 R14 = new Register64(14);
        public static readonly Register64 R15 = new Register64(15);
    }

    /// <summary>An x86 128-bits register.</summary>
    public struct Register128
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register128 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register128(byte value) => new Register128(value);

        /// <summary>Creates a new Register128, given its underlying value.</summary>
        public Register128(byte underlyingValue) { Value = underlyingValue; }
    }

    partial class X86
    {
        /// <summary>Emits a 'pushf' instruction.</summary>
        public static void pushf(Stream stream)
        {
            stream.WriteByte((byte)156);
        }

        /// <summary>Emits a 'popf' instruction.</summary>
        public static void popf(Stream stream)
        {
            stream.WriteByte((byte)157);
        }

        /// <summary>Emits a 'ret' instruction.</summary>
        public static void ret(Stream stream)
        {
            stream.WriteByte((byte)195);
        }

        /// <summary>Emits a 'clc' instruction.</summary>
        public static void clc(Stream stream)
        {
            stream.WriteByte((byte)248);
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void stc(Stream stream)
        {
            stream.WriteByte((byte)249);
        }

        /// <summary>Emits a 'cli' instruction.</summary>
        public static void cli(Stream stream)
        {
            stream.WriteByte((byte)250);
        }

        /// <summary>Emits a 'sti' instruction.</summary>
        public static void sti(Stream stream)
        {
            stream.WriteByte((byte)251);
        }

        /// <summary>Emits a 'cld' instruction.</summary>
        public static void cld(Stream stream)
        {
            stream.WriteByte((byte)252);
        }

        /// <summary>Emits a 'std' instruction.</summary>
        public static void std(Stream stream)
        {
            stream.WriteByte((byte)253);
        }

        /// <summary>Emits a 'jo' instruction.</summary>
        public static void jo(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)112);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jno' instruction.</summary>
        public static void jno(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)113);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jb' instruction.</summary>
        public static void jb(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)114);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnae' instruction.</summary>
        public static void jnae(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)114);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jc' instruction.</summary>
        public static void jc(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)114);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnb' instruction.</summary>
        public static void jnb(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)115);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jae' instruction.</summary>
        public static void jae(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)115);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnc' instruction.</summary>
        public static void jnc(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)115);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jz' instruction.</summary>
        public static void jz(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)116);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'je' instruction.</summary>
        public static void je(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)116);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnz' instruction.</summary>
        public static void jnz(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)117);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jne' instruction.</summary>
        public static void jne(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)117);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jbe' instruction.</summary>
        public static void jbe(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)118);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jna' instruction.</summary>
        public static void jna(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)118);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnbe' instruction.</summary>
        public static void jnbe(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)119);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'ja' instruction.</summary>
        public static void ja(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)119);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'js' instruction.</summary>
        public static void js(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)120);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jns' instruction.</summary>
        public static void jns(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)121);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jp' instruction.</summary>
        public static void jp(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)122);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jpe' instruction.</summary>
        public static void jpe(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)122);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnp' instruction.</summary>
        public static void jnp(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)123);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jpo' instruction.</summary>
        public static void jpo(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)123);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jl' instruction.</summary>
        public static void jl(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)124);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnge' instruction.</summary>
        public static void jnge(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)124);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnl' instruction.</summary>
        public static void jnl(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)125);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jge' instruction.</summary>
        public static void jge(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)125);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jle' instruction.</summary>
        public static void jle(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)126);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jng' instruction.</summary>
        public static void jng(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)126);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnle' instruction.</summary>
        public static void jnle(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)127);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jg' instruction.</summary>
        public static void jg(Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)127);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void inc(Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)64 + (byte)operand));
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void inc(Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)64 + (byte)operand));
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void dec(Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)72 + (byte)operand));
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void dec(Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)72 + (byte)operand));
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void push(Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)80 + (byte)operand));
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void push(Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)80 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void pop(Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void pop(Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void pop(Stream stream, Register64 operand)
        {
            stream.WriteByte(((byte)72 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)0)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)1)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)2)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)3)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)4)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)5)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)6)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.Write(BitConverter.GetBytes((Register8)((byte)reg + (byte)7)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)0)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)0)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)0)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)0)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)1)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)1)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)1)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)1)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)2)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)2)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)2)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)2)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)3)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)3)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)3)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)3)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)4)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)4)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)4)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)4)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)5)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)5)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)5)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)5)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)6)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)6)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)6)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)6)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)7)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)7)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)7)), 0, 1);
            stream.Write(BitConverter.GetBytes((short)(short)value), 0, 2);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)7)), 0, 1);
            stream.Write(BitConverter.GetBytes((int)(int)value), 0, 4);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)0)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void add(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)0)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)1)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void or(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)1)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)2)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void adc(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)2)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)3)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void sbb(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)3)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)4)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void and(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)4)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)5)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void sub(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)5)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)6)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void xor(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)6)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register16)((byte)reg + (byte)7)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void cmp(Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.Write(BitConverter.GetBytes((Register32)((byte)reg + (byte)7)), 0, 1);
            stream.WriteByte((sbyte)value);
        }

    }
}
