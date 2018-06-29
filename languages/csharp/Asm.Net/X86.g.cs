using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net.X86
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
        public static void Pushf(this Stream stream)
        {
            stream.WriteByte((byte)156);
        }

        /// <summary>Emits a 'popf' instruction.</summary>
        public static void Popf(this Stream stream)
        {
            stream.WriteByte((byte)157);
        }

        /// <summary>Emits a 'ret' instruction.</summary>
        public static void Ret(this Stream stream)
        {
            stream.WriteByte((byte)195);
        }

        /// <summary>Emits a 'clc' instruction.</summary>
        public static void Clc(this Stream stream)
        {
            stream.WriteByte((byte)248);
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void Stc(this Stream stream)
        {
            stream.WriteByte((byte)249);
        }

        /// <summary>Emits a 'cli' instruction.</summary>
        public static void Cli(this Stream stream)
        {
            stream.WriteByte((byte)250);
        }

        /// <summary>Emits a 'sti' instruction.</summary>
        public static void Sti(this Stream stream)
        {
            stream.WriteByte((byte)251);
        }

        /// <summary>Emits a 'cld' instruction.</summary>
        public static void Cld(this Stream stream)
        {
            stream.WriteByte((byte)252);
        }

        /// <summary>Emits a 'std' instruction.</summary>
        public static void Std(this Stream stream)
        {
            stream.WriteByte((byte)253);
        }

        /// <summary>Emits a 'jo' instruction.</summary>
        public static void Jo(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)112);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jno' instruction.</summary>
        public static void Jno(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)113);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jb' instruction.</summary>
        public static void Jb(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)114);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnae' instruction.</summary>
        public static void Jnae(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)114);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jc' instruction.</summary>
        public static void Jc(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)114);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnb' instruction.</summary>
        public static void Jnb(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)115);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jae' instruction.</summary>
        public static void Jae(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)115);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnc' instruction.</summary>
        public static void Jnc(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)115);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jz' instruction.</summary>
        public static void Jz(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)116);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'je' instruction.</summary>
        public static void Je(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)116);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnz' instruction.</summary>
        public static void Jnz(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)117);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jne' instruction.</summary>
        public static void Jne(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)117);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jbe' instruction.</summary>
        public static void Jbe(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)118);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jna' instruction.</summary>
        public static void Jna(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)118);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnbe' instruction.</summary>
        public static void Jnbe(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)119);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'ja' instruction.</summary>
        public static void Ja(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)119);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'js' instruction.</summary>
        public static void Js(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)120);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jns' instruction.</summary>
        public static void Jns(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)121);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jp' instruction.</summary>
        public static void Jp(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)122);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jpe' instruction.</summary>
        public static void Jpe(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)122);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnp' instruction.</summary>
        public static void Jnp(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)123);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jpo' instruction.</summary>
        public static void Jpo(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)123);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jl' instruction.</summary>
        public static void Jl(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)124);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnge' instruction.</summary>
        public static void Jnge(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)124);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnl' instruction.</summary>
        public static void Jnl(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)125);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jge' instruction.</summary>
        public static void Jge(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)125);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jle' instruction.</summary>
        public static void Jle(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)126);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jng' instruction.</summary>
        public static void Jng(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)126);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnle' instruction.</summary>
        public static void Jnle(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)127);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jg' instruction.</summary>
        public static void Jg(this Stream stream, sbyte operand)
        {
            stream.WriteByte((byte)127);
            stream.WriteByte((sbyte)operand);
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void Inc(this Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)64 + (byte)operand));
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void Inc(this Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)64 + (byte)operand));
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void Dec(this Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)72 + (byte)operand));
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void Dec(this Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)72 + (byte)operand));
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void Push(this Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)80 + (byte)operand));
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void Push(this Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)80 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void Pop(this Stream stream, Register16 operand)
        {
            stream.WriteByte(((byte)102 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void Pop(this Stream stream, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                stream.WriteByte((byte)65);
            }
            stream.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void Pop(this Stream stream, Register64 operand)
        {
            stream.WriteByte(((byte)72 + get_prefix((byte)operand)));
            stream.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register8 reg, sbyte value)
        {
            stream.WriteByte((byte)128);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register16 reg, short value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register16 reg, int value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register32 reg, short value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register32 reg, int value)
        {
            stream.WriteByte((byte)129);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)0));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)1));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)2));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)3));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)4));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)5));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)6));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register16 reg, sbyte value)
        {
            stream.WriteByte((byte)102);
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this Stream stream, Register32 reg, sbyte value)
        {
            stream.WriteByte((byte)131);
            stream.WriteByte(((byte)reg + (byte)7));
            stream.WriteByte((sbyte)value);
        }

    }
}
