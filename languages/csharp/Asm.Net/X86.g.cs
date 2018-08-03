using System;
using System.Diagnostics;

#if USE_BUFFERS
using OutputBuffer = System.Buffers.IBufferWriter<byte>;
#else
using OutputBuffer = System.IO.Stream;
#endif

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
        public static void Pushf(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)156);
        }

        /// <summary>Emits a 'popf' instruction.</summary>
        public static void Popf(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)157);
        }

        /// <summary>Emits a 'ret' instruction.</summary>
        public static void Ret(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)195);
        }

        /// <summary>Emits a 'clc' instruction.</summary>
        public static void Clc(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)248);
        }

        /// <summary>Emits a 'stc' instruction.</summary>
        public static void Stc(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)249);
        }

        /// <summary>Emits a 'cli' instruction.</summary>
        public static void Cli(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)250);
        }

        /// <summary>Emits a 'sti' instruction.</summary>
        public static void Sti(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)251);
        }

        /// <summary>Emits a 'cld' instruction.</summary>
        public static void Cld(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)252);
        }

        /// <summary>Emits a 'std' instruction.</summary>
        public static void Std(this OutputBuffer buffer)
        {
            buffer.WriteByte((byte)253);
        }

        /// <summary>Emits a 'jo' instruction.</summary>
        public static void Jo(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)112);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jno' instruction.</summary>
        public static void Jno(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)113);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jb' instruction.</summary>
        public static void Jb(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)114);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnae' instruction.</summary>
        public static void Jnae(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)114);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jc' instruction.</summary>
        public static void Jc(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)114);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnb' instruction.</summary>
        public static void Jnb(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)115);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jae' instruction.</summary>
        public static void Jae(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)115);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnc' instruction.</summary>
        public static void Jnc(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)115);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jz' instruction.</summary>
        public static void Jz(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)116);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'je' instruction.</summary>
        public static void Je(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)116);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnz' instruction.</summary>
        public static void Jnz(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)117);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jne' instruction.</summary>
        public static void Jne(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)117);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jbe' instruction.</summary>
        public static void Jbe(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)118);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jna' instruction.</summary>
        public static void Jna(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)118);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnbe' instruction.</summary>
        public static void Jnbe(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)119);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'ja' instruction.</summary>
        public static void Ja(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)119);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'js' instruction.</summary>
        public static void Js(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)120);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jns' instruction.</summary>
        public static void Jns(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)121);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jp' instruction.</summary>
        public static void Jp(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)122);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jpe' instruction.</summary>
        public static void Jpe(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)122);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnp' instruction.</summary>
        public static void Jnp(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)123);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jpo' instruction.</summary>
        public static void Jpo(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)123);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jl' instruction.</summary>
        public static void Jl(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)124);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnge' instruction.</summary>
        public static void Jnge(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)124);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnl' instruction.</summary>
        public static void Jnl(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)125);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jge' instruction.</summary>
        public static void Jge(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)125);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jle' instruction.</summary>
        public static void Jle(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)126);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jng' instruction.</summary>
        public static void Jng(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)126);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jnle' instruction.</summary>
        public static void Jnle(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)127);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits a 'jg' instruction.</summary>
        public static void Jg(this OutputBuffer buffer, sbyte operand)
        {
            buffer.WriteByte((byte)127);
            buffer.WriteByte((sbyte)operand);
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void Inc(this OutputBuffer buffer, Register16 operand)
        {
            buffer.WriteByte(((byte)102 + GetPrefix(ref operand)));
            buffer.WriteByte(((byte)64 + (byte)operand));
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void Inc(this OutputBuffer buffer, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                buffer.WriteByte((byte)65);
            }
            buffer.WriteByte(((byte)64 + (byte)operand));
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void Dec(this OutputBuffer buffer, Register16 operand)
        {
            buffer.WriteByte(((byte)102 + GetPrefix(ref operand)));
            buffer.WriteByte(((byte)72 + (byte)operand));
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void Dec(this OutputBuffer buffer, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                buffer.WriteByte((byte)65);
            }
            buffer.WriteByte(((byte)72 + (byte)operand));
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void Push(this OutputBuffer buffer, Register16 operand)
        {
            buffer.WriteByte(((byte)102 + GetPrefix(ref operand)));
            buffer.WriteByte(((byte)80 + (byte)operand));
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void Push(this OutputBuffer buffer, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                buffer.WriteByte((byte)65);
            }
            buffer.WriteByte(((byte)80 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void Pop(this OutputBuffer buffer, Register16 operand)
        {
            buffer.WriteByte(((byte)102 + GetPrefix(ref operand)));
            buffer.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void Pop(this OutputBuffer buffer, Register32 operand)
        {
            if (((byte)operand > (byte)7))
            {
                buffer.WriteByte((byte)65);
            }
            buffer.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void Pop(this OutputBuffer buffer, Register64 operand)
        {
            buffer.WriteByte(((byte)72 + GetPrefix(ref operand)));
            buffer.WriteByte(((byte)88 + (byte)operand));
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register8 reg, sbyte value)
        {
            buffer.WriteByte((byte)128);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register16 reg, short value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register16 reg, int value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register32 reg, short value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteLE((short)(short)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register32 reg, int value)
        {
            buffer.WriteByte((byte)129);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteLE((int)(int)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'add' instruction.</summary>
        public static void Add(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)0));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'or' instruction.</summary>
        public static void Or(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)1));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'adc' instruction.</summary>
        public static void Adc(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)2));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sbb' instruction.</summary>
        public static void Sbb(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)3));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits an 'and' instruction.</summary>
        public static void And(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)4));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'sub' instruction.</summary>
        public static void Sub(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)5));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'xor' instruction.</summary>
        public static void Xor(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)6));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register16 reg, sbyte value)
        {
            buffer.WriteByte((byte)102);
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Emits a 'cmp' instruction.</summary>
        public static void Cmp(this OutputBuffer buffer, Register32 reg, sbyte value)
        {
            buffer.WriteByte((byte)131);
            buffer.WriteByte(((byte)reg + (byte)7));
            buffer.WriteByte((sbyte)value);
        }

        /// <summary>Assembles an instruction, given its opcode and operands.</summary>
        public static bool Assemble(this OutputBuffer buffer, string opcode, params object[] operands)
        {
            switch (opcode)
            {
                case "adc":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Adc(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Adc(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Adc(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Adc(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Adc(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Adc(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Adc(reg, value); return true; }
                }

                return false;
                case "add":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Add(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Add(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Add(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Add(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Add(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Add(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Add(reg, value); return true; }
                }

                return false;
                case "and":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.And(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.And(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.And(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.And(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.And(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.And(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.And(reg, value); return true; }
                }

                return false;
                case "clc":
                {
                    if (operands.Length == 0) { buffer.Clc(); return true; }
                }

                return false;
                case "cld":
                {
                    if (operands.Length == 0) { buffer.Cld(); return true; }
                }

                return false;
                case "cli":
                {
                    if (operands.Length == 0) { buffer.Cli(); return true; }
                }

                return false;
                case "cmp":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Cmp(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Cmp(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Cmp(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Cmp(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Cmp(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Cmp(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Cmp(reg, value); return true; }
                }

                return false;
                case "dec":
                {
                    if (operands.Length == 1 && operands[0] is Register16 operand) { buffer.Dec(operand); return true; }
                }
                {
                    if (operands.Length == 1 && operands[0] is Register32 operand) { buffer.Dec(operand); return true; }
                }

                return false;
                case "inc":
                {
                    if (operands.Length == 1 && operands[0] is Register16 operand) { buffer.Inc(operand); return true; }
                }
                {
                    if (operands.Length == 1 && operands[0] is Register32 operand) { buffer.Inc(operand); return true; }
                }

                return false;
                case "ja":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Ja(operand); return true; }
                }

                return false;
                case "jae":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jae(operand); return true; }
                }

                return false;
                case "jb":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jb(operand); return true; }
                }

                return false;
                case "jbe":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jbe(operand); return true; }
                }

                return false;
                case "jc":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jc(operand); return true; }
                }

                return false;
                case "je":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Je(operand); return true; }
                }

                return false;
                case "jg":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jg(operand); return true; }
                }

                return false;
                case "jge":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jge(operand); return true; }
                }

                return false;
                case "jl":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jl(operand); return true; }
                }

                return false;
                case "jle":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jle(operand); return true; }
                }

                return false;
                case "jna":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jna(operand); return true; }
                }

                return false;
                case "jnae":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnae(operand); return true; }
                }

                return false;
                case "jnb":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnb(operand); return true; }
                }

                return false;
                case "jnbe":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnbe(operand); return true; }
                }

                return false;
                case "jnc":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnc(operand); return true; }
                }

                return false;
                case "jne":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jne(operand); return true; }
                }

                return false;
                case "jng":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jng(operand); return true; }
                }

                return false;
                case "jnge":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnge(operand); return true; }
                }

                return false;
                case "jnl":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnl(operand); return true; }
                }

                return false;
                case "jnle":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnle(operand); return true; }
                }

                return false;
                case "jno":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jno(operand); return true; }
                }

                return false;
                case "jnp":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnp(operand); return true; }
                }

                return false;
                case "jns":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jns(operand); return true; }
                }

                return false;
                case "jnz":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jnz(operand); return true; }
                }

                return false;
                case "jo":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jo(operand); return true; }
                }

                return false;
                case "jp":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jp(operand); return true; }
                }

                return false;
                case "jpe":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jpe(operand); return true; }
                }

                return false;
                case "jpo":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jpo(operand); return true; }
                }

                return false;
                case "js":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Js(operand); return true; }
                }

                return false;
                case "jz":
                {
                    if (operands.Length == 1 && operands[0] is sbyte operand) { buffer.Jz(operand); return true; }
                }

                return false;
                case "or":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Or(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Or(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Or(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Or(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Or(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Or(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Or(reg, value); return true; }
                }

                return false;
                case "pop":
                {
                    if (operands.Length == 1 && operands[0] is Register16 operand) { buffer.Pop(operand); return true; }
                }
                {
                    if (operands.Length == 1 && operands[0] is Register32 operand) { buffer.Pop(operand); return true; }
                }
                {
                    if (operands.Length == 1 && operands[0] is Register64 operand) { buffer.Pop(operand); return true; }
                }

                return false;
                case "popf":
                {
                    if (operands.Length == 0) { buffer.Popf(); return true; }
                }

                return false;
                case "push":
                {
                    if (operands.Length == 1 && operands[0] is Register16 operand) { buffer.Push(operand); return true; }
                }
                {
                    if (operands.Length == 1 && operands[0] is Register32 operand) { buffer.Push(operand); return true; }
                }

                return false;
                case "pushf":
                {
                    if (operands.Length == 0) { buffer.Pushf(); return true; }
                }

                return false;
                case "ret":
                {
                    if (operands.Length == 0) { buffer.Ret(); return true; }
                }

                return false;
                case "sbb":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Sbb(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Sbb(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Sbb(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Sbb(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Sbb(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Sbb(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Sbb(reg, value); return true; }
                }

                return false;
                case "stc":
                {
                    if (operands.Length == 0) { buffer.Stc(); return true; }
                }

                return false;
                case "std":
                {
                    if (operands.Length == 0) { buffer.Std(); return true; }
                }

                return false;
                case "sti":
                {
                    if (operands.Length == 0) { buffer.Sti(); return true; }
                }

                return false;
                case "sub":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Sub(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Sub(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Sub(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Sub(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Sub(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Sub(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Sub(reg, value); return true; }
                }

                return false;
                case "xor":
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is short value) { buffer.Xor(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is int value) { buffer.Xor(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register16 reg && operands[1] is sbyte value) { buffer.Xor(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is short value) { buffer.Xor(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is int value) { buffer.Xor(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register32 reg && operands[1] is sbyte value) { buffer.Xor(reg, value); return true; }
                }
                {
                    if (operands.Length == 2 && operands[0] is Register8 reg && operands[1] is sbyte value) { buffer.Xor(reg, value); return true; }
                }

                return false;
            }
            return false;
        }
    }
}
