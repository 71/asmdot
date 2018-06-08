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

    }
}
