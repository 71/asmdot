using System;
using System.Runtime.InteropServices;

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
        public static explicit operator Register8(byte value) => new Register8 { Value = value };
    }

    /// <summary>An x86 16-bits register.</summary>
    public struct Register16
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register16 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register16(byte value) => new Register16 { Value = value };
    }

    /// <summary>An x86 32-bits register.</summary>
    public struct Register32
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register32 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register32(byte value) => new Register32 { Value = value };
    }

    /// <summary>An x86 64-bits register.</summary>
    public struct Register64
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register64 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register64(byte value) => new Register64 { Value = value };
    }

    /// <summary>An x86 128-bits register.</summary>
    public struct Register128
    {
        /// <summary>Underlying value.</summary>
        public readonly byte Value;

        /// <summary>Converts the wrapper to its underlying value.</summary>
        public static explicit operator byte(Register128 wrapper) => wrapper.Value;

        /// <summary>Wraps the given underlying value.</summary>
        public static explicit operator Register128(byte value) => new Register128 { Value = value };
    }

    partial class X86
    {
        /// <summary>Emits an 'inc' instruction.</summary>
        public static void inc(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(byte*)(*buf) = (64 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits an 'inc' instruction.</summary>
        public static void inc(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = (64 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void dec(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(byte*)(*buf) = (72 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'dec' instruction.</summary>
        public static void dec(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = (72 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void push(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(byte*)(*buf) = (80 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'push' instruction.</summary>
        public static void push(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = (80 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void pop(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(byte*)(*buf) = (88 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void pop(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = (88 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'pop' instruction.</summary>
        public static void pop(ref IntPtr buffer, Register64 operand)
        {
            *(byte*)(*buf) = (72 + get_prefix(operand));
            *(byte*)buf += 1;
            *(byte*)(*buf) = (88 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'pushf' instruction.</summary>
        public static void pushf(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 156;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'popf' instruction.</summary>
        public static void popf(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 157;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a 'ret' instruction.</summary>
        public static void ret(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 195;
            *(byte*)buf += 1;
        }


    }
}
