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

        public static readonly AL = 0;
        public static readonly CL = 1;
        public static readonly DL = 2;
        public static readonly BL = 3;
        public static readonly SPL = 4;
        public static readonly BPL = 5;
        public static readonly SIL = 6;
        public static readonly DIL = 7;
        public static readonly R8B = 8;
        public static readonly R9B = 9;
        public static readonly R10B = 10;
        public static readonly R11B = 11;
        public static readonly R12B = 12;
        public static readonly R13B = 13;
        public static readonly R14B = 14;
        public static readonly R15B = 15;
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

        public static readonly AX = 0;
        public static readonly CX = 1;
        public static readonly DX = 2;
        public static readonly BX = 3;
        public static readonly SP = 4;
        public static readonly BP = 5;
        public static readonly SI = 6;
        public static readonly DI = 7;
        public static readonly R8W = 8;
        public static readonly R9W = 9;
        public static readonly R10W = 10;
        public static readonly R11W = 11;
        public static readonly R12W = 12;
        public static readonly R13W = 13;
        public static readonly R14W = 14;
        public static readonly R15W = 15;
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

        public static readonly EAX = 0;
        public static readonly ECX = 1;
        public static readonly EDX = 2;
        public static readonly EBX = 3;
        public static readonly ESP = 4;
        public static readonly EBP = 5;
        public static readonly ESI = 6;
        public static readonly EDI = 7;
        public static readonly R8D = 8;
        public static readonly R9D = 9;
        public static readonly R10D = 10;
        public static readonly R11D = 11;
        public static readonly R12D = 12;
        public static readonly R13D = 13;
        public static readonly R14D = 14;
        public static readonly R15D = 15;
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

        public static readonly RAX = 0;
        public static readonly RCX = 1;
        public static readonly RDX = 2;
        public static readonly RBX = 3;
        public static readonly RSP = 4;
        public static readonly RBP = 5;
        public static readonly RSI = 6;
        public static readonly RDI = 7;
        public static readonly R8 = 8;
        public static readonly R9 = 9;
        public static readonly R10 = 10;
        public static readonly R11 = 11;
        public static readonly R12 = 12;
        public static readonly R13 = 13;
        public static readonly R14 = 14;
        public static readonly R15 = 15;
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
