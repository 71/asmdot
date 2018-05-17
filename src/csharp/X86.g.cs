using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{
    partial class X86
    {
        /// <summary>Emits an <c>inc</c> instruction.</summary>
        public static void inc(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf) = 0x40 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits an <c>inc</c> instruction.</summary>
        public static void inc(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = 0x40 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>dec</c> instruction.</summary>
        public static void dec(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf) = 0x48 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>dec</c> instruction.</summary>
        public static void dec(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = 0x48 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>push</c> instruction.</summary>
        public static void push(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf) = 0x50 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>push</c> instruction.</summary>
        public static void push(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = 0x50 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static void pop(ref IntPtr buffer, Register16 operand)
        {
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf) = 0x58 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static void pop(ref IntPtr buffer, Register32 operand)
        {
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf) = 0x58 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static void pop(ref IntPtr buffer, Register64 operand)
        {
            *(byte*)(*buf) = 0x48 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf) = 0x58 + operand;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pushf</c> instruction.</summary>
        public static void pushf(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 156;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>popf</c> instruction.</summary>
        public static void popf(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 157;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>ret</c> instruction.</summary>
        public static void ret(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 195;
            *(byte*)buf += 1;
        }


    }
}
