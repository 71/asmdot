using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{
    partial class X86
    {
        /// <summary>Emits an <c>inc</c> instruction.</summary>
        public static void inc(ref IntPtr buffer, Reg16 operand)
        {
            *(usbyte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(usbyte*)(*buf) = (64 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits an <c>inc</c> instruction.</summary>
        public static void inc(ref IntPtr buffer, Reg32 operand)
        {
            if ((operand > 7))
            {
                *(usbyte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(usbyte*)(*buf) = (64 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>dec</c> instruction.</summary>
        public static void dec(ref IntPtr buffer, Reg16 operand)
        {
            *(usbyte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(usbyte*)(*buf) = (72 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>dec</c> instruction.</summary>
        public static void dec(ref IntPtr buffer, Reg32 operand)
        {
            if ((operand > 7))
            {
                *(usbyte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(usbyte*)(*buf) = (72 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>push</c> instruction.</summary>
        public static void push(ref IntPtr buffer, Reg16 operand)
        {
            *(usbyte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(usbyte*)(*buf) = (80 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>push</c> instruction.</summary>
        public static void push(ref IntPtr buffer, Reg32 operand)
        {
            if ((operand > 7))
            {
                *(usbyte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(usbyte*)(*buf) = (80 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static void pop(ref IntPtr buffer, Reg16 operand)
        {
            *(usbyte*)(*buf) = (102 + get_prefix(operand));
            *(byte*)buf += 1;
            *(usbyte*)(*buf) = (88 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static void pop(ref IntPtr buffer, Reg32 operand)
        {
            if ((operand > 7))
            {
                *(usbyte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(usbyte*)(*buf) = (88 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static void pop(ref IntPtr buffer, Reg64 operand)
        {
            *(usbyte*)(*buf) = (72 + get_prefix(operand));
            *(byte*)buf += 1;
            *(usbyte*)(*buf) = (88 + operand);
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>pushf</c> instruction.</summary>
        public static void pushf(ref IntPtr buffer)
        {
            *(usbyte*)(*buf) = 156;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>popf</c> instruction.</summary>
        public static void popf(ref IntPtr buffer)
        {
            *(usbyte*)(*buf) = 157;
            *(byte*)buf += 1;
        }

        /// <summary>Emits a <c>ret</c> instruction.</summary>
        public static void ret(ref IntPtr buffer)
        {
            *(usbyte*)(*buf) = 195;
            *(byte*)buf += 1;
        }


    }
}
