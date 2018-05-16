using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{
    partial class X86
    {
        /// <summary>Emits an <c>inc</c> instruction.</summary>
        public static byte inc(Register16 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf + offset) = 0x40 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits an <c>inc</c> instruction.</summary>
        public static byte inc(Register32 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf + offset) = 0x40 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>dec</c> instruction.</summary>
        public static byte dec(Register16 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf + offset) = 0x48 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>dec</c> instruction.</summary>
        public static byte dec(Register32 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf + offset) = 0x48 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>push</c> instruction.</summary>
        public static byte push(Register16 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf + offset) = 0x50 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>push</c> instruction.</summary>
        public static byte push(Register32 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf + offset) = 0x50 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static byte pop(Register16 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            *(byte*)(*buf) = 0x66 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf + offset) = 0x58 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static byte pop(Register32 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            if ((operand > 7))
            {
                *(byte*)(*buf) = 65;
                *(byte*)buf += 1;
            }
            *(byte*)(*buf + offset) = 0x58 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>pop</c> instruction.</summary>
        public static byte pop(Register64 operand, ref IntPtr buffer)
        {
            sbyte offset = 0;
            *(byte*)(*buf) = 0x48 + prefix_adder(operand);
            *(byte*)buf += 1;
            *(byte*)(*buf + offset) = 0x58 + operand;
            *(byte*)buf += 1;
            return offset;
        }

        /// <summary>Emits a <c>pushf</c> instruction.</summary>
        public static byte pushf(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 156;
            *(byte*)buf += 1;
            return 1;
        }

        /// <summary>Emits a <c>popf</c> instruction.</summary>
        public static byte popf(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 157;
            *(byte*)buf += 1;
            return 1;
        }

        /// <summary>Emits a <c>ret</c> instruction.</summary>
        public static byte ret(ref IntPtr buffer)
        {
            *(byte*)(*buf) = 195;
            *(byte*)buf += 1;
            return 1;
        }


    }
}
