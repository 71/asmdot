using System;
using System.Runtime.InteropServices;

namespace AsmSq
{
    public static class X86
    {
        public const string LIBNAME = "asmdot";
          [DllImport(LIBNAME, EntryPoint = "inc_r16", CallingConvention = CallingConvention.Cdecl)]
          public static int inc(Register16 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "inc_r32", CallingConvention = CallingConvention.Cdecl)]
          public static int inc(Register32 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "dec_r16", CallingConvention = CallingConvention.Cdecl)]
          public static int dec(Register16 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "dec_r32", CallingConvention = CallingConvention.Cdecl)]
          public static int dec(Register32 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "push_r16", CallingConvention = CallingConvention.Cdecl)]
          public static int push(Register16 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "push_r32", CallingConvention = CallingConvention.Cdecl)]
          public static int push(Register32 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pop_r16", CallingConvention = CallingConvention.Cdecl)]
          public static int pop(Register16 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pop_r32", CallingConvention = CallingConvention.Cdecl)]
          public static int pop(Register32 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pop_r64", CallingConvention = CallingConvention.Cdecl)]
          public static int pop(Register64 operand, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pushf", CallingConvention = CallingConvention.Cdecl)]
          public static int pushf(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "popf", CallingConvention = CallingConvention.Cdecl)]
          public static int popf(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ret", CallingConvention = CallingConvention.Cdecl)]
          public static int ret(IntPtr buffer)
;

    }
}
