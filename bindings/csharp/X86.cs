using System;
using System.Runtime.InteropServices;

namespace AsmSq
{
    public static class X86
    {
        [DllImport("asmsq", EntryPoint = "inc_r16", CallingConvention = CallingConvention.Cdecl)]
        public static int inc(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "inc_r32", CallingConvention = CallingConvention.Cdecl)]
        public static int inc(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "dec_r16", CallingConvention = CallingConvention.Cdecl)]
        public static int dec(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "dec_r32", CallingConvention = CallingConvention.Cdecl)]
        public static int dec(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "push_r16", CallingConvention = CallingConvention.Cdecl)]
        public static int push(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "push_r32", CallingConvention = CallingConvention.Cdecl)]
        public static int push(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pop_r16", CallingConvention = CallingConvention.Cdecl)]
        public static int pop(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pop_r32", CallingConvention = CallingConvention.Cdecl)]
        public static int pop(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pop_r64", CallingConvention = CallingConvention.Cdecl)]
        public static int pop(reg operand, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pushf", CallingConvention = CallingConvention.Cdecl)]
        public static int pushf(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "popf", CallingConvention = CallingConvention.Cdecl)]
        public static int popf(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ret", CallingConvention = CallingConvention.Cdecl)]
        public static int ret(ref IntPtr buf);

    }
}
