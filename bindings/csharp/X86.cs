using System;
using System.Runtime.InteropServices;

namespace AsmSq
{
    public static class X86
    {
        [DllImport("asmsq", EntryPoint = "ret", CallingConvention = CallingConvention.Cdecl)]
        public static int ret(ref IntPtr buf);

    }
}
