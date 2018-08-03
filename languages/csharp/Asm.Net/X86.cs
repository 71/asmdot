namespace Asm.Net.X86
{
    /// <summary>
    ///   Defines methods for emitting x86 instructions.
    /// </summary>
    public static partial class X86
    {
        private static byte GetPrefix(ref Register16 r)
        {
            if (r.Value < 8)
                return r.Value;
            
            r = new Register16((byte)(r.Value - 8));
            return 1;
        }

        private static byte GetPrefix(ref Register32 r)
        {
            if (r.Value < 8)
                return r.Value;
            
            r = new Register32((byte)(r.Value - 8));
            return 1;
        }
        
        private static byte GetPrefix(ref Register64 r)
        {
            if (r.Value < 8)
                return r.Value;
            
            r = new Register64((byte)(r.Value - 8));
            return 1;
        }
    }
}
