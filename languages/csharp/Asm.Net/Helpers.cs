using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace Asm.Net
{
    /// <summary>
    ///   Defines statuc helpers used by the assemblers.
    /// </summary>
    internal static class Helpers
    {
        [ThreadStatic]
        private static byte[] tmpBuffer;
        private static byte[] GetTempBuffer() => tmpBuffer ?? (tmpBuffer = new byte[16]);

#if BIGENDIAN

#region BE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, short i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, int i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, long i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            buffer[4] = (byte)(i >> 32);
            buffer[5] = (byte)(i >> 40);
            buffer[6] = (byte)(i >> 48);
            buffer[7] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, ushort i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, uint i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, ulong i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            buffer[4] = (byte)(i >> 32);
            buffer[5] = (byte)(i >> 40);
            buffer[6] = (byte)(i >> 48);
            buffer[7] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }
#endregion

#region LE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, short i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[1] = (byte)(i);
            buffer[0] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, int i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[3] = (byte)(i);
            buffer[2] = (byte)(i >> 8);
            buffer[1] = (byte)(i >> 16);
            buffer[0] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, long i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[7] = (byte)(i);
            buffer[6] = (byte)(i >> 8);
            buffer[5] = (byte)(i >> 16);
            buffer[4] = (byte)(i >> 24);
            buffer[3] = (byte)(i >> 32);
            buffer[2] = (byte)(i >> 40);
            buffer[1] = (byte)(i >> 48);
            buffer[0] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, ushort i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[1] = (byte)(i);
            buffer[0] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, uint i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[3] = (byte)(i);
            buffer[2] = (byte)(i >> 8);
            buffer[1] = (byte)(i >> 16);
            buffer[0] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, ulong i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[7] = (byte)(i);
            buffer[6] = (byte)(i >> 8);
            buffer[5] = (byte)(i >> 16);
            buffer[4] = (byte)(i >> 24);
            buffer[3] = (byte)(i >> 32);
            buffer[2] = (byte)(i >> 40);
            buffer[1] = (byte)(i >> 48);
            buffer[0] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }
#endregion

#else

#region BE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, short i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, int i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, long i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            buffer[4] = (byte)(i >> 32);
            buffer[5] = (byte)(i >> 40);
            buffer[6] = (byte)(i >> 48);
            buffer[7] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, ushort i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, uint i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this Stream stream, ulong i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[0] = (byte)(i);
            buffer[1] = (byte)(i >> 8);
            buffer[2] = (byte)(i >> 16);
            buffer[3] = (byte)(i >> 24);
            buffer[4] = (byte)(i >> 32);
            buffer[5] = (byte)(i >> 40);
            buffer[6] = (byte)(i >> 48);
            buffer[7] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }
#endregion

#region LE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, short i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[1] = (byte)(i);
            buffer[0] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, int i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[3] = (byte)(i);
            buffer[2] = (byte)(i >> 8);
            buffer[1] = (byte)(i >> 16);
            buffer[0] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, long i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[7] = (byte)(i);
            buffer[6] = (byte)(i >> 8);
            buffer[5] = (byte)(i >> 16);
            buffer[4] = (byte)(i >> 24);
            buffer[3] = (byte)(i >> 32);
            buffer[2] = (byte)(i >> 40);
            buffer[1] = (byte)(i >> 48);
            buffer[0] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, ushort i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[1] = (byte)(i);
            buffer[0] = (byte)(i >> 8);

            stream.Write(buffer, 0, 2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, uint i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[3] = (byte)(i);
            buffer[2] = (byte)(i >> 8);
            buffer[1] = (byte)(i >> 16);
            buffer[0] = (byte)(i >> 24);
            
            stream.Write(buffer, 0, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this Stream stream, ulong i)
        {
            byte[] buffer = GetTempBuffer();

            buffer[7] = (byte)(i);
            buffer[6] = (byte)(i >> 8);
            buffer[5] = (byte)(i >> 16);
            buffer[4] = (byte)(i >> 24);
            buffer[3] = (byte)(i >> 32);
            buffer[2] = (byte)(i >> 40);
            buffer[1] = (byte)(i >> 48);
            buffer[0] = (byte)(i >> 56);
            
            stream.Write(buffer, 0, 8);
        }
#endregion

#endif
    }
}
