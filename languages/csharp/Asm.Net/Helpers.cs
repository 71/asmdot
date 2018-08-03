using System;
using System.Runtime.CompilerServices;

#if USE_BUFFERS
using OutputBuffer = System.Buffers.IBufferWriter<byte>;
#else
using OutputBuffer = System.IO.Stream;
#endif

namespace Asm.Net
{
    /// <summary>
    ///   Defines statuc helpers used by the assemblers.
    /// </summary>
    internal static class Helpers
    {
#if USE_BUFFERS
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteByte(this OutputBuffer buffer, byte b)
        {
            buffer.GetSpan(1)[0] = b;
            buffer.Advance(1);
        }
#else
        [ThreadStatic]
        private static byte[] threadTmpBuffer;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] GetTempBuffer() => threadTmpBuffer ?? (threadTmpBuffer = new byte[16]);
#endif


#if BIGENDIAN

#region BE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, short i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, int i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, long i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            tmpBuffer[4] = (byte)(i >> 32);
            tmpBuffer[5] = (byte)(i >> 40);
            tmpBuffer[6] = (byte)(i >> 48);
            tmpBuffer[7] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, ushort i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, uint i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, ulong i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            tmpBuffer[4] = (byte)(i >> 32);
            tmpBuffer[5] = (byte)(i >> 40);
            tmpBuffer[6] = (byte)(i >> 48);
            tmpBuffer[7] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }
#endregion

#region LE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, short i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[1] = (byte)(i);
            tmpBuffer[0] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, int i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[3] = (byte)(i);
            tmpBuffer[2] = (byte)(i >> 8);
            tmpBuffer[1] = (byte)(i >> 16);
            tmpBuffer[0] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, long i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[7] = (byte)(i);
            tmpBuffer[6] = (byte)(i >> 8);
            tmpBuffer[5] = (byte)(i >> 16);
            tmpBuffer[4] = (byte)(i >> 24);
            tmpBuffer[3] = (byte)(i >> 32);
            tmpBuffer[2] = (byte)(i >> 40);
            tmpBuffer[1] = (byte)(i >> 48);
            tmpBuffer[0] = (byte)(i >> 56);

#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, ushort i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[1] = (byte)(i);
            tmpBuffer[0] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, uint i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[3] = (byte)(i);
            tmpBuffer[2] = (byte)(i >> 8);
            tmpBuffer[1] = (byte)(i >> 16);
            tmpBuffer[0] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, ulong i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[7] = (byte)(i);
            tmpBuffer[6] = (byte)(i >> 8);
            tmpBuffer[5] = (byte)(i >> 16);
            tmpBuffer[4] = (byte)(i >> 24);
            tmpBuffer[3] = (byte)(i >> 32);
            tmpBuffer[2] = (byte)(i >> 40);
            tmpBuffer[1] = (byte)(i >> 48);
            tmpBuffer[0] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }
#endregion

#else

#region BE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, short i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, int i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, long i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            tmpBuffer[4] = (byte)(i >> 32);
            tmpBuffer[5] = (byte)(i >> 40);
            tmpBuffer[6] = (byte)(i >> 48);
            tmpBuffer[7] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, ushort i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, uint i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteLE(this OutputBuffer buffer, ulong i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[0] = (byte)(i);
            tmpBuffer[1] = (byte)(i >> 8);
            tmpBuffer[2] = (byte)(i >> 16);
            tmpBuffer[3] = (byte)(i >> 24);
            tmpBuffer[4] = (byte)(i >> 32);
            tmpBuffer[5] = (byte)(i >> 40);
            tmpBuffer[6] = (byte)(i >> 48);
            tmpBuffer[7] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }
#endregion

#region LE
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, short i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[1] = (byte)(i);
            tmpBuffer[0] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, int i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[3] = (byte)(i);
            tmpBuffer[2] = (byte)(i >> 8);
            tmpBuffer[1] = (byte)(i >> 16);
            tmpBuffer[0] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, long i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[7] = (byte)(i);
            tmpBuffer[6] = (byte)(i >> 8);
            tmpBuffer[5] = (byte)(i >> 16);
            tmpBuffer[4] = (byte)(i >> 24);
            tmpBuffer[3] = (byte)(i >> 32);
            tmpBuffer[2] = (byte)(i >> 40);
            tmpBuffer[1] = (byte)(i >> 48);
            tmpBuffer[0] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, ushort i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(2);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[1] = (byte)(i);
            tmpBuffer[0] = (byte)(i >> 8);

#if USE_BUFFERS
            buffer.Advance(2);
#else
            buffer.Write(tmpBuffer, 0, 2);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, uint i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(4);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[3] = (byte)(i);
            tmpBuffer[2] = (byte)(i >> 8);
            tmpBuffer[1] = (byte)(i >> 16);
            tmpBuffer[0] = (byte)(i >> 24);
            
#if USE_BUFFERS
            buffer.Advance(4);
#else
            buffer.Write(tmpBuffer, 0, 4);
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBE(this OutputBuffer buffer, ulong i)
        {
#if USE_BUFFERS
            Span<byte> tmpBuffer = buffer.GetSpan(8);
#else   
            byte[] tmpBuffer = GetTempBuffer();
#endif

            tmpBuffer[7] = (byte)(i);
            tmpBuffer[6] = (byte)(i >> 8);
            tmpBuffer[5] = (byte)(i >> 16);
            tmpBuffer[4] = (byte)(i >> 24);
            tmpBuffer[3] = (byte)(i >> 32);
            tmpBuffer[2] = (byte)(i >> 40);
            tmpBuffer[1] = (byte)(i >> 48);
            tmpBuffer[0] = (byte)(i >> 56);
            
#if USE_BUFFERS
            buffer.Advance(8);
#else
            buffer.Write(tmpBuffer, 0, 8);
#endif
        }
#endregion

#endif


#region Helpers
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteByte(this OutputBuffer buffer, sbyte value)
            => buffer.WriteByte((byte)value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteByte(this OutputBuffer buffer, int value)
            => buffer.WriteByte((byte)value);
#endregion
    }
}
