#if USE_BUFFERS
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace Asm.Net.Tests
{
    internal sealed class BufferWriter : IBufferWriter<byte>
    {
        private byte[] storage;
        private int index;

        public int Position
        {
            get => index;
            set => index = value; // Not checked, we only except 0 to be given.
        }

        public BufferWriter(int capacity = 16)
        {
            storage = new byte[capacity];
            index = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count) => index += count;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            // Note: this method is never used anyway, but would most likely
            //       perform worse.
            int needed = sizeHint > 0 ? index + sizeHint : index + 16;

            if (needed > storage.Length)
                Array.Resize(ref storage, needed);

            return new Memory<byte>(storage, index, storage.Length - index);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Span<byte> GetSpan(int sizeHint = 0)
        {
            int needed = sizeHint > 0 ? index + sizeHint : index + 16;

            if (needed > storage.Length)
                Array.Resize(ref storage, needed);
            
            return new Span<byte>(storage, index, storage.Length - index);
        }

        public byte[] ToArray()
        {
            byte[] result = new byte[index];

            Array.Copy(storage, result, index);

            return result;
        }
    }
}
#endif
