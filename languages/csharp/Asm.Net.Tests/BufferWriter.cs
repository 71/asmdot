#if USE_BUFFERS
using System;
using System.Buffers;

namespace Asm.Net.Tests
{
    internal sealed class BufferWriter : IBufferWriter<byte>
    {
        private byte[] storage = new byte[16];
        private int index = 0;

        public void Advance(int count) => index += count;

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            int needed = sizeHint > 0 ? index + sizeHint : index + 16;

            if (needed > storage.Length)
                Array.Resize(ref storage, needed);

            return new Memory<byte>(storage, index, storage.Length - index);
        }

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
