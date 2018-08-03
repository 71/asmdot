#if !USE_BUFFERS
using System.IO;
#endif
using NUnit.Framework;
using Asm.Net.X86;

namespace Asm.Net.Tests.X86
{
    [TestFixture]
    public class X86Test
    {
        [Test(Description = "should assemble single ret instruction")]
        public void should_assemble_single_ret_instruction()
        {
#if USE_BUFFERS
            BufferWriter stream = new BufferWriter();
#else
            using (MemoryStream stream = new MemoryStream())
#endif
            {
                stream.Ret();

                Assert.AreEqual(stream.ToArray(), new byte[] { 195 });
            }
        }

    }
}
