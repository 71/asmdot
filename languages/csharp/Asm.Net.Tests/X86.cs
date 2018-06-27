using System.IO;
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
            using (MemoryStream stream = new MemoryStream())
            {
                stream.Ret();

                Assert.AreEqual(stream.ToArray(), new byte[] { 195 });
            }
        }

    }
}
