#if !USE_BUFFERS
using System.IO;
#endif
using NUnit.Framework;
using Asm.Net.Arm;

namespace Asm.Net.Tests.Arm
{
    [TestFixture]
    public class ArmTest
    {
        [Test(Description = "should encode single cps instruction")]
        public void should_encode_single_cps_instruction()
        {
#if USE_BUFFERS
            BufferWriter stream = new BufferWriter();
#else
            using (MemoryStream stream = new MemoryStream())
#endif
            {
                stream.Cps(Mode.USR);

                Assert.AreEqual(stream.ToArray(), new byte[] { 16, 0, 2, 241 });
            }
        }

    }
}
