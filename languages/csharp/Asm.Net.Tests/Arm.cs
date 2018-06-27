using System.IO;
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
            using (MemoryStream stream = new MemoryStream())
            {
                stream.Cps(Mode.USR);

                Assert.AreEqual(stream.ToArray(), new byte[] { 16, 0, 2, 241 });
            }
        }

    }
}
