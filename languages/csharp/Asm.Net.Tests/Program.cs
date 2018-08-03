using System.Buffers;
using System.IO;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace Asm.Net.Tests
{
    using Asm.Net.Arm;
    using Asm.Net.X86;

    [ShortRunJob, MemoryDiagnoser]
    public class Benchmarks
    {
        private const int N = 256;

#if USE_BUFFERS
        private readonly BufferWriter buffer = new BufferWriter(N * 8);
#else
        private readonly MemoryStream buffer = new MemoryStream(N * 8);
#endif

        [Benchmark(OperationsPerInvoke = N)]
        public void X86Ret()
        {
            var buf = buffer;

            buf.Position = 0;

            for (int i = 0; i < N; i++)
                buf.Ret();
        }

        [Benchmark(OperationsPerInvoke = N)]
        public void X86PopEax()
        {
            var buf = buffer;

            buf.Position = 0;

            for (int i = 0; i < N; i++)
                buf.Pop(Register32.EAX);
        }

        [Benchmark(OperationsPerInvoke = N)]
        public void X86PopR15()
        {
            var buf = buffer;

            buf.Position = 0;

            for (int i = 0; i < N; i++)
                buf.Pop(Register32.R15D);
        }

        [Benchmark(OperationsPerInvoke = N)]
        public void ArmCps()
        {
            var buf = buffer;

            buf.Position = 0;

            for (int i = 0; i < N; i++)
                buf.Cps(Mode.USR);
        }
    }

    public static class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run<Benchmarks>();
        }
    }
}
